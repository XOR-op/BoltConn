use crate::adapter::{Connector, TcpStatus};
use crate::common::duplex_chan::DuplexChan;
use crate::common::io_err;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::platform::bind_to_device;
use crate::session::{NetworkAddr, SessionInfo, SessionProtocol};
use crate::PktBufPool;
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct DirectOutbound {
    iface_name: String,
    dst: NetworkAddr,
    allocator: PktBufPool,
    dns: Arc<Dns>,
}

impl DirectOutbound {
    pub fn new(iface_name: &str, dst: NetworkAddr, allocator: PktBufPool, dns: Arc<Dns>) -> Self {
        Self {
            iface_name: iface_name.into(),
            dst,
            allocator,
            dns,
        }
    }

    pub async fn run(self, inbound: Connector) -> Result<()> {
        let dst_addr = match self.dst {
            NetworkAddr::DomainName { domain_name, port } => {
                // translate fake ip
                SocketAddr::new(
                    self.dns
                        .domain_to_real_ip(domain_name.as_str())
                        .await
                        .ok_or(io_err("DNS failed"))?,
                    port,
                )
            }
            NetworkAddr::Raw(s) => s,
        };
        let outbound = match dst_addr {
            SocketAddr::V4(_) => Egress::new(&self.iface_name).tcpv4_stream(dst_addr).await?,
            SocketAddr::V6(_) => Egress::new(&self.iface_name).tcpv6_stream(dst_addr).await?,
        };
        tracing::info!(
            "[Direct] Connection {:?} <=> {:?} established",
            outbound.local_addr(),
            outbound.peer_addr()
        );
        let (mut out_read, mut out_write) = outbound.into_split();
        let allocator = self.allocator.clone();
        let Connector { tx, mut rx } = inbound;
        // recv from inbound and send to outbound
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Some(buf) => {
                        if let Err(err) = out_write.write_all(buf.as_ready()).await {
                            tracing::warn!("[Direct] write to outbound failed: {}", err);
                            allocator.release(buf);
                            break;
                        } else {
                            allocator.release(buf);
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        });
        // recv from outbound and send to inbound
        loop {
            let mut buf = self.allocator.obtain().await;
            match buf.read(&mut out_read).await {
                Ok(0) => {
                    break;
                }
                Ok(_) => {
                    if let Err(err) = tx.send(buf).await {
                        tracing::warn!("[Direct] write to inbound failed: {}", err);
                        break;
                    }
                }
                Err(err) => {
                    tracing::warn!("[Direct] encounter error: {}", err);
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn as_async(&self) -> (DuplexChan, JoinHandle<Result<()>>) {
        let (inner, outer) = Connector::new_pair(10);
        (
            DuplexChan::new(self.allocator.clone(), inner),
            tokio::spawn(self.clone().run(outer)),
        )
    }
}
