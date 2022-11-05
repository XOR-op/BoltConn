use crate::network::egress::Egress;
use crate::adapter::{Connector, TcpStatus};
use crate::platform::bind_to_device;
use crate::session::{SessionInfo, SessionProtocol};
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use crate::PktBufPool;

pub struct DirectOutbound {
    iface_name: String,
    dst: SocketAddr,
    allocator: PktBufPool,
    connector: Connector,
}

impl DirectOutbound {
    pub fn new(
        iface_name: &str,
        dst: SocketAddr,
        allocator: PktBufPool,
        connector: Connector,
    ) -> Self {
        Self {
            iface_name: iface_name.into(),
            dst,
            allocator,
            connector,
        }
    }

    pub async fn run(self) -> Result<()> {
        let outbound = match self.dst {
            SocketAddr::V4(_) => {
                Egress::new(&self.iface_name)
                    .tcpv4_stream(self.dst)
                    .await?
            }
            SocketAddr::V6(_) => {
                Egress::new(&self.iface_name)
                    .tcpv6_stream(self.dst)
                    .await?
            }
        };
        tracing::info!(
            "[Direct] Connection {:?} <=> {:?} established",
            outbound.local_addr(),
            outbound.peer_addr()
        );
        let (mut out_read, mut out_write) = outbound.into_split();
        let allocator = self.allocator.clone();
        let Connector { tx, mut rx } = self.connector;
        // recv from inbound and send to outbound
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Some(buf) => {
                        if let Err(err) = out_write.write_all(buf.as_ready()).await {
                            tracing::warn!("[Direct] write to outbound failed: {}", err);
                            allocator.release(buf);
                            break;
                        }
                        allocator.release(buf);
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
                Ok(size) => {
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
}
