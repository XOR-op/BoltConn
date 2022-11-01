use crate::network::egress::Egress;
use crate::outbound::TcpConnection;
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

pub struct DirectOutbound {
    iface_name: String,
    conn: TcpConnection,
    info: Arc<RwLock<SessionInfo>>,
}

impl DirectOutbound {
    const BUF_SIZE: usize = 65536;

    pub fn new(
        iface_name: &str,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        info: SessionInfo,
        available: Arc<AtomicU8>,
    ) -> Self {
        Self {
            iface_name: iface_name.into(),
            conn: TcpConnection::new(src_addr, dst_addr, available),
            info: Arc::new(RwLock::new(info)),
        }
    }

    pub async fn run(&mut self, inbound: TcpStream) -> Result<()> {
        let ingoing_indicator = self.conn.available.clone();
        let outgoing_indicator = self.conn.available.clone();
        let outbound = match self.conn.dst {
            SocketAddr::V4(_) => {
                Egress::new(&self.iface_name)
                    .tcpv4_stream(self.conn.dst)
                    .await?
            }
            SocketAddr::V6(_) => {
                Egress::new(&self.iface_name)
                    .tcpv6_stream(self.conn.dst)
                    .await?
            }
        };
        tracing::info!(
            "[Direct] Connection {:?} <=> {:?} established",
            outbound.local_addr(),
            outbound.peer_addr()
        );
        let mut first_packet = true;
        let (mut in_read, mut in_write) = inbound.into_split();
        let (mut out_read, mut out_write) = outbound.into_split();
        let outgoing_info_arc = self.info.clone();
        // recv from inbound and send to outbound
        tokio::spawn(async move {
            let mut buf = [0u8; Self::BUF_SIZE];
            loop {
                match in_read.read(&mut buf).await {
                    Ok(0) => {
                        // tracing::trace!("[Direct] in->out closed");
                        break;
                    }
                    Ok(size) => {
                        if first_packet {
                            first_packet = false;
                            outgoing_info_arc
                                .write()
                                .unwrap()
                                .update_proto(&buf[..size]);
                        }
                        // tracing::trace!("[Direct] outgoing {} bytes", size);
                        if let Err(err) = out_write.write_all(&buf[..size]).await {
                            tracing::warn!("[Direct] write to outbound failed: {}", err);
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!("[Direct] encounter error: {}", err);
                        break;
                    }
                }
            }
            outgoing_indicator.fetch_sub(1, Ordering::Relaxed);
        });
        // recv from outbound and send to inbound
        let mut buf = [0u8; Self::BUF_SIZE];
        loop {
            match out_read.read(&mut buf).await {
                Ok(0) => {
                    // tracing::trace!("[Direct] out->in closed");
                    break;
                }
                Ok(size) => {
                    // tracing::trace!("[Direct] ingoing {} bytes", size);
                    if let Err(err) = in_write.write_all(&buf[..size]).await {
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
        ingoing_indicator.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }
}
