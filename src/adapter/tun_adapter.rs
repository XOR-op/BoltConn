use crate::network::egress::Egress;
use crate::adapter::{Connector, TcpStatus};
use crate::platform::bind_to_device;
use crate::session::{SessionInfo, SessionProtocol};
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use crate::PktBufPool;

pub struct TunAdapter {
    stat: TcpStatus,
    info: Arc<RwLock<SessionInfo>>,
    inbound: TcpStream,
    allocator: PktBufPool,
    connector: Connector,
}

impl TunAdapter {
    const BUF_SIZE: usize = 65536;

    pub fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        info: SessionInfo,
        inbound: TcpStream,
        available: Arc<AtomicU8>,
        allocator: PktBufPool,
        connector: Connector,
    ) -> Self {
        Self {
            stat: TcpStatus::new(src_addr, dst_addr, available),
            info: Arc::new(RwLock::new(info)),
            inbound,
            allocator,
            connector,
        }
    }

    pub async fn run(self) -> Result<()> {
        let ingoing_indicator = self.stat.available.clone();
        let outgoing_indicator = self.stat.available.clone();
        let mut first_packet = true;
        let (mut in_read, mut in_write) = self.inbound.into_split();
        let outgoing_info_arc = self.info.clone();
        let allocator = self.allocator.clone();
        let Connector { tx, mut rx } = self.connector;
        // recv from inbound and send to outbound
        tokio::spawn(async move {
            loop {
                let mut buf = allocator.obtain().await;
                match buf.read(&mut in_read).await {
                    Ok(0) => {
                        break;
                    }
                    Ok(size) => {
                        if first_packet {
                            first_packet = false;
                            outgoing_info_arc
                                .write()
                                .unwrap()
                                .update_proto(buf.as_ready());
                        }
                        if let Err(err) = tx.send(buf).await {
                            tracing::warn!("TunAdapter send: {}", err);
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!("TunAdapter encounter error: {}", err);
                        break;
                    }
                }
            }
            outgoing_indicator.fetch_sub(1, Ordering::Relaxed);
        });
        // recv from outbound and send to inbound
        loop {
            match rx.recv().await {
                Some(buf) => {
                    // tracing::trace!("[Direct] ingoing {} bytes", size);
                    if let Err(err) = in_write.write_all(buf.as_ready()).await {
                        tracing::warn!("TunAdapter write to inbound failed: {}", err);
                        self.allocator.release(buf);
                        break;
                    }
                    self.allocator.release(buf);
                }
                None => {
                    // closed
                    break;
                }
            }
        }
        ingoing_indicator.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }
}
