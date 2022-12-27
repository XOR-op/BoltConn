use crate::adapter::{Connector, TcpIndicatorGuard, TcpStatus};
use crate::proxy::{ConnAgent, NetworkAddr};
use crate::PktBufPool;
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8};
use std::sync::{Arc, RwLock};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct TunAdapter {
    stat: TcpStatus,
    info: Arc<RwLock<ConnAgent>>,
    inbound: TcpStream,
    allocator: PktBufPool,
    connector: Connector,
}

impl TunAdapter {
    const BUF_SIZE: usize = 65536;

    pub fn new(
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        info: Arc<RwLock<ConnAgent>>,
        inbound: TcpStream,
        available: Arc<AtomicU8>,
        allocator: PktBufPool,
        connector: Connector,
    ) -> Self {
        Self {
            stat: TcpStatus::new(src_addr, dst_addr, available),
            info,
            inbound,
            allocator,
            connector,
        }
    }

    pub async fn run(self) -> Result<()> {
        let ingoing_indicator = self.stat.available.clone();
        let outgoing_indicator = self.stat.available.clone();
        let mut first_packet = true;
        let (mut in_read, mut in_write) = tokio::io::split(self.inbound);
        let outgoing_info_arc = self.info.clone();
        let allocator = self.allocator.clone();
        let Connector { tx, mut rx } = self.connector;
        // recv from inbound and send to outbound
        self.info
            .write()
            .unwrap()
            .more_handle(tokio::spawn(async move {
                let _guard = TcpIndicatorGuard {
                    indicator: outgoing_indicator,
                    info: outgoing_info_arc.clone(),
                };
                loop {
                    let mut buf = allocator.obtain().await;
                    match buf.read(&mut in_read).await {
                        Ok(0) => {
                            allocator.release(buf);
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
                            outgoing_info_arc.write().unwrap().more_upload(size);
                            if let Err(err) = tx.send(buf).await {
                                allocator.release(err.0);
                                tracing::warn!("TunAdapter tx send err");
                                break;
                            }
                        }
                        Err(err) => {
                            allocator.release(buf);
                            tracing::warn!("TunAdapter encounter error: {}", err);
                            break;
                        }
                    }
                }
            }));
        // recv from outbound and send to inbound
        let _guard = TcpIndicatorGuard {
            indicator: ingoing_indicator,
            info: self.info.clone(),
        };
        loop {
            match rx.recv().await {
                Some(buf) => {
                    // tracing::trace!("[Direct] ingoing {} bytes", size);
                    self.info.write().unwrap().more_download(buf.len);
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

        Ok(())
    }
}
