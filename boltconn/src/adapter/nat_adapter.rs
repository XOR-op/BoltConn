// Adapter to NAT

use crate::adapter::Connector;
use crate::common::buf_pool::{PktBufHandle, PktBufPool};
use crate::proxy::{NetworkAddr, SessionManager, StatisticsInfo};
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub struct NatAdapter {
    info: Arc<RwLock<StatisticsInfo>>,
    inbound_read: mpsc::Receiver<PktBufHandle>,
    inbound_write: Arc<UdpSocket>,
    allocator: PktBufPool,
    connector: Connector,
    session_mgr: Arc<SessionManager>,
}

impl NatAdapter {
    const BUF_SIZE: usize = 65536;

    pub fn new(
        info: Arc<RwLock<StatisticsInfo>>,
        inbound_read: mpsc::Receiver<PktBufHandle>,
        inbound_write: Arc<UdpSocket>,
        allocator: PktBufPool,
        connector: Connector,
        session_mgr: Arc<SessionManager>,
    ) -> Self {
        Self {
            info,
            inbound_read,
            inbound_write,
            allocator,
            connector,
            session_mgr,
        }
    }

    pub async fn run(self) -> Result<()> {
        let mut first_packet = true;
        let outgoing_info_arc = self.info.clone();
        let allocator = self.allocator.clone();
        let mut inbound_read = self.inbound_read;
        let Connector { tx, mut rx } = self.connector;
        // recv from inbound and send to outbound
        tokio::spawn(async move {
            loop {
                match inbound_read.recv().await {
                    None => {
                        break;
                    }
                    Some(buf) => {
                        if first_packet {
                            first_packet = false;
                            outgoing_info_arc
                                .write()
                                .unwrap()
                                .update_proto(buf.as_ready());
                        }
                        outgoing_info_arc.write().unwrap().more_upload(buf.len);
                        if let Err(err) = tx.send(buf).await {
                            allocator.release(err.0);
                            tracing::warn!("NatAdapter tx send err");
                            break;
                        }
                    }
                }
            }
        });
        // recv from outbound and send to inbound
        loop {
            match rx.recv().await {
                Some(buf) => {
                    // tracing::trace!("[Direct] ingoing {} bytes", size);
                    self.info.write().unwrap().more_download(buf.len);
                    if let Err(err) = self.inbound_write.send(buf.as_ready()).await {
                        tracing::warn!("NatAdapter write to inbound failed: {}", err);
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
