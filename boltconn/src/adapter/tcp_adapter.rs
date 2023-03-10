use crate::adapter::{Connector, DuplexCloseGuard, TcpIndicatorGuard, TcpStatus};
use crate::common::buf_pool::{read_to_bytes_mut, MAX_PKT_SIZE};
use crate::proxy::{ConnAbortHandle, ConnAgent, NetworkAddr};
use crate::PktBufPool;
use bytes::BytesMut;
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

pub struct TcpAdapter {
    stat: TcpStatus,
    info: Arc<RwLock<ConnAgent>>,
    inbound: TcpStream,
    allocator: PktBufPool,
    connector: Connector,
    abort_handle: ConnAbortHandle,
}

impl TcpAdapter {
    const BUF_SIZE: usize = 65536;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        info: Arc<RwLock<ConnAgent>>,
        inbound: TcpStream,
        available: Arc<AtomicU8>,
        allocator: PktBufPool,
        connector: Connector,
        abort_handle: ConnAbortHandle,
    ) -> Self {
        Self {
            stat: TcpStatus::new(src_addr, dst_addr, available),
            info,
            inbound,
            allocator,
            connector,
            abort_handle,
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
        let abort_handle = self.abort_handle.clone();
        // recv from inbound and send to outbound
        let mut duplex_guard = DuplexCloseGuard::new(tokio::spawn(async move {
            let _guard = TcpIndicatorGuard {
                indicator: outgoing_indicator,
                info: outgoing_info_arc.clone(),
            };
            loop {
                let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
                match read_to_bytes_mut(&mut buf, &mut in_read).await {
                    Ok(0) => {
                        break;
                    }
                    Ok(size) => {
                        if first_packet {
                            first_packet = false;
                            outgoing_info_arc.write().await.update_proto(buf.as_ref());
                        }
                        outgoing_info_arc.write().await.more_upload(size);
                        if let Err(_) = tx.send(buf.freeze()).await {
                            tracing::warn!("TunAdapter tx send err");
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!("TunAdapter encounter error: {}", err);
                        abort_handle.cancel().await;
                        break;
                    }
                }
            }
            // tracing::debug!("TUN outgoing closed");
        }));
        // recv from outbound and send to inbound
        let _guard = TcpIndicatorGuard {
            indicator: ingoing_indicator,
            info: self.info.clone(),
        };
        while let Some(buf) = rx.recv().await {
            self.info.write().await.more_download(buf.len());
            if let Err(err) = in_write.write_all(buf.as_ref()).await {
                tracing::warn!("TunAdapter write to inbound failed: {}", err);
                self.abort_handle.cancel().await;
                duplex_guard.set_err_exit();
                break;
            }
        }
        // tracing::debug!("TUN incoming closed");
        Ok(())
    }
}
