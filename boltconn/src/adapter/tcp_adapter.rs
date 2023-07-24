use crate::adapter::{Connector, DuplexCloseGuard, TcpIndicatorGuard, TcpStatus};
use crate::common::{read_to_bytes_mut, MAX_PKT_SIZE};
use crate::proxy::{ConnAbortHandle, ConnContext, NetworkAddr};
use bytes::BytesMut;
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct TcpAdapter {
    stat: TcpStatus,
    info: Arc<ConnContext>,
    inbound: TcpStream,
    connector: Connector,
    abort_handle: ConnAbortHandle,
}

impl TcpAdapter {
    const BUF_SIZE: usize = 65536;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        info: Arc<ConnContext>,
        inbound: TcpStream,
        available: Arc<AtomicU8>,
        connector: Connector,
        abort_handle: ConnAbortHandle,
    ) -> Self {
        Self {
            stat: TcpStatus::new(src_addr, dst_addr, available),
            info,
            inbound,
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
        let Connector { tx, mut rx } = self.connector;
        let abort_handle = self.abort_handle.clone();
        let _duplex_guard = DuplexCloseGuard::new(
            tokio::spawn(async move {
                // recv from outbound and send to inbound
                let _guard = TcpIndicatorGuard {
                    indicator: ingoing_indicator,
                    info: self.info.clone(),
                };
                while let Some(buf) = rx.recv().await {
                    self.info.more_download(buf.len());
                    if let Err(err) = in_write.write_all(buf.as_ref()).await {
                        tracing::warn!("TunAdapter write to inbound failed: {}", err);
                        self.abort_handle.cancel();
                        break;
                    }
                }
            }),
            abort_handle.clone(),
        );

        // recv from inbound and send to outbound
        let _guard = TcpIndicatorGuard {
            indicator: outgoing_indicator,
            info: outgoing_info_arc.clone(),
        };
        loop {
            let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
            match read_to_bytes_mut(&mut buf, &mut in_read).await {
                Ok(0) => {
                    // CLOSE_WAIT
                    break;
                }
                Ok(size) => {
                    if first_packet {
                        first_packet = false;
                        outgoing_info_arc.update_proto(buf.as_ref());
                    }
                    outgoing_info_arc.more_upload(size);
                    if tx.send(buf.freeze()).await.is_err() {
                        tracing::warn!("TunAdapter tx send err");
                        abort_handle.cancel();
                        break;
                    }
                }
                Err(err) => {
                    tracing::warn!("TunAdapter read error: {}", err);
                    abort_handle.cancel();
                    break;
                }
            }
        }
        Ok(())
    }
}
