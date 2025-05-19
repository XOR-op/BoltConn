use crate::adapter::{Connector, DuplexCloseGuard, TcpIndicatorGuard, TcpStatus};
use crate::common::{
    parse_http_host, parse_tls_sni, read_to_bytes_mut, StreamOutboundTrait, MAX_PKT_SIZE,
};
use crate::proxy::error::TransportError;
use crate::proxy::{
    check_tcp_protocol, ConnAbortHandle, ConnContext, NetworkAddr, SessionProtocol,
};
use bytes::BytesMut;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};

pub struct TcpAdapter<S> {
    stat: TcpStatus,
    in_read: ReadHalf<S>,
    in_write: WriteHalf<S>,
    connector: Connector,
    abort_handle: ConnAbortHandle,
    first_packet_buffer: Option<BytesMut>,
}

impl<S: StreamOutboundTrait> TcpAdapter<S> {
    const BUF_SIZE: usize = 65536;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        inbound: S,
        available: Arc<AtomicU8>,
        connector: Connector,
        abort_handle: ConnAbortHandle,
    ) -> Self {
        let (in_read, in_write) = tokio::io::split(inbound);
        Self {
            stat: TcpStatus::new(src_addr, dst_addr, available),
            in_read,
            in_write,
            connector,
            abort_handle,
            first_packet_buffer: None,
        }
    }

    pub async fn try_sni_or_host(
        &mut self,
    ) -> Result<Option<(SessionProtocol, String)>, TransportError> {
        let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
        let read_size = read_to_bytes_mut(&mut buf, &mut self.in_read).await?;
        if read_size == 0 {
            Err(TransportError::Io(std::io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read first packet error",
            )))
        } else {
            assert!(
                self.first_packet_buffer.is_none(),
                "read_first_packet called twice"
            );
            let proto = check_tcp_protocol(buf.as_ref());
            let result = match &proto {
                SessionProtocol::Http => parse_http_host(buf.as_ref()),
                SessionProtocol::Tls(_) => parse_tls_sni(buf.as_ref()),
                _ => None,
            }
            .map(|h| (proto, h));
            self.first_packet_buffer = Some(buf);
            Ok(result)
        }
    }

    pub async fn run(self, info: Arc<ConnContext>) -> io::Result<()> {
        let mut need_parse_first_packet = self.first_packet_buffer.is_none();
        let Connector { tx, mut rx } = self.connector;
        let dest = info.conn_info.dst.clone();
        let abort_handle = self.abort_handle.clone();
        let conn_id = info.id;
        let mut in_read = self.in_read;
        let mut in_write = self.in_write;

        let _duplex_guard = {
            let ingoing_indicator = self.stat.available.clone();
            let dest2 = dest.clone();
            let info = info.clone();
            DuplexCloseGuard::new(
                tokio::spawn(async move {
                    // recv from outbound and send to inbound
                    let _guard = TcpIndicatorGuard {
                        indicator: ingoing_indicator,
                        info: info.clone(),
                    };
                    while let Some(buf) = rx.recv().await {
                        info.more_download(buf.len());
                        if let Err(err) = in_write.write_all(buf.as_ref()).await {
                            tracing::warn!(
                                "TcpAdapter #{}({}) write to client failed: {}",
                                conn_id,
                                dest2,
                                err
                            );
                            self.abort_handle.cancel();
                            break;
                        }
                    }
                }),
                abort_handle.clone(),
            )
        };

        // recv from inbound and send to outbound
        let outgoing_indicator = self.stat.available.clone();
        let _guard = TcpIndicatorGuard {
            indicator: outgoing_indicator,
            info: info.clone(),
        };
        if let Some(first_packet) = self.first_packet_buffer {
            info.more_upload(first_packet.len());
            if tx.send(first_packet.freeze()).await.is_err() {
                tracing::warn!("TcpAdapter #{}({}) tx send err", conn_id, dest);
                abort_handle.cancel();
                return Ok(());
            }
        }

        loop {
            let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
            let read_size = match read_to_bytes_mut(&mut buf, &mut in_read).await {
                Ok(0) => {
                    // CLOSE_WAIT
                    break;
                }
                Ok(size) => {
                    if need_parse_first_packet {
                        need_parse_first_packet = false;
                        info.update_proto(buf.as_ref());
                    }
                    size
                }
                Err(err) => {
                    tracing::warn!(
                        "TcpAdapter #{}({}) read from client error: {}",
                        conn_id,
                        dest,
                        err
                    );
                    abort_handle.cancel();
                    break;
                }
            };
            info.more_upload(read_size);
            if tx.send(buf.freeze()).await.is_err() {
                tracing::warn!("TcpAdapter #{}({}) tx send err", conn_id, dest);
                abort_handle.cancel();
                break;
            }
        }
        Ok(())
    }
}
