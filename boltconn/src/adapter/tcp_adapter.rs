use crate::adapter::{
    Connector, TcpIndicatorGuard, TcpRelayActivity, TcpRelayDirection, TcpStatus,
    error_termination, relay_channel_to_writer, relay_reader_to_channel, relay_tcp_bidirectional,
};
use crate::common::{
    MAX_PKT_SIZE, StreamOutboundTrait, parse_http_host, parse_tls_sni, read_to_bytes_mut,
};
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, ConnHandle, NetworkAddr, SessionProtocol, check_tcp_protocol};
use bytes::{Bytes, BytesMut};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::mpsc;

pub struct TcpAdapter<S> {
    stat: TcpStatus,
    in_read: ReadHalf<S>,
    in_write: WriteHalf<S>,
    connector: Connector,
    abort_handle: ConnAbortHandle,
    first_packet_buffer: Option<BytesMut>,
}

/// Completes the connection when another relay aborts this task before its normal finish path.
struct TcpAbortGuard {
    info: ConnHandle,
    abort_handle: ConnAbortHandle,
    armed: bool,
}

impl TcpAbortGuard {
    fn new(info: ConnHandle, abort_handle: ConnAbortHandle) -> Self {
        Self {
            info,
            abort_handle,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TcpAbortGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(reason) = self.abort_handle.cancel_reason() {
            self.info.finish(reason.code, reason.stage, reason.detail);
        }
    }
}

impl<S: StreamOutboundTrait> TcpAdapter<S> {
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
                SessionProtocol::Tls => parse_tls_sni(buf.as_ref()),
                _ => None,
            }
            .map(|h| (proto, h));
            self.first_packet_buffer = Some(buf);
            Ok(result)
        }
    }

    async fn upload(
        in_read: ReadHalf<S>,
        tx: mpsc::Sender<Bytes>,
        first_packet_buffer: Option<BytesMut>,
        mut need_parse_first_packet: bool,
        activity: TcpRelayActivity,
        info: ConnHandle,
        _indicator_guard: TcpIndicatorGuard,
    ) -> io::Result<()> {
        if let Some(first_packet) = first_packet_buffer {
            info.more_upload(first_packet.len());
            tx.send(first_packet.freeze())
                .await
                .map_err(|_| Self::channel_closed_error(&info, "send first packet to outbound"))?;
            activity.touch();
        }

        let callback_info = info.clone();
        relay_reader_to_channel(in_read, tx, false, activity, move |buf| {
            if need_parse_first_packet {
                need_parse_first_packet = false;
                callback_info.update_proto(buf);
            }
            callback_info.more_upload(buf.len());
        })
        .await
        .map_err(|error| Self::io_error(&info, "forward client data to outbound", error))
    }

    async fn download(
        in_write: WriteHalf<S>,
        rx: mpsc::Receiver<Bytes>,
        activity: TcpRelayActivity,
        info: ConnHandle,
        _indicator_guard: TcpIndicatorGuard,
    ) -> io::Result<()> {
        let callback_info = info.clone();
        relay_channel_to_writer(rx, in_write, false, activity, move |buf| {
            callback_info.more_download(buf.len());
        })
        .await
        .map_err(|error| Self::io_error(&info, "forward outbound data to client", error))
    }

    fn channel_closed_error(info: &ConnHandle, operation: &'static str) -> io::Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!(
                "TcpAdapter #{}({}) failed to {}: channel closed",
                info.id(),
                info.metadata().conn_info.dst,
                operation
            ),
        )
    }

    fn io_error(info: &ConnHandle, operation: &'static str, error: io::Error) -> io::Error {
        io::Error::new(
            error.kind(),
            format!(
                "TcpAdapter #{}({}) failed to {}: {}",
                info.id(),
                info.metadata().conn_info.dst,
                operation,
                error
            ),
        )
    }

    pub async fn run(self, info: ConnHandle) -> io::Result<()> {
        let mut abort_guard = TcpAbortGuard::new(info.clone(), self.abort_handle.clone());
        let need_parse_first_packet = self.first_packet_buffer.is_none();
        let Connector { tx, rx } = self.connector;
        let activity = TcpRelayActivity::new();

        // Construct both guards before polling either future. This ensures both sides update the
        // connection status even when one branch completes before the other is first polled.
        let upload_guard = TcpIndicatorGuard {
            indicator: self.stat.available.clone(),
        };
        let download_guard = TcpIndicatorGuard {
            indicator: self.stat.available.clone(),
        };

        let upload_info = info.clone();
        let upload_activity = activity.clone();
        let upload = async move {
            let result = Self::upload(
                self.in_read,
                tx,
                self.first_packet_buffer,
                need_parse_first_packet,
                upload_activity,
                upload_info.clone(),
                upload_guard,
            )
            .await;
            if upload_info.snapshot().state.established_at_ms.is_some() {
                upload_info.set_state(boltapi::ConnState::Closing);
            }
            result
        };
        let download_info = info.clone();
        let download_activity = activity.clone();
        let download = async move {
            let result = Self::download(
                self.in_write,
                rx,
                download_activity,
                download_info.clone(),
                download_guard,
            )
            .await;
            if download_info.snapshot().state.established_at_ms.is_some() {
                download_info.set_state(boltapi::ConnState::Closing);
            }
            result
        };

        // A clean close is a TCP half-close: keep forwarding the other direction while it remains
        // active. An I/O failure terminates immediately so sibling tasks can be cancelled.
        let label = format!(
            "TcpAdapter #{}({})",
            info.id(),
            info.metadata().conn_info.dst
        );
        let outcome = relay_tcp_bidirectional(&label, upload, download, activity).await;
        let reached_active = info.snapshot().state.established_at_ms.is_some();
        let reason = match &outcome.result {
            Ok(()) => boltapi::ConnTermination::new(
                match outcome.first {
                    TcpRelayDirection::Upload => boltapi::ConnResultCode::ClientClosed,
                    TcpRelayDirection::Download => boltapi::ConnResultCode::RemoteClosed,
                },
                if reached_active {
                    boltapi::ConnStage::Closing
                } else {
                    boltapi::ConnStage::Connecting
                },
                None,
            ),
            Err(error) => error_termination(
                boltapi::ConnResultCode::TransferError,
                if reached_active {
                    boltapi::ConnStage::Transferring
                } else {
                    boltapi::ConnStage::Connecting
                },
                error,
            ),
        };
        if reached_active || (outcome.first == TcpRelayDirection::Upload && outcome.result.is_ok())
        {
            info.finish(reason.code, reason.stage, reason.detail.clone());
        }
        abort_guard.disarm();
        self.abort_handle.cancel(reason);
        outcome.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::{ConnInfo, InboundInfo};
    use crate::platform::process::NetworkType;
    use crate::proxy::ContextManager;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    impl StreamOutboundTrait for DuplexStream {}

    fn test_context(abort_handle: ConnAbortHandle) -> ConnHandle {
        let src = "127.0.0.1:12345".parse().unwrap();
        let dst = "127.0.0.1:443".parse().unwrap();
        ContextManager::new(10).begin(
            ConnInfo {
                src,
                dst: NetworkAddr::Socket { address: dst },
                local_ip: None,
                inbound: InboundInfo::Tun,
                resolved_dst: None,
                connection_type: NetworkType::Tcp,
                process_info: None,
            },
            NetworkAddr::Socket { address: dst },
            None,
            abort_handle,
        )
    }

    #[tokio::test]
    async fn clean_upload_half_close_keeps_downloading() {
        let (mut client, adapter_stream) = tokio::io::duplex(1024);
        let (adapter_connector, outbound_connector) = Connector::new_pair(4);
        let Connector {
            tx: outbound_tx,
            rx: mut outbound_rx,
        } = outbound_connector;
        let available = Arc::new(AtomicU8::new(2));
        let abort_handle = ConnAbortHandle::placeholder();
        let info = test_context(abort_handle.clone());
        info.set_state(boltapi::ConnState::Active);
        let adapter = TcpAdapter::new(
            info.metadata().conn_info.src,
            info.metadata().conn_info.dst.clone(),
            adapter_stream,
            available.clone(),
            adapter_connector,
            abort_handle,
        );
        let adapter_task = tokio::spawn(adapter.run(info.clone()));

        client.write_all(b"request").await.unwrap();
        assert_eq!(
            outbound_rx.recv().await.unwrap(),
            Bytes::from_static(b"request")
        );

        // Closing the upload half must not discard a response that is still in flight.
        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while info.state() != boltapi::ConnState::Closing {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("adapter did not enter closing after the upload half-close");
        outbound_tx
            .send(Bytes::from_static(b"response"))
            .await
            .unwrap();
        let mut response = [0; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");

        drop(outbound_tx);
        tokio::time::timeout(Duration::from_secs(1), adapter_task)
            .await
            .expect("adapter did not stop after both directions closed")
            .expect("adapter task panicked")
            .expect("adapter returned an error");
        assert_eq!(available.load(Ordering::Relaxed), 0);
        assert!(info.done());
    }

    #[tokio::test]
    async fn transport_cancellation_finishes_a_closing_connection() {
        let (mut client, adapter_stream) = tokio::io::duplex(1024);
        let (adapter_connector, outbound_connector) = Connector::new_pair(4);
        let Connector {
            tx: outbound_tx,
            rx: _outbound_rx,
        } = outbound_connector;
        let available = Arc::new(AtomicU8::new(2));
        let abort_handle = ConnAbortHandle::new();
        let info = test_context(abort_handle.clone());
        info.set_state(boltapi::ConnState::Active);
        let adapter = TcpAdapter::new(
            info.metadata().conn_info.src,
            info.metadata().conn_info.dst.clone(),
            adapter_stream,
            available.clone(),
            adapter_connector,
            abort_handle.clone(),
        );
        let task_info = info.clone();
        let adapter_task = tokio::spawn(async move {
            let _ = adapter.run(task_info).await;
        });
        abort_handle.fulfill(vec![("tcp".to_string(), adapter_task)]);

        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while info.state() != boltapi::ConnState::Closing {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("adapter did not enter closing after the upload half-close");

        abort_handle.cancel(boltapi::ConnTermination::new(
            boltapi::ConnResultCode::RemoteClosed,
            boltapi::ConnStage::Closing,
            None,
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !info.done() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reasoned cancellation did not finish the connection");

        drop(outbound_tx);
        assert_eq!(available.load(Ordering::Relaxed), 0);
        let snapshot = info.snapshot();
        assert_eq!(snapshot.state.state, boltapi::ConnState::Closed);
        assert_eq!(
            snapshot.state.termination.unwrap().code,
            boltapi::ConnResultCode::RemoteClosed
        );
    }
}
