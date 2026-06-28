use super::session::{SessionShared, WriteRequest};
use super::{Command, FrameWrite, MAX_FRAME_DATA_LEN, PROTOCOL_VERSION};
use crate::proxy::error::TransportError;
use bytes::Bytes;
use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

pub struct AnytlsStream {
    pub(super) id: u32,
    pub(super) events: mpsc::UnboundedReceiver<StreamEvent>,
    pub(super) pending_read: Bytes,
    pub(super) state: Arc<StreamState>,
    pub(super) synack: Option<oneshot::Receiver<Result<(), String>>>,
}

impl AnytlsStream {
    pub fn stream_id(&self) -> u32 {
        self.id
    }

    pub async fn wait_synack(&mut self, timeout: Duration) -> Result<(), TransportError> {
        if self.state.session.peer_version.load(Ordering::Acquire) < PROTOCOL_VERSION {
            return Ok(());
        }
        let Some(synack) = self.synack.take() else {
            return Ok(());
        };
        match tokio::time::timeout(timeout, synack).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(message))) => {
                self.state.close(false);
                Err(TransportError::InternalExtra(format!(
                    "AnyTLS SYNACK failed: {message}"
                )))
            }
            Ok(Err(_)) => {
                self.state.close(false);
                Err(TransportError::Anytls("AnyTLS SYNACK channel closed"))
            }
            Err(_) => {
                self.state.session.close();
                Err(TransportError::Timeout("anytls synack"))
            }
        }
    }
}

impl AsyncRead for AnytlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending_read.is_empty() {
                let len = min(buf.remaining(), this.pending_read.len());
                buf.put_slice(&this.pending_read.split_to(len));
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut this.events).poll_recv(cx) {
                Poll::Ready(Some(StreamEvent::Data(data))) => {
                    this.pending_read = data;
                }
                Poll::Ready(Some(StreamEvent::Fin)) => {
                    this.state.close(false);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(StreamEvent::Reset(reason))) => {
                    this.state.close(false);
                    return Poll::Ready(Err(io::Error::other(reason)));
                }
                Poll::Ready(None) => {
                    this.state.close(false);
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for AnytlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.state.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AnyTLS stream is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let len = min(buf.len(), MAX_FRAME_DATA_LEN);
        let frame = FrameWrite {
            command: Command::Psh,
            stream_id: this.id,
            data: Bytes::copy_from_slice(&buf[..len]),
        };
        if this
            .state
            .session
            .write_tx
            .send(WriteRequest::Frames(vec![frame]))
            .is_err()
        {
            this.state.close(false);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AnyTLS writer is closed",
            )));
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().state.close(true);
        Poll::Ready(Ok(()))
    }
}

impl Drop for AnytlsStream {
    fn drop(&mut self) {
        self.state.close(true);
    }
}

pub(super) struct StreamState {
    pub(super) id: u32,
    pub(super) session: Arc<SessionShared>,
    pub(super) closed: AtomicBool,
}

impl StreamState {
    pub(super) fn close(&self, notify_remote: bool) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if notify_remote && self.session.is_alive() {
            let _ = self
                .session
                .write_tx
                .send(WriteRequest::Frames(vec![FrameWrite {
                    command: Command::Fin,
                    stream_id: self.id,
                    data: Bytes::new(),
                }]));
        }
        self.session.remove_stream(self.id);
        self.session.stream_finished();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

pub(super) struct StreamEntry {
    pub(super) events: mpsc::UnboundedSender<StreamEvent>,
    pub(super) synack: std::sync::Mutex<Option<oneshot::Sender<Result<(), String>>>>,
    pub(super) state: Arc<StreamState>,
}

pub(super) enum StreamEvent {
    Data(Bytes),
    Fin,
    Reset(String),
}
