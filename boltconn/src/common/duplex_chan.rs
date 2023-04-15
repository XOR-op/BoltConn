use crate::adapter::Connector;
use crate::common::{io_err, StreamOutboundTrait};
use bytes::{Bytes, BytesMut};
use std::io::Error;
use std::pin::Pin;
use std::task::Poll::Ready;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

pub struct DuplexChan {
    tx: mpsc::Sender<Bytes>,
    rx: mpsc::Receiver<Bytes>,
    pending_read: Option<(Bytes, usize)>,
}

impl DuplexChan {
    pub fn new(conn: Connector) -> Self {
        Self {
            tx: conn.tx,
            rx: conn.rx,
            pending_read: None,
        }
    }
}

impl AsyncWrite for DuplexChan {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        // todo: decide if waker logic should be rewritten
        if self.tx.capacity() == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut handle = BytesMut::with_capacity(buf.len());
        handle.extend_from_slice(buf);
        return match self.tx.try_send(handle.freeze()) {
            Ok(_) => Ready(Ok(buf.len())),
            Err(TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(TrySendError::Closed(_)) => Ready(Err(io_err("DuplexChan: tx closed"))),
        };
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Ready(Ok(()))
    }
}

impl AsyncRead for DuplexChan {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some((buffer, offset)) = self.pending_read.take() {
            let remaining = buffer.len() - offset;
            if remaining <= buf.remaining() {
                buf.initialize_unfilled()[..remaining].copy_from_slice(&buffer.as_ref()[offset..]);
                buf.advance(remaining);
                self.pending_read = None;
                Ready(Ok(()))
            } else {
                let remaining = buf.remaining();
                buf.initialize_unfilled()[..remaining]
                    .copy_from_slice(&buffer.as_ref()[offset..offset + remaining]);
                self.pending_read = Some((buffer, offset + remaining));
                buf.advance(remaining);
                Ready(Ok(()))
            }
        } else {
            return match self.rx.poll_recv(cx) {
                Ready(Some(v)) => {
                    if v.len() <= buf.remaining() {
                        buf.initialize_unfilled()[..v.len()].copy_from_slice(v.as_ref());
                        buf.advance(v.len());
                        Ready(Ok(()))
                    } else {
                        let remaining = buf.remaining();
                        buf.initialize_unfilled()[..remaining]
                            .copy_from_slice(&v.as_ref()[..remaining]);
                        self.pending_read = Some((v, remaining));
                        buf.advance(remaining);
                        Ready(Ok(()))
                    }
                }
                Ready(None) => Ready(Ok(())),
                Poll::Pending => Poll::Pending,
            };
        }
    }
}

impl StreamOutboundTrait for DuplexChan {}
