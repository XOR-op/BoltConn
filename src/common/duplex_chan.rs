use std::io::Error;
use std::pin::Pin;
use std::sync::mpsc::TryRecvError;
use std::task::{Context, Poll};
use std::task::Poll::Ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use crate::common::buf_pool::PktBufHandle;
use crate::common::io_err;
use crate::PktBufPool;

pub struct DuplexChan {
    allocator: PktBufPool,
    tx: mpsc::Sender<PktBufHandle>,
    rx: mpsc::Receiver<PktBufHandle>,
    pending_read: Option<(PktBufHandle, usize)>,
}

impl AsyncWrite for DuplexChan {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let Some(mut buffer) = self.allocator.try_obtain()else {
            return Poll::Pending;
        };
        let size = if buf.len() > buffer.data.len() {
            buffer.data.as_mut_slice().copy_from_slice(&buf[..buffer.data.len()]);
            buffer.len = buffer.data.len();
            buffer.data.len()
        } else {
            buffer.data.as_mut_slice()[..buf.len()].copy_from_slice(buf);
            buffer.len = buf.len();
            buf.len()
        };
        return match self.tx.try_send(buffer) {
            Ok(_) => Ready(Ok(size)),
            Err(TrySendError::Full(b)) => {
                // a large performance loss, but have to do this
                self.allocator.release(b);
                Poll::Pending
            }
            Err(TrySendError::Closed(_)) => Ready(Err(io_err("chan closed")))
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
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if let Some((buffer, offset)) = self.pending_read.take() {
            let remaining = buffer.len - offset;
            if remaining <= buf.remaining() {
                buf.initialize_unfilled()[..remaining].copy_from_slice(&buffer.as_ready()[offset..]);
                buf.advance(remaining);
                self.pending_read = None;
                Ready(Ok(()))
            } else {
                buf.initialize_unfilled()[..buf.remaining()].copy_from_slice(&v.as_ready()[offset..offset + buf.remaining()]);
                self.pending_read = Some((v, offset + buf.remaining()));
                buf.advance(buf.remaining());
                Ready(Ok(()))
            }
        } else {
            return match self.rx.try_recv() {
                Ok(v) => {
                    if v.len <= buf.remaining() {
                        buf.initialize_unfilled()[..v.len].copy_from_slice(v.as_ready());
                        buf.advance(v.len);
                        Ready(Ok(()))
                    } else {
                        buf.initialize_unfilled()[..buf.remaining()].copy_from_slice(&v.as_ready()[..buf.remaining()]);
                        self.pending_read = Some((v, buf.remaining()));
                        buf.advance(buf.remaining());
                        Ready(Ok(()))
                    }
                }
                TryRecvError::Disconnected() => Ready(Err(io_err("done"))),
                TryRecvError::Empty() => Poll::Pending
            };
        }
    }
}