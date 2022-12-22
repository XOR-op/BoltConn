use crate::adapter::Connector;
use crate::common::buf_pool::PktBufHandle;
use crate::common::io_err;
use crate::PktBufPool;
use std::io::Error;
use std::pin::Pin;
use std::task::Poll::Ready;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

pub struct DuplexChan {
    allocator: PktBufPool,
    tx: mpsc::Sender<PktBufHandle>,
    rx: mpsc::Receiver<PktBufHandle>,
    pending_read: Option<(PktBufHandle, usize)>,
}

impl DuplexChan {
    pub fn new(alloc: PktBufPool, conn: Connector) -> Self {
        Self {
            allocator: alloc,
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
        let Some(mut handle) = self.allocator.try_obtain() else {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };
        if self.tx.capacity() == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let handle_data_len = handle.data.len();
        let size = if buf.len() > handle_data_len {
            handle
                .data
                .as_mut_slice()
                .copy_from_slice(&buf[..handle_data_len]);
            handle.len = handle_data_len;
            handle_data_len
        } else {
            handle.data.as_mut_slice()[..buf.len()].copy_from_slice(buf);
            handle.len = buf.len();
            buf.len()
        };
        return match self.tx.try_send(handle) {
            Ok(_) => Ready(Ok(size)),
            Err(TrySendError::Full(b)) => {
                // a large performance loss, but have to do this
                self.allocator.release(b);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(TrySendError::Closed(_)) => Ready(Err(io_err("chan closed"))),
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
            let remaining = buffer.len - offset;
            if remaining <= buf.remaining() {
                buf.initialize_unfilled()[..remaining]
                    .copy_from_slice(&buffer.as_ready()[offset..]);
                buf.advance(remaining);
                self.pending_read = None;
                Ready(Ok(()))
            } else {
                let remaining = buf.remaining();
                buf.initialize_unfilled()[..remaining]
                    .copy_from_slice(&buffer.as_ready()[offset..offset + remaining]);
                self.pending_read = Some((buffer, offset + remaining));
                buf.advance(remaining);
                Ready(Ok(()))
            }
        } else {
            return match self.rx.poll_recv(cx) {
                Ready(Some(v)) => {
                    if v.len <= buf.remaining() {
                        buf.initialize_unfilled()[..v.len].copy_from_slice(v.as_ready());
                        buf.advance(v.len);
                        Ready(Ok(()))
                    } else {
                        let remaining = buf.remaining();
                        buf.initialize_unfilled()[..remaining]
                            .copy_from_slice(&v.as_ready()[..remaining]);
                        self.pending_read = Some((v, remaining));
                        buf.advance(remaining);
                        Ready(Ok(()))
                    }
                }
                Ready(None) => Ready(Err(io_err("done"))),
                Poll::Pending => Poll::Pending,
            };
        }
    }
}
