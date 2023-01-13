use crate::common::{as_io_err, io_err};
use bytes::{Buf, Bytes};
use futures::{sink::Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::{Error, Message};
use tokio_tungstenite::WebSocketStream;

pub struct AsyncWsStream<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> {
    stream: WebSocketStream<S>,
    read_buf: Option<Bytes>,
}
impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncWsStream<S> {
    pub fn new(stream: WebSocketStream<S>) -> AsyncWsStream<S> {
        Self {
            stream,
            read_buf: None,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncRead for AsyncWsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            // read remaining data
            if let Some(ref mut remaining) = self.read_buf {
                if remaining.remaining() <= buf.remaining() {
                    buf.put_slice(remaining);
                    self.read_buf = None;
                } else {
                    let len = buf.remaining();
                    buf.put_slice(&remaining[..len]);
                    remaining.advance(len);
                }
                return Poll::Ready(Ok(()));
            }

            match ready!(Pin::new(&mut self.stream).poll_next(cx)) {
                None => {
                    return Poll::Ready(Err(io_err("Websocket closed")));
                }
                Some(Err(err)) => {
                    return Poll::Ready(Err(as_io_err(err)));
                }
                Some(Ok(msg)) => match msg {
                    Message::Binary(data) => {
                        if data.len() <= buf.remaining() {
                            buf.put_slice(data.as_slice());
                            return Poll::Ready(Ok(()));
                        } else {
                            self.read_buf = Some(Bytes::from(data));
                            continue; // keep data and return partial
                        }
                    }
                    Message::Close(_) => {
                        return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()))
                    }
                    _ => {
                        return Poll::Ready(Err(io_err("Unexpected websocket message")));
                    }
                },
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncWrite for AsyncWsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        ready!(Pin::new(&mut self.stream)
            .poll_ready(cx)
            .map_err(|e| as_io_err(e))?);
        Pin::new(&mut self.stream)
            .start_send(Message::Binary(buf.into()))
            .map_err(|e| as_io_err(e))?;
        Poll::Ready(Ok(buf.remaining()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream)
            .poll_flush(cx)
            .map_err(|e| as_io_err(e))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        ready!(Pin::new(&mut self.stream)
            .poll_ready(cx)
            .map_err(|e| as_io_err(e))?);
        let _ = Pin::new(&mut self.stream).start_send(Message::Close(None));
        Pin::new(&mut self.stream)
            .poll_close(cx)
            .map_err(|e| as_io_err(e))
    }
}
