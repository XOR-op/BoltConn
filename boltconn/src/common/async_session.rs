use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    thread,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};
use wintun::Session;

pub struct AsyncSession {
    session: Arc<Session>,
    chan_recv: mpsc::Receiver<Vec<u8>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl AsyncSession {
    pub fn new(session: Session) -> Self {
        let (chan_send, chan_recv) = mpsc::channel(256);
        let session = Arc::new(session);
        let session2 = session.clone();
        let worker = thread::spawn(move || {
            loop {
                match session2.receive_blocking() {
                    Ok(pkt) => {
                        // Release the Wintun ring slot before waiting for the consumer.
                        let bytes = pkt.bytes().to_vec();
                        drop(pkt);
                        if chan_send.blocking_send(bytes).is_err() {
                            break;
                        }
                    }
                    Err(wintun::Error::ShuttingDown) => {
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to receive packet: {:?}", e);
                        break;
                    }
                }
            }
        });
        Self {
            session,
            chan_recv,
            worker: Some(worker),
        }
    }
}

impl AsyncRead for AsyncSession {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match std::task::ready!(self.chan_recv.poll_recv(cx)) {
            Some(pkt) => {
                if pkt.len() > buf.remaining() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TUN receive buffer is too small for the packet",
                    )));
                } else {
                    buf.put_slice(&pkt);
                }
                Poll::Ready(Ok(()))
            }
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for AsyncSession {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let length = u16::try_from(buf.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN packet exceeds 65535 bytes",
            )
        })?;
        let mut out_pkt = self.session.allocate_send_packet(length)?;
        out_pkt.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(out_pkt);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.session.shutdown().map_err(Into::into))
    }
}

impl Drop for AsyncSession {
    fn drop(&mut self) {
        // Unblock either the bounded queue or receive_blocking before joining.
        self.chan_recv.close();
        match self.session.shutdown() {
            Ok(()) => {
                if let Some(worker) = self.worker.take() {
                    let _ = worker.join();
                }
            }
            Err(error) => tracing::warn!(%error, "Failed to stop Wintun reader"),
        }
    }
}
