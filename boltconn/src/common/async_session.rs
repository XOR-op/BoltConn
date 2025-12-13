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
    chan_recv: mpsc::UnboundedReceiver<wintun::Packet>,
}

impl AsyncSession {
    pub fn new(session: Session) -> Self {
        let (chan_send, chan_recv) = mpsc::unbounded_channel();
        let session = Arc::new(session);
        let session2 = session.clone();
        thread::spawn(move || {
            loop {
                match session2.receive_blocking() {
                    Ok(pkt) => {
                        let _ = chan_send.send(pkt);
                    }
                    Err(wintun::Error::ShuttingDown) => {
                        break;
                    }
                    Err(e) => {
                        tracing::error!("Failed to receive packet: {:?}", e);
                        continue;
                    }
                }
            }
        });
        Self { session, chan_recv }
    }
}

impl AsyncRead for AsyncSession {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match std::task::ready!(self.chan_recv.poll_recv(cx)) {
            Some(pkt) => {
                let pkt = pkt.bytes();
                if pkt.len() > buf.remaining() {
                    tracing::warn!("TUN packet truncated: {} > {}", pkt.len(), buf.remaining());
                    buf.put_slice(&pkt[..buf.remaining()]);
                } else {
                    buf.put_slice(pkt);
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
        let mut out_pkt = self.session.allocate_send_packet(buf.len() as u16)?;
        out_pkt.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(out_pkt);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
