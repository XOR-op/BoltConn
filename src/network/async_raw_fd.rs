use std::convert::TryFrom;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, Poll::*};

use tokio::io::{unix, AsyncRead, AsyncWrite, ReadBuf};

fn set_nonblock(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(Error::last_os_error());
    }

    match unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub struct AsyncRawFd(unix::AsyncFd<RawFd>);

impl TryFrom<RawFd> for AsyncRawFd {
    type Error = Error;

    fn try_from(fd: RawFd) -> Result<Self> {
        set_nonblock(fd)?;
        Ok(Self(unix::AsyncFd::new(fd)?))
    }
}

impl AsRawFd for AsyncRawFd {
    fn as_raw_fd(&self) -> RawFd {
        *self.0.get_ref()
    }
}

impl AsyncRead for AsyncRawFd {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        loop {
            let mut ready = match self.0.poll_read_ready(cx) {
                Ready(x) => x?,
                Pending => return Pending,
            };

            let ret = unsafe {
                libc::read(
                    self.as_raw_fd(),
                    buf.unfilled_mut() as *mut _ as _,
                    buf.remaining(),
                )
            };

            if ret < 0 {
                let e = Error::last_os_error();
                if e.kind() == ErrorKind::WouldBlock {
                    ready.clear_ready();
                    continue;
                } else {
                    return Ready(Err(e));
                }
            } else {
                let n = ret as usize;
                unsafe { buf.assume_init(n) };
                buf.advance(n);
                return Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for AsyncRawFd {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        loop {
            let mut ready = match self.0.poll_write_ready(cx) {
                Ready(x) => x?,
                Pending => return Pending,
            };

            let ret = unsafe { libc::write(self.as_raw_fd(), buf.as_ptr() as _, buf.len()) };

            return if ret < 0 {
                let e = Error::last_os_error();
                if e.kind() == ErrorKind::WouldBlock {
                    ready.clear_ready();
                    continue;
                } else {
                    Ready(Err(e))
                }
            } else {
                Ready(Ok(ret as usize))
            };
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Ready(Ok(()))
    }
}
