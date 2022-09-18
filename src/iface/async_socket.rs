use libc::{c_int, sockaddr_in, socklen_t};
use std::convert::TryFrom;
use std::io::{Error, ErrorKind, Result};
use std::{mem, net};
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, Poll::*};
use byteorder::ByteOrder;
use crate::iface::platform;

use tokio::io::{unix, AsyncRead, AsyncWrite, ReadBuf};

pub struct AsyncRawSocket {
    pub fd: unix::AsyncFd<RawFd>,
    pub sockaddr: sockaddr_in,
}

impl AsyncRawSocket {
    pub fn create(fd: c_int, dst_addr: net::Ipv4Addr) -> Result<Self> {
        set_nonblock(fd)?;
        let mut sockaddr: sockaddr_in = unsafe { mem::zeroed() };
        sockaddr.sin_family=libc::AF_INET as libc::sa_family_t;
        sockaddr.sin_port = 0;
        sockaddr.sin_addr = libc::in_addr{ s_addr: u32::to_be(u32::from(dst_addr)) };
        
        Ok(Self {
            fd: unix::AsyncFd::new(RawFd::from(fd))?,
            sockaddr,
        })
    }
}

impl AsRawFd for AsyncRawSocket {
    fn as_raw_fd(&self) -> RawFd {
        *self.fd.get_ref()
    }
}

impl AsyncWrite for AsyncRawSocket {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        loop {
            let mut ready = match self.fd.poll_write_ready(cx) {
                Ready(x) => x?,
                Pending => return Pending,
            };

            let ret = unsafe {
                libc::sendto(
                    self.as_raw_fd(),
                    buf.as_ptr() as _,
                    buf.len(),
                    0,
                    &self.sockaddr as *const _ as *const _,
                    mem::size_of_val(&self.sockaddr) as socklen_t,
                )
            };

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
