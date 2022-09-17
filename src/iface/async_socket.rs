/*
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This file originates from nanpuyue/tokio-fd. Modification applied.

The license of this software will override the above copyright notice.
 */

use libc::{c_int, socklen_t};
use std::convert::TryFrom;
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, Poll::*};

use tokio::io::{unix, AsyncRead, AsyncWrite, ReadBuf};

pub struct AsyncRawSocket {
    fd: unix::AsyncFd<RawFd>,
    sockaddr: libc::sockaddr,
}

impl AsyncRawSocket {
    pub fn create((fd, sockaddr): (c_int, libc::sockaddr)) -> Result<Self> {
        let addr_in: libc::sockaddr_in = unsafe { mem::transmute(sockaddr) };
        let v4addr = std::net::Ipv4Addr::from(addr_in.sin_addr.s_addr.to_ne_bytes());
        tracing::trace!("Iface addr: {}:{}",v4addr,addr_in.sin_port);
        set_nonblock(fd)?;
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
                    &self.sockaddr as *const _,
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
