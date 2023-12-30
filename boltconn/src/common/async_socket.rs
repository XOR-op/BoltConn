use libc::{c_int, sockaddr_in, sockaddr_in6, socklen_t};
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, Poll::*};

use tokio::io::{unix, AsyncWrite};

pub struct AsyncRawSocket {
    fd: unix::AsyncFd<RawFd>,
    sockaddr: SockAddr,
}

enum SockAddr {
    V4(sockaddr_in),
    V6(sockaddr_in6),
}

impl AsyncRawSocket {
    pub fn create(fd: c_int, dst_addr: IpAddr) -> Result<Self> {
        set_nonblock(fd)?;
        match dst_addr {
            IpAddr::V4(dst_addr) => {
                let mut sockaddr: sockaddr_in = unsafe { mem::zeroed() };
                sockaddr.sin_family = libc::AF_INET as libc::sa_family_t;
                sockaddr.sin_port = 0;
                sockaddr.sin_addr = libc::in_addr {
                    s_addr: u32::to_be(u32::from(dst_addr)),
                };
                Ok(Self {
                    fd: unix::AsyncFd::new(fd)?,
                    sockaddr: SockAddr::V4(sockaddr),
                })
            }
            IpAddr::V6(dst_addr) => {
                let mut sockaddr: sockaddr_in6 = unsafe { mem::zeroed() };
                sockaddr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sockaddr.sin6_port = 0;
                sockaddr.sin6_addr = libc::in6_addr {
                    s6_addr: dst_addr.octets(),
                };
                Ok(Self {
                    fd: unix::AsyncFd::new(fd)?,
                    sockaddr: SockAddr::V6(sockaddr),
                })
            }
        }
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
                match &self.sockaddr {
                    SockAddr::V4(sockaddr) => libc::sendto(
                        self.as_raw_fd(),
                        buf.as_ptr() as _,
                        buf.len(),
                        0,
                        sockaddr as *const _ as *const _,
                        mem::size_of_val(sockaddr) as socklen_t,
                    ),
                    SockAddr::V6(sockaddr6) => libc::sendto(
                        self.as_raw_fd(),
                        buf.as_ptr() as _,
                        buf.len(),
                        0,
                        sockaddr6 as *const _ as *const _,
                        mem::size_of_val(sockaddr6) as socklen_t,
                    ),
                }
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
