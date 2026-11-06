use crate::common::async_raw_fd::AsyncRawFd;
use crate::platform;
use crate::platform::errno_err;
use ipnet::Ipv4Net;
use std::io;
use std::os::fd::RawFd;

pub(super) struct TunInstance {
    fd: Option<AsyncRawFd>,
    ctl_fd: RawFd,
    #[cfg(target_os = "linux")]
    pub(super) vnet_hdr: bool,
}

impl TunInstance {
    pub fn new() -> io::Result<(Self, String)> {
        #[cfg(target_os = "macos")]
        let (fd, name) = unsafe { platform::open_tun()? };
        #[cfg(target_os = "linux")]
        let (fd, name, vnet_hdr) = unsafe { platform::open_tun()? };
        let ctl_fd = {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if fd < 0 {
                return Err(errno_err("Unable to open control fd"));
            }
            fd
        };
        Ok((
            Self {
                fd: Some(AsyncRawFd::try_from(fd)?),
                ctl_fd,
                #[cfg(target_os = "linux")]
                vnet_hdr,
            },
            name,
        ))
    }

    pub fn take_fd(&mut self) -> Option<AsyncRawFd> {
        self.fd.take()
    }

    pub fn interface_up(&self, name: &str) -> io::Result<()> {
        crate::platform::interface_up(self.ctl_fd, name)
    }

    pub fn set_address(&self, name: &str, addr: Ipv4Net) -> io::Result<()> {
        crate::platform::set_address(self.ctl_fd, name, addr)
    }
}
