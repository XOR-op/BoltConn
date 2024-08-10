use crate::common::async_raw_fd::AsyncRawFd;
use crate::common::async_socket::AsyncRawSocket;
use crate::network::packet::ip::IPPkt;
use crate::platform;
use ipnet::Ipv4Net;
use std::io;
use std::io::ErrorKind;
use std::os::fd::{IntoRawFd, RawFd};
use tokio::io::AsyncWriteExt;

pub(super) struct TunInstance {
    fd: Option<AsyncRawFd>,
    ctl_fd: RawFd,
}

impl TunInstance {
    pub fn new(fd: AsyncRawFd, ctl_fd: RawFd) -> Self {
        Self {
            fd: Some(fd),
            ctl_fd,
        }
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

    pub async fn send_outbound(pkt: &IPPkt, gw_name: &str, ipv6_enabled: bool) -> io::Result<()> {
        match pkt {
            IPPkt::V4(_) => {
                let fd = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
                )?
                .into_raw_fd();
                platform::bind_to_device(fd, gw_name).map_err(|e| {
                    io::Error::new(ErrorKind::Other, format!("Bind to device failed, {}", e))
                })?;
                let mut outbound = AsyncRawSocket::create(fd, pkt.dst_addr())?;
                let _ = outbound.write(pkt.packet_data()).await?;
            }
            IPPkt::V6(_) => {
                if ipv6_enabled {
                    let fd = socket2::Socket::new(
                        socket2::Domain::IPV6,
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
                    )?
                    .into_raw_fd();
                    platform::bind_to_device(fd, gw_name).map_err(|e| {
                        io::Error::new(ErrorKind::Other, format!("Bind to device failed, {}", e))
                    })?;
                    let mut outbound = AsyncRawSocket::create(fd, pkt.dst_addr())?;
                    let _ = outbound.write(pkt.packet_data()).await?;
                } else {
                    tracing::trace!("Drop IPv6 packets: IPv6 disabled");
                }
            }
        }
        Ok(())
    }
}
