use crate::common::io_err;
use crate::platform;
use crate::platform::get_iface_address;
use libc::socket;
use std::io::Result;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::{AsRawFd, FromRawFd};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

pub struct Egress {
    iface_name: String,
}

impl Egress {
    pub fn new(name: &str) -> Self {
        Self {
            iface_name: name.to_string(),
        }
    }

    pub async fn tcpv4_stream(&self, addr: SocketAddr) -> Result<TcpStream> {
        let socket = TcpSocket::new_v4()?;
        platform::bind_to_device(socket.as_raw_fd(), self.iface_name.as_str())?;
        socket.connect(addr).await
    }

    pub async fn tcpv6_stream(&self, addr: SocketAddr) -> Result<TcpStream> {
        let socket = TcpSocket::new_v6()?;
        platform::bind_to_device(socket.as_raw_fd(), self.iface_name.as_str())?;
        socket.connect(addr).await
    }

    pub async fn udpv4_socket(&self) -> Result<UdpSocket> {
        let IpAddr::V4(local_addr) = get_iface_address(self.iface_name.as_str())?else {
            return Err(io_err("not ipv4"));
        };
        let std_udp_sock = unsafe {
            let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if fd < 0 {
                return Err(io_err("create udp socket failed"));
            }
            platform::bind_to_device(fd, self.iface_name.as_str())?;

            let sock = platform::get_sockaddr(local_addr);
            if libc::bind(
                fd,
                &sock as *const _ as *const _,
                mem::size_of_val(&sock) as libc::socklen_t,
            ) != 0
            {
                return Err(io_err("bind udp socket failed"));
            }
            std::net::UdpSocket::from_raw_fd(fd)
        };
        std_udp_sock.set_nonblocking(true)?;
        // any port
        let socket = UdpSocket::from_std(std_udp_sock)?;
        Ok(socket)
    }
}
