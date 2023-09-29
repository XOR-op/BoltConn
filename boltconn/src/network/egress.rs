use crate::common::io_err;
use crate::platform;
use crate::platform::get_iface_address;
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::Result;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
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

    pub async fn tcp_stream(&self, addr: SocketAddr) -> Result<TcpStream> {
        match addr {
            SocketAddr::V4(v4addr) => {
                if v4addr.ip().is_loopback() {
                    TcpStream::connect(SocketAddr::V4(v4addr)).await
                } else {
                    self.tcpv4_stream(SocketAddr::V4(v4addr)).await
                }
            }
            SocketAddr::V6(v6addr) => {
                if v6addr.ip().is_loopback() {
                    TcpStream::connect(SocketAddr::V6(v6addr)).await
                } else {
                    self.tcpv6_stream(SocketAddr::V6(v6addr)).await
                }
            }
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
        let IpAddr::V4(local_addr) = get_iface_address(self.iface_name.as_str())? else {
            return Err(io_err("not ipv4"));
        };
        let std_udp_sock = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        platform::bind_to_device(std_udp_sock.as_raw_fd(), self.iface_name.as_str())?;
        std_udp_sock.bind(&SockAddr::from(SocketAddr::new(local_addr.into(), 0)))?;
        std_udp_sock.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_udp_sock.into())?;
        Ok(socket)
    }

    pub async fn udpv6_socket(&self) -> Result<UdpSocket> {
        let IpAddr::V6(local_addr) = get_iface_address(self.iface_name.as_str())? else {
            return Err(io_err("not ipv4"));
        };
        let std_udp_sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        platform::bind_to_device(std_udp_sock.as_raw_fd(), self.iface_name.as_str())?;
        std_udp_sock.bind(&SockAddr::from(SocketAddr::new(local_addr.into(), 0)))?;
        std_udp_sock.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_udp_sock.into())?;
        Ok(socket)
    }
}
