use super::platform;
use crate::network::get_iface_address;
use std::io::Result;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

pub struct Egress {
    iface_name: String,
}

impl Egress {
    pub fn new(name:&str)->Self{
        Self{
            iface_name: name.to_string()
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

    pub async fn udp_socket(&self, port: u16) -> Result<UdpSocket> {
        let ip_addr = get_iface_address(self.iface_name.as_str())?;
        let socket = UdpSocket::bind(SocketAddr::new(ip_addr, port)).await?;
        Ok(socket)
    }
}
