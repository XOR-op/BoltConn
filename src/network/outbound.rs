use std::io::Result;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use crate::network::get_iface_address;
use super::platform;

pub struct Outbound {
    iface_name: String,
}

impl Outbound {
    pub async fn tcpv4_stream(&self, addr: SocketAddr) -> Result<TcpStream> {
        let socket = TcpSocket::new_v4()?;
        platform::bind_to_device(socket.as_raw_fd(), self.iface_name.as_str())?;
        socket.connect(addr).await
    }


    pub async fn udp_socket(&self, port: u16) -> Result<UdpSocket> {
        let ip_addr = get_iface_address(self.iface_name.as_str())?;
        let socket = UdpSocket::bind(SocketAddr::new(ip_addr, port)).await?;
        Ok(socket)
    }
}
