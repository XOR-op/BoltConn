use crate::common::io_err;
use crate::platform;
use crate::platform::get_iface_address;
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::Result;
use std::net::{IpAddr, SocketAddr};
#[cfg(not(target_os = "windows"))]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
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
        if addr.ip().is_loopback() {
            return TcpStream::connect(addr).await;
        }
        // With the kill switch on, macOS pf sometimes fails to attribute a root socket's first SYN
        // when connects race, and its `block return` rule refuses it locally in well under 5ms.
        // Retry such refusals after a random delay so the attempts no longer coincide.
        #[cfg(target_os = "macos")]
        for (min_ms, max_ms) in [(5, 10), (5, 15)].into_iter() {
            let start = std::time::Instant::now();
            match self.remote_tcp_stream(addr).await {
                Err(e)
                    if e.kind() == std::io::ErrorKind::ConnectionRefused
                        && start.elapsed() <= std::time::Duration::from_millis(5) =>
                {
                    let delay = std::time::Duration::from_millis(fastrand::u64(min_ms..=max_ms));
                    tokio::time::sleep(delay).await;
                }
                result => return result,
            }
        }
        self.remote_tcp_stream(addr).await
    }

    async fn remote_tcp_stream(&self, addr: SocketAddr) -> Result<TcpStream> {
        match addr {
            SocketAddr::V4(_) => self.tcpv4_stream(addr).await,
            SocketAddr::V6(_) => self.tcpv6_stream(addr).await,
        }
    }

    async fn tcpv4_stream(&self, addr: SocketAddr) -> Result<TcpStream> {
        let socket = TcpSocket::new_v4()?;
        #[cfg(target_os = "linux")]
        platform::set_fwmark(socket.as_raw_fd())?;
        #[cfg(not(target_os = "windows"))]
        platform::bind_to_device(socket.as_raw_fd(), self.iface_name.as_str())?;
        #[cfg(target_os = "windows")]
        {
            let IpAddr::V4(local_addr) = get_iface_address(self.iface_name.as_str())? else {
                return Err(io_err("not ipv4"));
            };
            platform::bind_to_interface_v4(socket.as_raw_socket(), &self.iface_name)?;
            socket.bind(SocketAddr::new(local_addr.into(), 0))?;
        }
        socket.connect(addr).await
    }

    #[cfg(windows)]
    async fn tcpv6_stream(&self, mut addr: SocketAddr) -> Result<TcpStream> {
        let socket = TcpSocket::new_v6()?;
        let index = platform::bind_to_interface_v6(socket.as_raw_socket(), &self.iface_name)?;
        if let SocketAddr::V6(ref mut destination) = addr {
            if destination.scope_id() != 0 && destination.scope_id() != index {
                return Err(io_err("IPv6 scope does not match the outbound interface"));
            }
            if destination.ip().is_unicast_link_local() {
                destination.set_scope_id(index);
            }
        }
        socket.connect(addr).await
    }

    #[cfg(not(windows))]
    async fn tcpv6_stream(&self, addr: SocketAddr) -> Result<TcpStream> {
        let socket = TcpSocket::new_v6()?;
        #[cfg(target_os = "linux")]
        platform::set_fwmark(socket.as_raw_fd())?;
        #[cfg(not(target_os = "windows"))]
        platform::bind_to_device(socket.as_raw_fd(), self.iface_name.as_str())?;
        socket.connect(addr).await
    }

    pub async fn udpv4_socket(&self) -> Result<UdpSocket> {
        let IpAddr::V4(local_addr) = get_iface_address(self.iface_name.as_str())? else {
            return Err(io_err("not ipv4"));
        };
        let std_udp_sock = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        #[cfg(target_os = "linux")]
        platform::set_fwmark(std_udp_sock.as_raw_fd())?;
        #[cfg(not(target_os = "windows"))]
        platform::bind_to_device(std_udp_sock.as_raw_fd(), self.iface_name.as_str())?;
        #[cfg(windows)]
        platform::bind_to_interface_v4(std_udp_sock.as_raw_socket(), &self.iface_name)?;
        std_udp_sock.bind(&SockAddr::from(SocketAddr::new(local_addr.into(), 0)))?;
        std_udp_sock.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_udp_sock.into())?;
        Ok(socket)
    }

    #[cfg(windows)]
    pub async fn udpv6_socket(&self) -> Result<UdpSocket> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "IPv6 UDP egress is not supported on Windows",
        ))
    }

    #[cfg(not(windows))]
    pub async fn udpv6_socket(&self) -> Result<UdpSocket> {
        let IpAddr::V6(local_addr) = get_iface_address(self.iface_name.as_str())? else {
            return Err(io_err("not ipv4"));
        };
        let std_udp_sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        #[cfg(target_os = "linux")]
        platform::set_fwmark(std_udp_sock.as_raw_fd())?;
        #[cfg(not(target_os = "windows"))]
        platform::bind_to_device(std_udp_sock.as_raw_fd(), self.iface_name.as_str())?;
        std_udp_sock.bind(&SockAddr::from(SocketAddr::new(local_addr.into(), 0)))?;
        std_udp_sock.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_udp_sock.into())?;
        Ok(socket)
    }
}
