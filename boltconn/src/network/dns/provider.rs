use crate::common::io_err;
use crate::network::egress::Egress;
use hickory_resolver::net::runtime::{
    RuntimeProvider, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd,
};
use std::net::SocketAddr;
use std::pin::Pin;
use std::{future::Future, time::Duration};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Clone)]
pub struct IfaceProvider {
    handle: TokioHandle,
    interface_name: String,
}

impl IfaceProvider {
    pub fn new(iface_name: &str) -> Self {
        Self {
            handle: Default::default(),
            interface_name: iface_name.to_string(),
        }
    }
}

impl RuntimeProvider for IfaceProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        let iface = self.interface_name.clone();
        Box::pin(async move {
            let tcp = if let Some(timeout) = timeout {
                tokio::time::timeout(timeout, Egress::new(iface.as_str()).tcp_stream(server_addr))
                    .await
                    .map_err(|_| io_err("timeout"))??
            } else {
                Egress::new(iface.as_str()).tcp_stream(server_addr).await?
            };
            Ok(AsyncIoTokioAsStd(tcp))
        })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        let iface = self.interface_name.clone();
        Box::pin(async move {
            let udp = match server_addr {
                SocketAddr::V4(_) => {
                    let udp = Egress::new(iface.as_str()).udpv4_socket().await?;
                    udp.connect(server_addr).await?;
                    udp
                }
                SocketAddr::V6(_) => {
                    let udp = Egress::new(iface.as_str()).udpv6_socket().await?;
                    udp.connect(server_addr).await?;
                    udp
                }
            };
            Ok(udp)
        })
    }
}

#[derive(Clone)]
pub struct PlainProvider {
    handle: TokioHandle,
}

impl PlainProvider {
    pub fn new() -> Self {
        Self {
            handle: Default::default(),
        }
    }
}

impl RuntimeProvider for PlainProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        Box::pin(async move {
            let tcp = if let Some(timeout) = timeout {
                tokio::time::timeout(timeout, TcpStream::connect(server_addr))
                    .await
                    .map_err(|_| io_err("timeout"))??
            } else {
                TcpStream::connect(server_addr).await?
            };
            Ok(AsyncIoTokioAsStd(tcp))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        Box::pin(async move {
            let udp = UdpSocket::bind(local_addr).await?;
            udp.connect(server_addr).await?;
            Ok(udp)
        })
    }
}
