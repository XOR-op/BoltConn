use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

mod direct;
mod nat_adapter;
mod shadowsocks;
mod socks5;
mod tun_adapter;

pub use crate::adapter::shadowsocks::*;
use crate::common::buf_pool::{PktBufHandle, PktBufPool};
use crate::common::duplex_chan::DuplexChan;
use crate::proxy::NetworkAddr;
pub use direct::*;
pub use nat_adapter::*;
pub use socks5::*;
pub use tun_adapter::*;

pub struct TcpStatus {
    src: SocketAddr,
    dst: NetworkAddr,
    available: Arc<AtomicU8>,
}

impl TcpStatus {
    pub fn new(src: SocketAddr, dst: NetworkAddr, available: Arc<AtomicU8>) -> Self {
        Self {
            src,
            dst,
            available,
        }
    }
}

pub struct Connector {
    pub tx: mpsc::Sender<PktBufHandle>,
    pub rx: mpsc::Receiver<PktBufHandle>,
}

impl Connector {
    pub fn new(tx: mpsc::Sender<PktBufHandle>, rx: mpsc::Receiver<PktBufHandle>) -> Self {
        Self { tx, rx }
    }

    pub fn new_pair(size: usize) -> (Self, Self) {
        let (utx, urx) = mpsc::channel(size);
        let (dtx, drx) = mpsc::channel(size);
        (Connector::new(utx, drx), Connector::new(dtx, urx))
    }
}

#[derive(Debug, Clone)]
pub enum OutboundType {
    Direct,
    Socks5,
    Http,
    Wireguard,
    Openvpn,
    Shadowsocks,
    Trojan,
}

pub trait TcpOutBound: Send + Sync {
    /// Run with tokio::spawn.
    fn spawn_tcp(&self, inbound: Connector) -> JoinHandle<io::Result<()>>;

    /// Run with tokio::spawn, returning handle and a duplex channel
    fn spawn_tcp_with_chan(&self) -> (DuplexChan, JoinHandle<io::Result<()>>);
}

pub trait UdpOutBound: Send + Sync {
    /// Run with tokio::spawn.
    fn spawn_udp(&self, inbound: Connector) -> JoinHandle<io::Result<()>>;

    /// Run with tokio::spawn, returning handle and a duplex channel
    fn spawn_udp_with_chan(&self) -> (DuplexChan, JoinHandle<io::Result<()>>);
}

async fn established_tcp<T>(inbound: Connector, outbound: T, allocator: PktBufPool)
where
    T: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
    let (mut out_read, mut out_write) = tokio::io::split(outbound);
    let allocator2 = allocator.clone();
    let Connector { tx, mut rx } = inbound;
    // recv from inbound and send to outbound
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(buf) => {
                    let res = out_write.write_all(buf.as_ready()).await;
                    allocator2.release(buf);
                    if let Err(err) = res {
                        tracing::warn!("write to outbound failed: {}", err);
                        break;
                    }
                }
                None => {
                    break;
                }
            }
        }
    });
    // recv from outbound and send to inbound
    loop {
        let mut buf = allocator.obtain().await;
        match buf.read(&mut out_read).await {
            Ok(0) => {
                allocator.release(buf);
                break;
            }
            Ok(_) => {
                if let Err(err) = tx.send(buf).await {
                    allocator.release(err.0);
                    tracing::warn!("write to inbound failed");
                    break;
                }
            }
            Err(err) => {
                allocator.release(buf);
                tracing::warn!("[Direct] encounter error: {}", err);
                break;
            }
        }
    }
}

#[derive(Clone)]
enum UdpSocketWrapper {
    Direct(Arc<UdpSocket>),
}

impl UdpSocketWrapper {
    async fn send(&self, data: &[u8], dest: SocketAddr) -> anyhow::Result<()> {
        match self {
            UdpSocketWrapper::Direct(s) => {
                s.send_to(data, dest).await?;
            }
        }
        Ok(())
    }
    async fn recv(&self, data: &mut [u8]) -> anyhow::Result<(usize, SocketAddr)> {
        match self {
            UdpSocketWrapper::Direct(s) => {
                let (len, addr) = s.recv_from(data).await?;
                Ok((len, addr))
            }
        }
    }
}

async fn established_udp(
    inbound: Connector,
    outbound: UdpSocketWrapper,
    allocator: PktBufPool,
    dest: SocketAddr,
) {
    // establish udp
    let allocator2 = allocator.clone();
    let outbound2 = outbound.clone();
    let dest2 = dest.clone();
    let Connector { tx, mut rx } = inbound;
    // recv from inbound and send to outbound
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(buf) => {
                    let res = outbound2.send(buf.as_ready(), dest2).await;
                    allocator2.release(buf);
                    if let Err(err) = res {
                        tracing::warn!("write to outbound failed: {}", err);
                        break;
                    }
                }
                None => {
                    break;
                }
            }
        }
    });
    // recv from outbound and send to inbound
    loop {
        let mut buf = allocator.obtain().await;
        let res = outbound.recv(buf.as_uninited()).await;
        match res {
            Ok((0, _addr)) => {
                allocator.release(buf);
                break;
            }
            Ok((n, addr)) => {
                buf.len = n;
                if dest != addr {
                    // we follow symmetric NAT here; drop unknown packets
                    allocator.release(buf);
                    continue;
                }
                if let Err(err) = tx.send(buf).await {
                    allocator.release(err.0);
                    tracing::warn!("write to inbound failed");
                    break;
                }
            }
            Err(err) => {
                allocator.release(buf);
                tracing::warn!("[Direct] encounter error: {}", err);
                break;
            }
        }
    }
}
