use ::shadowsocks::relay::Address;
use ::shadowsocks::ProxySocket;
use fast_socks5::util::target_addr::TargetAddr;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
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
use crate::proxy::{ConnAgent, NetworkAddr};
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
    let _guard = TcpHalfClosedGuard::new(tokio::spawn(async move {
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
    }));
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
                    // tracing::warn!("write to inbound failed: channel closed");
                    break;
                }
            }
            Err(err) => {
                allocator.release(buf);
                tracing::warn!("outbound read error: {}", err);
                break;
            }
        }
    }
}

#[derive(Clone)]
enum UdpSocketWrapper {
    Direct(Arc<UdpSocket>),
    Socks5(Arc<UdpSocket>, TargetAddr),
    SS(Arc<ProxySocket>, Address),
}

impl UdpSocketWrapper {
    async fn send(&self, data: &[u8]) -> anyhow::Result<()> {
        match self {
            UdpSocketWrapper::Direct(s) => {
                s.send(data).await?;
            }
            UdpSocketWrapper::Socks5(s, target) => {
                let mut buf = match target {
                    TargetAddr::Ip(s) => fast_socks5::new_udp_header(s.clone())?,
                    TargetAddr::Domain(s, p) => {
                        fast_socks5::new_udp_header((s.as_str(), p.clone()))?
                    }
                };
                buf.extend_from_slice(data);
                s.send(buf.as_slice()).await?;
            }
            UdpSocketWrapper::SS(s, target) => {
                s.send(target, data).await?;
            }
        }
        Ok(())
    }

    // @return: <length>, <if addr matches target>
    async fn recv(&self, data: &mut [u8]) -> anyhow::Result<(usize, bool)> {
        match self {
            UdpSocketWrapper::Direct(s) => {
                let (len, _) = s.recv_from(data).await?;
                // s is established by connect
                Ok((len, true))
            }
            UdpSocketWrapper::Socks5(s, target) => {
                let mut buf = [0u8; 0x10000];
                let (size, _) = s.recv_from(&mut buf).await?;
                let (frag, target_addr, raw_data) =
                    fast_socks5::parse_udp_request(&mut buf[..size]).await?;
                if frag != 0 {
                    return Err(anyhow::anyhow!("Unsupported frag value."));
                }
                data[..raw_data.len()].copy_from_slice(raw_data);
                Ok((
                    raw_data.len(),
                    match (target, target_addr) {
                        (TargetAddr::Ip(a), TargetAddr::Ip(b)) => *a == b,
                        (TargetAddr::Domain(s1, p1), TargetAddr::Domain(s2, p2)) => {
                            *p1 == p2 && *s1 == s2
                        }
                        _ => false,
                    },
                ))
            }
            UdpSocketWrapper::SS(s, target) => {
                let (len, addr, _) = s.recv(data).await?;
                Ok((len, addr == *target))
            }
        }
    }
}

async fn established_udp(inbound: Connector, outbound: UdpSocketWrapper, allocator: PktBufPool) {
    // establish udp
    let allocator2 = allocator.clone();
    let outbound2 = outbound.clone();
    let Connector { tx, mut rx } = inbound;
    // recv from inbound and send to outbound
    let _guard = UdpDropGuard(tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(buf) => {
                    let res = outbound2.send(buf.as_ready()).await;
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
    }));
    // recv from outbound and send to inbound
    loop {
        let mut buf = allocator.obtain().await;
        let res = outbound.recv(buf.as_uninited()).await;
        match res {
            Ok((0, _)) => {
                allocator.release(buf);
                break;
            }
            Ok((n, match_addr)) => {
                buf.len = n;
                if !match_addr {
                    // we follow symmetric NAT here; drop unknown packets
                    tracing::trace!("Sym NAT drop unknown packet");
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

struct TcpIndicatorGuard {
    pub indicator: Arc<AtomicU8>,
    pub info: Arc<RwLock<ConnAgent>>,
}

impl Drop for TcpIndicatorGuard {
    fn drop(&mut self) {
        self.indicator.fetch_sub(1, Ordering::Relaxed);
        if self.indicator.load(Ordering::Relaxed) == 0 {
            self.info.write().unwrap().mark_fin();
        }
    }
}

struct TcpHalfClosedGuard {
    handle: Option<JoinHandle<()>>,
}

impl TcpHalfClosedGuard {
    pub fn new(handle: JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }
}

impl Drop for TcpHalfClosedGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if !handle.is_finished() {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if !handle.is_finished() {
                        // wait until 30s
                        tokio::time::sleep(Duration::from_secs(25)).await;
                        handle.abort();
                        // done, return deliberately
                    }
                });
            }
        }
    }
}

struct UdpDropGuard(JoinHandle<()>);

impl Drop for UdpDropGuard {
    fn drop(&mut self) {
        if !self.0.is_finished() {
            self.0.abort();
        }
    }
}
