use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

mod direct;
mod nat_adapter;
mod shadowsocks;
mod socks5;
mod trojan;
mod tun_adapter;

pub use super::adapter::shadowsocks::*;
use crate::common::buf_pool::{PktBufHandle, PktBufPool};
use crate::common::duplex_chan::DuplexChan;
use crate::proxy::{ConnAbortHandle, ConnAgent, NetworkAddr};
pub use direct::*;
pub use nat_adapter::*;
pub use socks5::*;
pub use trojan::*;
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
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>>;

    /// Run with tokio::spawn, returning handle and a duplex channel
    fn spawn_tcp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<io::Result<()>>);
}

pub trait UdpOutBound: Send + Sync {
    /// Run with tokio::spawn.
    fn spawn_udp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>>;

    /// Run with tokio::spawn, returning handle and a duplex channel
    fn spawn_udp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<io::Result<()>>);
}

async fn established_tcp<T>(
    inbound: Connector,
    outbound: T,
    allocator: PktBufPool,
    abort_handle: ConnAbortHandle,
) where
    T: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
    let (mut out_read, mut out_write) = tokio::io::split(outbound);
    let allocator2 = allocator.clone();
    let Connector { tx, mut rx } = inbound;
    // recv from inbound and send to outbound
    let _guard = DuplexCloseGuard::new(tokio::spawn(async move {
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
        // tracing::debug!("Outbound outgoing closed");
    }));
    // recv from outbound and send to inbound
    loop {
        let mut buf = allocator.obtain().await;
        select! {
            _ = tx.closed() => break,
            data = buf.read(&mut out_read) => match data {
                Ok(0) => {
                    allocator.release(buf);
                    break;
                }
                Ok(_) => {
                    if let Err(err) = tx.send(buf).await {
                        allocator.release(err.0);
                        break;
                    }
                }
                Err(err) => {
                    allocator.release(buf);
                    tracing::warn!("outbound read error: {}", err);
                    abort_handle.cancel().await;
                    break;
                }
            }
        }
    }
    // tracing::debug!("Outbound incoming closed");
}

#[async_trait]
trait UdpSocketAdapter: Clone + Send {
    async fn send(&self, data: &[u8]) -> anyhow::Result<()>;

    // @return: <length>, <if addr matches target>
    async fn recv(&self, data: &mut [u8]) -> anyhow::Result<(usize, bool)>;
}

async fn established_udp<S: UdpSocketAdapter + Sync + 'static>(
    inbound: Connector,
    outbound: S,
    allocator: PktBufPool,
    abort_handle: ConnAbortHandle,
) {
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
                    abort_handle.cancel().await;
                    break;
                }
            }
            Err(err) => {
                allocator.release(buf);
                tracing::warn!("outbound read error: {}", err);
                abort_handle.cancel().await;
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
            let info = self.info.clone();
            tokio::spawn(async move { info.write().await.mark_fin() });
        }
    }
}

pub(crate) struct DuplexCloseGuard {
    handle: Option<JoinHandle<()>>,
    err_exit: bool,
}

impl DuplexCloseGuard {
    pub fn new(handle: JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
            err_exit: false,
        }
    }

    pub fn set_err_exit(&mut self) {
        self.err_exit = true;
    }
}

impl Drop for DuplexCloseGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if !handle.is_finished() {
                if self.err_exit {
                    handle.abort();
                } else {
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        if !handle.is_finished() {
                            // wait until 30s
                            tokio::time::sleep(Duration::from_secs(29)).await;
                            handle.abort();
                            // done, return deliberately
                        }
                    });
                }
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
