use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

mod chain;
mod direct;
mod http;
mod shadowsocks;
mod socks5;
mod tcp_adapter;
mod trojan;
mod udp_adapter;
mod wireguard;

pub use self::http::*;
pub use super::adapter::shadowsocks::*;
use crate::common::buf_pool::{mut_buf, read_to_bytes_mut, PktBufPool, MAX_PKT_SIZE};
use crate::common::duplex_chan::DuplexChan;
use crate::common::{io_err, OutboundTrait};
use crate::network::dns::Dns;
use crate::proxy::{ConnAbortHandle, ConnAgent, NetworkAddr};
pub use chain::*;
pub use direct::*;
pub use socks5::*;
pub use tcp_adapter::*;
pub use trojan::*;
pub use udp_adapter::*;
pub use wireguard::*;

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
    pub tx: mpsc::Sender<Bytes>,
    pub rx: mpsc::Receiver<Bytes>,
}

impl Connector {
    pub fn new(tx: mpsc::Sender<Bytes>, rx: mpsc::Receiver<Bytes>) -> Self {
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
    Shadowsocks,
    Trojan,
    Wireguard,
    Chain,
}

pub trait TcpOutBound: Send + Sync {
    /// Run with tokio::spawn.
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>>;

    fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        outbound: Box<dyn OutboundTrait>,
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
    _allocator: PktBufPool,
    abort_handle: ConnAbortHandle,
) where
    T: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
    let (mut out_read, mut out_write) = tokio::io::split(outbound);
    let Connector { tx, mut rx } = inbound;
    // recv from inbound and send to outbound
    let _guard = DuplexCloseGuard::new(tokio::spawn(async move {
        while let Some(buf) = rx.recv().await {
            let res = out_write.write_all(buf.as_ref()).await;
            if let Err(err) = res {
                tracing::warn!("write to outbound failed: {}", err);
                break;
            }
        }
        // tracing::debug!("Outbound outgoing closed");
    }));
    // recv from outbound and send to inbound
    loop {
        let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);

        select! {
            _ = tx.closed() => break,
            data = read_to_bytes_mut(&mut buf, &mut out_read) => match data {
                Ok(0) => {
                    break;
                }
                Ok(_) => {
                    if tx.send(buf.freeze()).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
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
    _allocator: PktBufPool,
    abort_handle: ConnAbortHandle,
) {
    // establish udp
    let outbound2 = outbound.clone();
    let Connector { tx, mut rx } = inbound;
    // recv from inbound and send to outbound
    let _guard = UdpDropGuard(tokio::spawn(async move {
        while let Some(buf) = rx.recv().await {
            let res = outbound2.send(buf.as_ref()).await;
            if let Err(err) = res {
                tracing::warn!("write to outbound failed: {}", err);
                break;
            }
        }
    }));
    // recv from outbound and send to inbound
    loop {
        let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
        let res = outbound.recv(unsafe { mut_buf(&mut buf) }).await;
        match res {
            Ok((0, _)) => {
                break;
            }
            Ok((n, match_addr)) => {
                unsafe { buf.advance_mut(n) };
                if !match_addr {
                    // we follow symmetric NAT here; drop unknown packets
                    tracing::trace!("Sym NAT drop unknown packet");
                    continue;
                }
                if tx.send(buf.freeze()).await.is_err() {
                    tracing::warn!("write to inbound failed");
                    abort_handle.cancel().await;
                    break;
                }
            }
            Err(err) => {
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

async fn lookup(dns: &Dns, addr: &NetworkAddr) -> io::Result<SocketAddr> {
    Ok(match addr {
        NetworkAddr::Raw(addr) => *addr,
        NetworkAddr::DomainName {
            ref domain_name,
            port,
        } => {
            let resp = dns
                .genuine_lookup(domain_name.as_str())
                .await
                .ok_or_else(|| io_err("dns not found"))?;
            SocketAddr::new(resp, *port)
        }
    })
}
