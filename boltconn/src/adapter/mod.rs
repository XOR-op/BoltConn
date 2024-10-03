use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::fmt::{Display, Formatter};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

mod chain;
mod direct;
mod http;
mod shadowsocks;
mod socks5;
mod ssh;
mod tcp_adapter;
mod trojan;
mod udp_adapter;
mod udp_over_tcp;
mod wireguard;

pub use self::http::*;
pub use super::adapter::shadowsocks::*;

use crate::common::{io_err, mut_buf, read_to_bytes_mut, StreamOutboundTrait, MAX_PKT_SIZE};
use crate::network::dns::Dns;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, ConnContext, NetworkAddr};
use crate::transport::UdpSocketAdapter;
pub use chain::*;
pub use direct::*;
pub use socks5::*;
pub use ssh::*;
use std::future::Future;
use std::io::ErrorKind;
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

pub struct AdapterConnector<S> {
    pub tx: mpsc::Sender<S>,
    pub rx: mpsc::Receiver<S>,
}

impl<S> AdapterConnector<S> {
    pub fn new(tx: mpsc::Sender<S>, rx: mpsc::Receiver<S>) -> Self {
        Self { tx, rx }
    }

    pub fn new_pair(size: usize) -> (Self, Self) {
        let (utx, urx) = mpsc::channel(size);
        let (dtx, drx) = mpsc::channel(size);
        (
            AdapterConnector::new(utx, drx),
            AdapterConnector::new(dtx, urx),
        )
    }
}

pub type Connector = AdapterConnector<Bytes>;
pub type AddrConnector = AdapterConnector<(Bytes, NetworkAddr)>;

#[derive(Debug, Clone)]
pub struct AddrConnectorWrapper {
    pub tx: mpsc::Sender<(Bytes, NetworkAddr)>,
    pub rx: Arc<Mutex<mpsc::Receiver<(Bytes, NetworkAddr)>>>,
}

impl From<AddrConnector> for AddrConnectorWrapper {
    fn from(value: AddrConnector) -> Self {
        Self {
            tx: value.tx,
            rx: Arc::new(Mutex::new(value.rx)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum OutboundType {
    Direct,
    Socks5,
    Http,
    Shadowsocks,
    Trojan,
    Wireguard,
    Chain,
    Ssh,
}

impl Display for OutboundType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OutboundType::Direct => "direct",
            OutboundType::Socks5 => "socks5",
            OutboundType::Http => "http",
            OutboundType::Shadowsocks => "shadowsocks",
            OutboundType::Trojan => "trojan",
            OutboundType::Wireguard => "wireguard",
            OutboundType::Chain => "chain",
            OutboundType::Ssh => "ssh",
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpTransferType {
    Tcp,
    TcpOverUdp,
    NotApplicable,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UdpTransferType {
    Udp,
    UdpOverTcp,
    NotApplicable,
}

impl OutboundType {
    pub fn tcp_transfer_type(&self) -> TcpTransferType {
        match self {
            OutboundType::Direct
            | OutboundType::Socks5
            | OutboundType::Http
            | OutboundType::Shadowsocks
            | OutboundType::Trojan => TcpTransferType::Tcp,
            OutboundType::Wireguard => TcpTransferType::TcpOverUdp,
            OutboundType::Chain => TcpTransferType::NotApplicable,
            OutboundType::Ssh => TcpTransferType::Tcp,
        }
    }

    pub fn udp_transfer_type(&self) -> UdpTransferType {
        match self {
            OutboundType::Direct => UdpTransferType::NotApplicable,
            OutboundType::Socks5 => UdpTransferType::Udp,
            OutboundType::Http => UdpTransferType::NotApplicable,
            OutboundType::Shadowsocks => UdpTransferType::Udp,
            OutboundType::Trojan => UdpTransferType::UdpOverTcp,
            OutboundType::Wireguard => UdpTransferType::Udp,
            OutboundType::Chain => UdpTransferType::NotApplicable,
            OutboundType::Ssh => UdpTransferType::NotApplicable,
        }
    }
}

#[async_trait]
pub trait Outbound: Send + Sync {
    /// Get the globally unique id of the outbound to distinguish it
    /// even from others with the same type.
    fn id(&self) -> String;

    fn outbound_type(&self) -> OutboundType;

    /// Run with tokio::spawn.
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>>;

    /// Return whether outbound is used
    async fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> io::Result<bool>;

    /// Run with tokio::spawn.
    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        tunnel_only: bool,
    ) -> JoinHandle<io::Result<()>>;

    /// Return whether outbound is used
    async fn spawn_udp_with_outbound(
        &self,
        inbound: AddrConnector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
        tunnel_only: bool,
    ) -> io::Result<bool>;
}

fn empty_handle() -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move { Err(io_err("Invalid spawn")) })
}

#[tracing::instrument(skip_all)]
async fn established_tcp<T>(
    name: String,
    inbound: Connector,
    outbound: T,
    abort_handle: ConnAbortHandle,
) where
    T: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
    let (mut out_read, mut out_write) = tokio::io::split(outbound);
    let Connector { tx, mut rx } = inbound;
    // recv from inbound and send to outbound
    let abort_handle2 = abort_handle.clone();
    let name2 = name.clone();
    let _guard = DuplexCloseGuard::new(
        tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                let res = out_write.write_all(buf.as_ref()).await;
                if let Err(err) = res {
                    tracing::debug!("[{}] write to outbound failed: {}", name2, err);
                    abort_handle2.cancel();
                    break;
                }
                let _ = out_write.flush().await;
            }
        }),
        abort_handle.clone(),
    );
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
                        abort_handle.cancel();
                        break;
                    }
                }
                Err(err) => {
                    tracing::debug!("[{}] outbound read error: {}", name, err);
                    abort_handle.cancel();
                    break;
                }
            }
        }
    }
}

#[tracing::instrument(skip_all)]
async fn established_udp<S: UdpSocketAdapter + Sync + 'static>(
    name: String,
    inbound: AddrConnector,
    outbound: S,
    tunnel_addr: Option<NetworkAddr>,
    abort_handle: ConnAbortHandle,
) {
    // establish udp
    let outbound = Arc::new(outbound);
    let outbound2 = outbound.clone();
    let tunnel_addr2 = tunnel_addr.clone();
    let AddrConnector { tx, mut rx } = inbound;
    let abort_handle2 = abort_handle.clone();
    let name2 = name.clone();
    let _guard = UdpDropGuard(tokio::spawn(async move {
        // recv from outbound and send to inbound
        loop {
            let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
            let res = outbound.recv_from(unsafe { mut_buf(&mut buf) }).await;
            match res {
                Ok((0, _)) => {
                    break;
                }
                Ok((n, addr)) => {
                    unsafe { buf.advance_mut(n) };
                    if let Some(t_addr) = &tunnel_addr {
                        if addr.definitely_not_equal(t_addr) {
                            // drop definitely unequal packets; for domain name & socket address pair, only compare ports
                            continue;
                        }
                    }
                    if tx.send((buf.freeze(), addr)).await.is_err() {
                        tracing::debug!("[{}] write to inbound failed", name);
                        break;
                    }
                }
                Err(err) => {
                    tracing::debug!("[{}] outbound read error: {}", name, err);
                    break;
                }
            }
        }
        abort_handle.cancel();
    }));
    // recv from inbound and send to outbound
    while let Some((buf, addr)) = rx.recv().await {
        let addr = tunnel_addr2.clone().unwrap_or(addr);
        let res = outbound2.send_to(buf.as_ref(), addr).await;
        if let Err(err) = res {
            tracing::debug!("[{}] write to outbound failed: {}", name2, err);
            break;
        }
    }
    abort_handle2.cancel();
}

#[async_trait]
impl UdpSocketAdapter for AddrConnectorWrapper {
    async fn send_to(&self, data: &[u8], addr: NetworkAddr) -> Result<(), TransportError> {
        self.tx
            .send((Bytes::copy_from_slice(data), addr))
            .await
            .map_err(|_| TransportError::Internal("UDP mpsc channel full"))
    }

    async fn recv_from(&self, data: &mut [u8]) -> Result<(usize, NetworkAddr), TransportError> {
        let (buf, addr) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(TransportError::Internal("UDP mpsc closed"))?;
        if data.len() < buf.len() {
            let len = data.len();
            data[..len].copy_from_slice(&buf[..len]);
            Ok((len, addr))
        } else {
            let len = buf.len();
            data[..len].copy_from_slice(&buf[..len]);
            Ok((len, addr))
        }
    }
}

struct TcpIndicatorGuard {
    pub indicator: Arc<AtomicU8>,
    pub info: Arc<ConnContext>,
}

impl Drop for TcpIndicatorGuard {
    fn drop(&mut self) {
        self.indicator.fetch_sub(1, Ordering::Relaxed);
        if self.indicator.load(Ordering::Relaxed) == 0 {
            self.info.mark_fin();
        }
    }
}

pub(crate) struct DuplexCloseGuard {
    handle: Option<JoinHandle<()>>,
    abort_handle: ConnAbortHandle,
    err_exit: bool,
}

impl DuplexCloseGuard {
    pub fn new(handle: JoinHandle<()>, abort_handle: ConnAbortHandle) -> Self {
        Self {
            handle: Some(handle),
            abort_handle,
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
            self.abort_handle.cancel();
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
            let resp = match dns.genuine_lookup(domain_name.as_str()).await {
                Ok(Some(resp)) => resp,
                _ => return Err(io_err("dns not found")),
            };
            SocketAddr::new(resp, *port)
        }
    })
}

pub(super) async fn get_dst(dns: &Dns, dst: &NetworkAddr) -> io::Result<SocketAddr> {
    Ok(match dst {
        NetworkAddr::DomainName { domain_name, port } => {
            // translate fake ip
            SocketAddr::new(
                match dns.genuine_lookup(domain_name.as_str()).await {
                    Ok(Some(resp)) => resp,
                    _ => return Err(io_err("dns not found")),
                },
                *port,
            )
        }
        NetworkAddr::Raw(s) => *s,
    })
}

pub(super) async fn connect_timeout<F: Future<Output = io::Result<()>>>(
    future: F,
    component_str: &str,
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .unwrap_or_else(|_| {
            tracing::debug!("{} timeout after 10s", component_str);
            Err(ErrorKind::TimedOut.into())
        })
}
