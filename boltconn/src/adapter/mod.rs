use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::fmt::{Display, Formatter};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

mod anytls;
mod chain;
mod direct;
mod http;
mod link;
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
pub(crate) use link::*;

use crate::common::{MAX_PKT_SIZE, StreamOutboundTrait, io_err, mut_buf, read_to_bytes_mut};
use crate::network::dns::Dns;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, ConnHandle, NetworkAddr};
use crate::transport::UdpSocketAdapter;
#[allow(unused_imports)]
pub use anytls::*;
use boltapi::{ConnResultCode, ConnStage, ConnTermination, DnsLookupPurpose};
pub use chain::*;
pub use direct::*;
pub use socks5::*;
pub use ssh::*;
use std::future::Future;
pub use tcp_adapter::*;
pub use trojan::*;
pub use udp_adapter::*;
pub use wireguard::*;

pub(crate) fn error_termination(
    code: ConnResultCode,
    stage: ConnStage,
    error: &(impl Display + ?Sized),
) -> ConnTermination {
    ConnTermination::new(
        code,
        stage,
        Some(crate::proxy::bounded_error_detail(&error.to_string())),
    )
}

pub(crate) fn handshake_error_termination(error: &(impl Display + ?Sized)) -> ConnTermination {
    error_termination(
        ConnResultCode::HandshakeError,
        ConnStage::Handshaking,
        error,
    )
}

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
    Anytls,
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
            OutboundType::Anytls => "anytls",
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
            | OutboundType::Trojan
            | OutboundType::Anytls => TcpTransferType::Tcp,
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
            OutboundType::Anytls => UdpTransferType::UdpOverTcp,
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
        conn: Option<ConnHandle>,
    ) -> JoinHandle<Result<(), TransportError>>;

    /// Return whether outbound is used
    async fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
        conn: Option<ConnHandle>,
    ) -> Result<bool, TransportError>;

    /// Run with tokio::spawn.
    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        tunnel_only: bool,
        conn: Option<ConnHandle>,
    ) -> JoinHandle<Result<(), TransportError>>;

    /// Return whether outbound is used
    async fn spawn_udp_with_outbound(
        &self,
        inbound: AddrConnector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
        tunnel_only: bool,
        conn: Option<ConnHandle>,
    ) -> Result<bool, TransportError>;
}

fn empty_handle() -> JoinHandle<Result<(), TransportError>> {
    tokio::spawn(async move { Err(TransportError::Internal("Invalid spawn")) })
}

const TCP_HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct TcpRelayActivity(Arc<TcpRelayActivityInner>);

#[derive(Debug)]
struct TcpRelayActivityInner {
    // Instant itself is not atomic, so activity is stored as a millisecond offset from one
    // monotonic epoch shared by both relay directions.
    epoch: tokio::time::Instant,
    last_activity_millis: AtomicU64,
}

impl TcpRelayActivity {
    fn new() -> Self {
        Self(Arc::new(TcpRelayActivityInner {
            epoch: tokio::time::Instant::now(),
            last_activity_millis: AtomicU64::new(0),
        }))
    }

    fn touch(&self) {
        // Multiple relay directions may report progress concurrently. fetch_max prevents an
        // older observation from replacing a newer timestamp.
        self.0
            .last_activity_millis
            .fetch_max(self.elapsed_millis(), Ordering::Relaxed);
    }

    fn idle_duration(&self) -> Duration {
        let last_activity = self.0.last_activity_millis.load(Ordering::Relaxed);
        Duration::from_millis(self.elapsed_millis().saturating_sub(last_activity))
    }

    fn elapsed_millis(&self) -> u64 {
        u64::try_from(self.0.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

async fn relay_reader_to_channel<R, F>(
    mut reader: ReadHalf<R>,
    tx: mpsc::Sender<Bytes>,
    stop_when_receiver_closes: bool,
    activity: TcpRelayActivity,
    mut on_chunk: F,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    F: FnMut(&[u8]),
{
    loop {
        let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
        // Outbound streams do not need another read after their consumer has gone away. The
        // inbound adapter disables this shortcut so a closed relay remains an explicit error.
        let read_size = tokio::select! {
            _ = tx.closed(), if stop_when_receiver_closes => return Ok(()),
            result = read_to_bytes_mut(&mut buf, &mut reader) => result?,
        };
        if read_size == 0 {
            return Ok(());
        }

        on_chunk(buf.as_ref());
        tx.send(buf.freeze())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TCP relay channel closed"))?;
        activity.touch();
    }
}

async fn relay_channel_to_writer<W, F>(
    mut rx: mpsc::Receiver<Bytes>,
    mut writer: WriteHalf<W>,
    flush_each_chunk: bool,
    activity: TcpRelayActivity,
    mut on_chunk: F,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    F: FnMut(&[u8]),
{
    while let Some(buf) = rx.recv().await {
        on_chunk(buf.as_ref());
        writer.write_all(buf.as_ref()).await?;
        activity.touch();
        if flush_each_chunk {
            // Flushing is best-effort, matching the original established TCP relay. A later
            // write still reports a meaningful connection failure if the stream is unusable.
            let _ = writer.flush().await;
        }
    }
    Ok(())
}

async fn drain_tcp_peer<F>(
    label: &str,
    completed_direction: &str,
    peer: F,
    activity: &TcpRelayActivity,
) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
{
    tokio::pin!(peer);
    // Activity before the half-close must not shorten the drain period.
    activity.touch();
    loop {
        let remaining = TCP_HALF_CLOSE_TIMEOUT.saturating_sub(activity.idle_duration());
        if remaining.is_zero() {
            tracing::debug!(
                "{} {} direction closed; peer was inactive for {:?}",
                label,
                completed_direction,
                TCP_HALF_CLOSE_TIMEOUT
            );
            return Ok(());
        }

        tokio::select! {
            result = &mut peer => return result,
            _ = tokio::time::sleep(remaining) => {}
        }
    }
}

async fn relay_tcp_bidirectional<U, D>(
    label: &str,
    upload: U,
    download: D,
    activity: TcpRelayActivity,
) -> TcpRelayOutcome
where
    U: Future<Output = io::Result<()>>,
    D: Future<Output = io::Result<()>>,
{
    tokio::pin!(upload, download);
    // An error stops both directions immediately. EOF is a TCP half-close, so the peer direction
    // may continue while it makes progress and stops after a bounded period of inactivity.
    tokio::select! {
        result = &mut upload => TcpRelayOutcome {
            first: TcpRelayDirection::Upload,
            result: match result {
                Ok(()) => drain_tcp_peer(
                    label,
                    "upload",
                    &mut download,
                    &activity,
                ).await,
                Err(error) => Err(error),
            },
        },
        result = &mut download => TcpRelayOutcome {
            first: TcpRelayDirection::Download,
            result: match result {
                Ok(()) => drain_tcp_peer(
                    label,
                    "download",
                    &mut upload,
                    &activity,
                ).await,
                Err(error) => Err(error),
            },
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpRelayDirection {
    Upload,
    Download,
}

struct TcpRelayOutcome {
    first: TcpRelayDirection,
    result: io::Result<()>,
}

#[tracing::instrument(skip_all)]
async fn established_tcp<T>(
    name: String,
    inbound: Connector,
    outbound: T,
    abort_handle: ConnAbortHandle,
    conn: Option<ConnHandle>,
) where
    T: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
    if let Some(conn) = &conn {
        conn.activate_from(&name);
    }
    let (out_read, out_write) = tokio::io::split(outbound);
    let Connector { tx, rx } = inbound;
    let activity = TcpRelayActivity::new();
    let upload = relay_channel_to_writer(rx, out_write, true, activity.clone(), |_| {});
    let download = relay_reader_to_channel(out_read, tx, true, activity.clone(), |_| {});
    let outcome = relay_tcp_bidirectional(&format!("[{name}]"), upload, download, activity).await;
    if let Err(error) = &outcome.result {
        tracing::debug!("[{}] TCP relay failed: {}", name, error);
    }
    let reason = match &outcome.result {
        Ok(()) => ConnTermination::new(
            match outcome.first {
                TcpRelayDirection::Upload => boltapi::ConnResultCode::ClientClosed,
                TcpRelayDirection::Download => boltapi::ConnResultCode::RemoteClosed,
            },
            boltapi::ConnStage::Closing,
            None,
        ),
        Err(error) => error_termination(
            boltapi::ConnResultCode::TransferError,
            boltapi::ConnStage::Transferring,
            error,
        ),
    };
    abort_handle.cancel(reason);
}

#[tracing::instrument(skip_all)]
async fn established_udp<S: UdpSocketAdapter + Sync + 'static>(
    name: String,
    inbound: AddrConnector,
    outbound: S,
    tunnel_addr: Option<NetworkAddr>,
    abort_handle: ConnAbortHandle,
    conn: Option<ConnHandle>,
) {
    if let Some(conn) = &conn {
        conn.activate_from(&name);
    }
    // establish udp
    let outbound = Arc::new(outbound);
    let outbound2 = outbound.clone();
    let tunnel_addr2 = tunnel_addr.clone();
    let AddrConnector { tx, mut rx } = inbound;
    let abort_handle2 = abort_handle.clone();
    let name2 = name.clone();
    let _guard = UdpDropGuard(tokio::spawn(async move {
        // recv from outbound and send to inbound
        let reason = loop {
            let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
            let res = outbound.recv_from(unsafe { mut_buf(&mut buf) }).await;
            match res {
                Ok((0, _)) => {
                    break ConnTermination::new(
                        boltapi::ConnResultCode::RemoteClosed,
                        boltapi::ConnStage::Closing,
                        None,
                    );
                }
                Ok((n, addr)) => {
                    unsafe { buf.advance_mut(n) };
                    if let Some(t_addr) = &tunnel_addr
                        && addr.definitely_not_equal(t_addr)
                    {
                        // drop definitely unequal packets; for domain name & socket address pair, only compare ports
                        continue;
                    }
                    if tx.send((buf.freeze(), addr)).await.is_err() {
                        tracing::debug!("[{}] write to inbound failed", name);
                        break ConnTermination::new(
                            boltapi::ConnResultCode::ClientClosed,
                            boltapi::ConnStage::Closing,
                            None,
                        );
                    }
                }
                Err(err) => {
                    tracing::debug!("[{}] outbound read error: {}", name, err);
                    break error_termination(
                        boltapi::ConnResultCode::TransferError,
                        boltapi::ConnStage::Transferring,
                        &err,
                    );
                }
            }
        };
        abort_handle.cancel(reason);
    }));
    // recv from inbound and send to outbound
    let reason = loop {
        match rx.recv().await {
            Some((buf, addr)) => {
                let addr = tunnel_addr2.clone().unwrap_or(addr);
                if let Err(err) = outbound2.send_to(buf.as_ref(), addr).await {
                    tracing::debug!("[{}] write to outbound failed: {}", name2, err);
                    break error_termination(
                        boltapi::ConnResultCode::TransferError,
                        boltapi::ConnStage::Transferring,
                        &err,
                    );
                }
            }
            None => {
                break ConnTermination::new(
                    boltapi::ConnResultCode::ClientClosed,
                    boltapi::ConnStage::Closing,
                    None,
                );
            }
        }
    };
    abort_handle2.cancel(reason);
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
}

impl Drop for TcpIndicatorGuard {
    fn drop(&mut self) {
        self.indicator.fetch_sub(1, Ordering::Relaxed);
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
            self.abort_handle.cancel(ConnTermination::new(
                boltapi::ConnResultCode::InternalError,
                boltapi::ConnStage::Closing,
                Some("UDP relay guard dropped before shutdown completed".to_string()),
            ));
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

async fn lookup(
    dns: &Dns,
    addr: &NetworkAddr,
    purpose: DnsLookupPurpose,
    conn: Option<&ConnHandle>,
) -> io::Result<SocketAddr> {
    Ok(match addr {
        NetworkAddr::Socket { address: addr } => *addr,
        NetworkAddr::Domain {
            name: domain_name,
            port,
        } => {
            let resp = match dns
                .genuine_lookup_for(domain_name.as_str(), purpose, conn)
                .await
            {
                Ok(Some(resp)) => resp,
                _ => return Err(io_err("dns not found")),
            };
            SocketAddr::new(resp, *port)
        }
    })
}

pub(super) async fn get_dst(
    dns: &Dns,
    dst: &NetworkAddr,
    purpose: DnsLookupPurpose,
) -> io::Result<SocketAddr> {
    Ok(match dst {
        NetworkAddr::Domain {
            name: domain_name,
            port,
        } => {
            // translate fake ip
            SocketAddr::new(
                match dns
                    .genuine_lookup_for(domain_name.as_str(), purpose, None)
                    .await
                {
                    Ok(Some(resp)) => resp,
                    _ => return Err(io_err("dns not found")),
                },
                *port,
            )
        }
        NetworkAddr::Socket { address: s } => *s,
    })
}

/// Resolves a reusable-link server and records caller-level DNS evidence on its
/// generation. Literal socket addresses require no lookup evidence.
pub(super) async fn get_link_dst(
    dns: &Dns,
    dst: &NetworkAddr,
    name: &str,
    generation: &LinkGeneration,
) -> Result<SocketAddr, TransportError> {
    match dst {
        NetworkAddr::Domain {
            name: domain_name,
            port,
        } => {
            let (result, evidence) = dns
                .genuine_lookup_with_evidence(
                    domain_name,
                    DnsLookupPurpose::LinkServer {
                        link: name.to_string(),
                    },
                )
                .await;
            // Store evidence before interpreting the result so NXDOMAIN,
            // timeout, and transport failures remain visible on the link.
            generation.record_dns_lookup(evidence);
            let address = result?;
            let address = address.ok_or_else(|| {
                TransportError::Dns(crate::proxy::error::DnsError::ResolveDomain(
                    domain_name.clone(),
                ))
            })?;
            Ok(SocketAddr::new(address, *port))
        }
        NetworkAddr::Socket { address } => Ok(*address),
    }
}

pub(super) async fn connect_timeout<F: Future<Output = Result<(), TransportError>>>(
    future: F,
    component_str: &str,
) -> Result<(), TransportError> {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .unwrap_or_else(|_| {
            tracing::debug!("{} timeout after 10s", component_str);
            Err(TransportError::Timeout("connect"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn established_tcp_drains_response_after_upload_half_close() {
        let (established_connector, peer_connector) = Connector::new_pair(4);
        let Connector {
            tx: peer_tx,
            rx: mut peer_rx,
        } = peer_connector;
        let (mut remote, outbound) = tokio::io::duplex(1024);
        let task = tokio::spawn(established_tcp(
            "test".to_string(),
            established_connector,
            outbound,
            ConnAbortHandle::placeholder(),
            None,
        ));

        peer_tx.send(Bytes::from_static(b"request")).await.unwrap();
        let mut request = [0; 7];
        remote.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");

        // Closing the request direction must not discard a response that is still in flight.
        drop(peer_tx);
        remote.write_all(b"response").await.unwrap();
        assert_eq!(
            peer_rx.recv().await.unwrap(),
            Bytes::from_static(b"response")
        );

        remote.shutdown().await.unwrap();
        drop(remote);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("established TCP relay did not stop")
            .expect("established TCP relay panicked");
    }

    #[tokio::test(start_paused = true)]
    async fn drain_timeout_restarts_after_activity() {
        let activity = TcpRelayActivity::new();
        let task_activity = activity.clone();
        let task = tokio::spawn(async move {
            drain_tcp_peer("test", "upload", std::future::pending(), &task_activity).await
        });
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(!task.is_finished());
        activity.touch();

        // The original deadline passes, but recent activity keeps the peer alive.
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(!task.is_finished());

        tokio::time::advance(Duration::from_secs(1)).await;
        task.await
            .expect("drain task panicked")
            .expect("drain task returned an error");
    }
}
