use crate::adapter::{
    AddrConnector, Connector, Outbound, OutboundType, established_tcp, established_udp, lookup,
};
use crate::common::cert::{CertVerify, make_tls_config};
use crate::common::{StreamOutboundTrait, as_io_err, io_err};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::UdpSocketAdapter;
use crate::transport::anytls::{AnytlsClient, AnytlsConfig, AnytlsStream, UDP_OVER_TCP_DOMAIN};
use async_trait::async_trait;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

#[derive(Clone)]
pub struct AnytlsOutboundHandle {
    name: String,
    iface_name: String,
    dst: NetworkAddr,
    dns: Arc<Dns>,
    config: AnytlsConfig,
    manager: Arc<AnytlsManager>,
}

impl AnytlsOutboundHandle {
    pub fn new(
        name: &str,
        iface_name: &str,
        dst: NetworkAddr,
        dns: Arc<Dns>,
        config: AnytlsConfig,
        manager: Arc<AnytlsManager>,
    ) -> Self {
        Self {
            name: name.to_string(),
            iface_name: iface_name.to_string(),
            dst,
            dns,
            config,
            manager,
        }
    }

    async fn attach_tcp(
        self,
        inbound: Connector,
        outbound: Option<Box<dyn StreamOutboundTrait>>,
        abort_handle: ConnAbortHandle,
        completion_tx: Option<tokio::sync::oneshot::Sender<bool>>,
    ) -> Result<(), TransportError> {
        let used_outbound = Arc::new(AtomicBool::new(false));
        let stream_res = self
            .open_stream_with_outbound(self.dst.clone(), outbound, used_outbound.clone())
            .await;
        send_completion(completion_tx, used_outbound.load(Ordering::Acquire));

        let mut stream = stream_res?;
        stream.wait_synack(Duration::from_secs(3)).await?;
        established_tcp(self.name, inbound, stream, abort_handle).await;
        Ok(())
    }

    async fn attach_udp(
        self,
        mut inbound: AddrConnector,
        outbound: Option<Box<dyn StreamOutboundTrait>>,
        abort_handle: ConnAbortHandle,
        completion_tx: Option<tokio::sync::oneshot::Sender<bool>>,
        tunnel_only: bool,
    ) -> Result<(), TransportError> {
        let (first_data, first_addr) = inbound.rx.recv().await.ok_or_else(|| io_err("No resp"))?;
        let target_addr = if tunnel_only {
            self.dst.clone()
        } else {
            first_addr
        };
        let udp_target = NetworkAddr::DomainName {
            domain_name: UDP_OVER_TCP_DOMAIN.to_string(),
            port: 0,
        };
        let used_outbound = Arc::new(AtomicBool::new(false));
        let stream_res = self
            .open_stream_with_outbound(udp_target, outbound, used_outbound.clone())
            .await;
        send_completion(completion_tx, used_outbound.load(Ordering::Acquire));

        let mut stream = stream_res?;
        stream.wait_synack(Duration::from_secs(3)).await?;

        let mode = if tunnel_only {
            UotMode::Connect(target_addr.clone())
        } else {
            UotMode::NonConnect
        };
        let socket = AnytlsUdpSocket::new(stream, mode);
        socket.write_request(&target_addr).await?;
        socket.send_to(first_data.as_ref(), target_addr).await?;

        established_udp(
            self.name,
            inbound,
            AnytlsUdpAdapter {
                socket: Arc::new(socket),
            },
            if tunnel_only { Some(self.dst) } else { None },
            abort_handle,
        )
        .await;
        Ok(())
    }

    async fn open_stream_with_outbound(
        &self,
        dst: NetworkAddr,
        outbound: Option<Box<dyn StreamOutboundTrait>>,
        used_outbound: Arc<AtomicBool>,
    ) -> Result<AnytlsStream, TransportError> {
        let client = self.manager.get_client(&self.config).await;
        let config = self.config.clone();
        let dns = self.dns.clone();
        let iface_name = self.iface_name.clone();

        client
            .open_stream_with(dst, move || async move {
                used_outbound.store(true, Ordering::Release);
                let outbound = match outbound {
                    Some(outbound) => outbound,
                    None => {
                        let server_addr = lookup(dns.as_ref(), &config.server_addr).await?;
                        let tcp_conn = Egress::new(&iface_name).tcp_stream(server_addr).await?;
                        Box::new(tcp_conn) as Box<dyn StreamOutboundTrait>
                    }
                };
                connect_proxy(&config, outbound).await
            })
            .await
    }
}

#[async_trait]
impl Outbound for AnytlsOutboundHandle {
    fn id(&self) -> String {
        self.name.clone()
    }

    fn outbound_type(&self) -> OutboundType {
        OutboundType::Anytls
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<Result<(), TransportError>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let abort_handle2 = abort_handle.clone();
            let res = self_clone
                .attach_tcp(inbound, None, abort_handle, None)
                .await;
            if let Err(err) = res {
                abort_handle2.cancel();
                return Err(err);
            }
            Ok(())
        })
    }

    async fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> Result<bool, TransportError> {
        if tcp_outbound.is_none() || udp_outbound.is_some() {
            tracing::error!("Invalid AnyTLS tcp outbound ancestor");
            return Err(TransportError::Internal("Invalid outbound"));
        }
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let self_clone = self.clone();
        tokio::spawn(async move {
            let abort_handle2 = abort_handle.clone();
            let res = self_clone
                .attach_tcp(inbound, tcp_outbound, abort_handle, Some(completion_tx))
                .await;
            if let Err(err) = res {
                abort_handle2.cancel();
                return Err(err);
            }
            Ok(())
        });
        completion_rx
            .await
            .map_err(|_| TransportError::Anytls("AnyTLS TCP spawn aborted"))
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        tunnel_only: bool,
    ) -> JoinHandle<Result<(), TransportError>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let abort_handle2 = abort_handle.clone();
            let res = self_clone
                .attach_udp(inbound, None, abort_handle, None, tunnel_only)
                .await;
            if let Err(err) = res {
                abort_handle2.cancel();
                return Err(err);
            }
            Ok(())
        })
    }

    async fn spawn_udp_with_outbound(
        &self,
        inbound: AddrConnector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
        tunnel_only: bool,
    ) -> Result<bool, TransportError> {
        if tcp_outbound.is_none() || udp_outbound.is_some() {
            tracing::error!("Invalid AnyTLS udp outbound ancestor");
            return Err(TransportError::Internal("Invalid outbound"));
        }
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let self_clone = self.clone();
        tokio::spawn(async move {
            let abort_handle2 = abort_handle.clone();
            let res = self_clone
                .attach_udp(
                    inbound,
                    tcp_outbound,
                    abort_handle,
                    Some(completion_tx),
                    tunnel_only,
                )
                .await;
            if let Err(err) = res {
                abort_handle2.cancel();
                return Err(err);
            }
            Ok(())
        });
        completion_rx
            .await
            .map_err(|_| TransportError::Anytls("AnyTLS UDP spawn aborted"))
    }
}

pub struct AnytlsManager {
    clients: Mutex<HashMap<AnytlsClientKey, Arc<ManagedAnytlsClient>>>,
}

impl Default for AnytlsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AnytlsManager {
    pub fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
        }
    }

    async fn get_client(&self, config: &AnytlsConfig) -> Arc<AnytlsClient> {
        let key = AnytlsClientKey::from(config);
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get(&key) {
            return client.client.clone();
        }

        let client = Arc::new(AnytlsClient::new(config));
        let managed = Arc::new(ManagedAnytlsClient {
            client: client.clone(),
            cleanup_handle: client.spawn_idle_cleanup(),
        });
        clients.insert(key, managed);
        client
    }
}

struct ManagedAnytlsClient {
    client: Arc<AnytlsClient>,
    cleanup_handle: JoinHandle<()>,
}

impl Drop for ManagedAnytlsClient {
    fn drop(&mut self) {
        self.cleanup_handle.abort();
    }
}

#[derive(Clone, Eq, PartialEq)]
struct AnytlsClientKey {
    server_addr: NetworkAddr,
    password: String,
    sni: String,
    cert_verify: CertVerify,
    reuse_session: bool,
}

impl Hash for AnytlsClientKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.server_addr.hash(state);
        self.password.hash(state);
        self.sni.hash(state);
        match &self.cert_verify {
            CertVerify::Verify => 0u8.hash(state),
            CertVerify::SkipVerify => 1u8.hash(state),
            CertVerify::Pinned(cert) => {
                2u8.hash(state);
                cert.as_ref().hash(state);
            }
        }
        self.reuse_session.hash(state);
    }
}

impl From<&AnytlsConfig> for AnytlsClientKey {
    fn from(value: &AnytlsConfig) -> Self {
        Self {
            server_addr: value.server_addr.clone(),
            password: value.password.clone(),
            sni: value.sni.clone(),
            cert_verify: value.cert_verify.clone(),
            reuse_session: value.reuse_session,
        }
    }
}

async fn connect_proxy(
    config: &AnytlsConfig,
    outbound: Box<dyn StreamOutboundTrait>,
) -> Result<TlsStream<Box<dyn StreamOutboundTrait>>, TransportError> {
    let server_name = ServerName::try_from(config.sni.as_str())
        .map_err(as_io_err)?
        .to_owned();
    let tls_conn = TlsConnector::from(make_tls_config(&config.cert_verify));
    let stream = tls_conn.connect(server_name, outbound).await?;
    Ok(stream)
}

fn send_completion(tx: Option<tokio::sync::oneshot::Sender<bool>>, value: bool) {
    if let Some(tx) = tx {
        let _ = tx.send(value);
    }
}

#[derive(Clone)]
enum UotMode {
    Connect(NetworkAddr),
    NonConnect,
}

struct AnytlsUdpSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    reader: Mutex<ReadHalf<S>>,
    writer: Mutex<WriteHalf<S>>,
    mode: UotMode,
}

impl<S> AnytlsUdpSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(stream: S, mode: UotMode) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(read_half),
            writer: Mutex::new(write_half),
            mode,
        }
    }

    async fn write_request(&self, target: &NetworkAddr) -> Result<(), TransportError> {
        let mut data = Vec::new();
        data.push(match self.mode {
            UotMode::Connect(_) => 1,
            UotMode::NonConnect => 0,
        });
        data.extend(crate::transport::anytls::encode_socks_addr(target)?);
        let mut writer = self.writer.lock().await;
        writer.write_all(&data).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn send_to(&self, data: &[u8], addr: NetworkAddr) -> Result<(), TransportError> {
        let len = u16::try_from(data.len())
            .map_err(|_| TransportError::Anytls("AnyTLS UDP payload exceeded u16::MAX"))?;
        let mut packet = Vec::new();
        match &self.mode {
            UotMode::Connect(_) => {
                packet.extend(len.to_be_bytes());
                packet.extend(data);
            }
            UotMode::NonConnect => {
                encode_uot_addr(&addr, &mut packet)?;
                packet.extend(len.to_be_bytes());
                packet.extend(data);
            }
        }

        let mut writer = self.writer.lock().await;
        writer.write_all(&packet).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, NetworkAddr), TransportError> {
        let mut reader = self.reader.lock().await;
        let addr = match &self.mode {
            UotMode::Connect(addr) => addr.clone(),
            UotMode::NonConnect => decode_uot_addr(&mut *reader).await?,
        };
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len > buffer.len() {
            return Err(TransportError::Anytls("AnyTLS UDP buffer too small"));
        }
        reader.read_exact(&mut buffer[..len]).await?;
        Ok((len, addr))
    }
}

struct AnytlsUdpAdapter<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    socket: Arc<AnytlsUdpSocket<S>>,
}

#[async_trait]
impl<S> UdpSocketAdapter for AnytlsUdpAdapter<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn send_to(&self, data: &[u8], addr: NetworkAddr) -> Result<(), TransportError> {
        self.socket.send_to(data, addr).await
    }

    async fn recv_from(&self, data: &mut [u8]) -> Result<(usize, NetworkAddr), TransportError> {
        self.socket.recv_from(data).await
    }
}

fn encode_uot_addr(addr: &NetworkAddr, data: &mut Vec<u8>) -> Result<(), TransportError> {
    match addr {
        NetworkAddr::Raw(SocketAddr::V4(v4)) => {
            data.push(0);
            data.extend(v4.ip().octets());
            data.extend(v4.port().to_be_bytes());
        }
        NetworkAddr::Raw(SocketAddr::V6(v6)) => {
            data.push(1);
            data.extend(v6.ip().octets());
            data.extend(v6.port().to_be_bytes());
        }
        NetworkAddr::DomainName { domain_name, port } => {
            let len = u8::try_from(domain_name.len())
                .map_err(|_| TransportError::Anytls("AnyTLS UDP domain name too long"))?;
            data.push(2);
            data.push(len);
            data.extend(domain_name.as_bytes());
            data.extend(port.to_be_bytes());
        }
    }
    Ok(())
}

async fn decode_uot_addr<R>(reader: &mut R) -> Result<NetworkAddr, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut one = [0u8; 1];
    reader.read_exact(&mut one).await?;
    match one[0] {
        0 => {
            let mut buf = [0u8; 6];
            reader.read_exact(&mut buf).await?;
            Ok(NetworkAddr::Raw(SocketAddr::new(
                Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]).into(),
                u16::from_be_bytes([buf[4], buf[5]]),
            )))
        }
        1 => {
            let mut buf = [0u8; 18];
            reader.read_exact(&mut buf).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);
            Ok(NetworkAddr::Raw(SocketAddr::new(
                Ipv6Addr::from(ip).into(),
                u16::from_be_bytes([buf[16], buf[17]]),
            )))
        }
        2 => {
            reader.read_exact(&mut one).await?;
            let len = one[0] as usize;
            let mut domain = vec![0u8; len];
            reader.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await?;
            Ok(NetworkAddr::DomainName {
                domain_name: String::from_utf8(domain)
                    .map_err(|_| TransportError::Anytls("AnyTLS UDP domain is not UTF-8"))?,
                port: u16::from_be_bytes(port),
            })
        }
        _ => Err(TransportError::Anytls("Invalid AnyTLS UDP address type")),
    }
}
