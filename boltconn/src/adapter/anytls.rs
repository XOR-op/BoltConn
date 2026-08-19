use crate::adapter::{
    AddrConnector, Connector, LinkRuntimeConfig, LinkTable, ManagedRuntime, Outbound, OutboundType,
    established_tcp, established_udp,
};
use crate::common::cert::make_tls_config;
use crate::common::{StreamOutboundTrait, as_io_err, io_err};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, ConnHandle, NetworkAddr};
use crate::transport::UdpSocketAdapter;
use crate::transport::anytls::{AnytlsClient, AnytlsConfig, AnytlsStream, UDP_OVER_TCP_DOMAIN};
use async_trait::async_trait;
use std::collections::HashMap;
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
    config: LinkRuntimeConfig<AnytlsConfig>,
    manager: Arc<AnytlsManager>,
}

impl AnytlsOutboundHandle {
    pub fn new(
        name: &str,
        iface_name: &str,
        dst: NetworkAddr,
        dns: Arc<Dns>,
        config: LinkRuntimeConfig<AnytlsConfig>,
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
        conn: Option<ConnHandle>,
    ) -> Result<(), TransportError> {
        let used_outbound = Arc::new(AtomicBool::new(false));
        let stream_res = self
            .open_stream_with_outbound(self.dst.clone(), outbound, used_outbound.clone())
            .await;
        send_completion(completion_tx, used_outbound.load(Ordering::Acquire));

        let mut stream = stream_res?;
        stream
            .wait_synack(Duration::from_secs(3))
            .await
            .map_err(|error| TransportError::Handshake(error.to_string()))?;
        established_tcp(self.name, inbound, stream, abort_handle, conn).await;
        Ok(())
    }

    async fn attach_udp(
        self,
        mut inbound: AddrConnector,
        outbound: Option<Box<dyn StreamOutboundTrait>>,
        abort_handle: ConnAbortHandle,
        completion_tx: Option<tokio::sync::oneshot::Sender<bool>>,
        tunnel_only: bool,
        conn: Option<ConnHandle>,
    ) -> Result<(), TransportError> {
        let (first_data, first_addr) = inbound.rx.recv().await.ok_or_else(|| io_err("No resp"))?;
        let target_addr = if tunnel_only {
            self.dst.clone()
        } else {
            first_addr
        };
        let udp_target = NetworkAddr::Domain {
            name: UDP_OVER_TCP_DOMAIN.to_string(),
            port: 0,
        };
        let used_outbound = Arc::new(AtomicBool::new(false));
        let stream_res = self
            .open_stream_with_outbound(udp_target, outbound, used_outbound.clone())
            .await;
        send_completion(completion_tx, used_outbound.load(Ordering::Acquire));

        let mut stream = stream_res?;
        stream
            .wait_synack(Duration::from_secs(3))
            .await
            .map_err(|error| TransportError::Handshake(error.to_string()))?;

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
            conn,
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
        let managed = self.manager.get_client(&self.name, &self.config).await?;
        let config = self.config.config.clone();
        let dns = self.dns.clone();
        let iface_name = self.iface_name.clone();
        let link_name = self.name.clone();
        let record = managed.record.clone();
        let generation = managed.generation;

        let result = managed
            .runtime
            .open_stream_with(dst, move || async move {
                used_outbound.store(true, Ordering::Release);
                let (outbound, connected_endpoint) = match outbound {
                    Some(outbound) => (outbound, None),
                    None => {
                        let server_addr = crate::adapter::get_link_dst(
                            dns.as_ref(),
                            &config.server_addr,
                            &link_name,
                            &record,
                        )
                        .await?;
                        let tcp_conn = Egress::new(&iface_name).tcp_stream(server_addr).await?;
                        (
                            Box::new(tcp_conn) as Box<dyn StreamOutboundTrait>,
                            Some(server_addr),
                        )
                    }
                };
                Ok((connect_proxy(&config, outbound).await?, connected_endpoint))
            })
            .await;
        match result {
            Ok(stream) => {
                self.manager
                    .refresh_generation(&self.name, generation)
                    .await;
                Ok(stream)
            }
            Err(error) => {
                self.manager
                    .finish_failed_if_unused(&self.name, generation, &error)
                    .await;
                Err(error)
            }
        }
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
        conn: Option<ConnHandle>,
    ) -> JoinHandle<Result<(), TransportError>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let abort_handle2 = abort_handle.clone();
            let res = self_clone
                .attach_tcp(inbound, None, abort_handle, None, conn)
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
        conn: Option<ConnHandle>,
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
                .attach_tcp(
                    inbound,
                    tcp_outbound,
                    abort_handle,
                    Some(completion_tx),
                    conn,
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
            .map_err(|_| TransportError::Anytls("AnyTLS TCP spawn aborted"))
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        tunnel_only: bool,
        conn: Option<ConnHandle>,
    ) -> JoinHandle<Result<(), TransportError>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let abort_handle2 = abort_handle.clone();
            let res = self_clone
                .attach_udp(inbound, None, abort_handle, None, tunnel_only, conn)
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
        conn: Option<ConnHandle>,
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
                    conn,
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
    clients: Mutex<HashMap<String, ManagedRuntime<AnytlsClient>>>,
    link_table: Arc<LinkTable>,
}

impl AnytlsManager {
    pub fn new(link_table: Arc<LinkTable>) -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            link_table,
        }
    }

    async fn get_client(
        &self,
        name: &str,
        requested: &LinkRuntimeConfig<AnytlsConfig>,
    ) -> Result<ManagedRuntime<AnytlsClient>, TransportError> {
        let config = &requested.config;
        let mut lease = self
            .link_table
            .acquire(name, requested)
            .map_err(|_| TransportError::Internal("stale AnyTLS link acquisition"))?;

        let stale = {
            let mut clients = self.clients.lock().await;
            match clients.get(name) {
                Some(client)
                    if client.generation == lease.generation.number()
                        && !client.runtime.is_closed() =>
                {
                    return Ok(client.clone());
                }
                Some(_) => clients.remove(name),
                None => None,
            }
        };
        if let Some(stale) = stale {
            let stale_generation = stale.generation;
            self.close_runtime(stale).await;
            self.link_table.mark_terminal(
                name,
                stale_generation,
                boltapi::LinkState::Failed,
                boltapi::LinkHealth::Unhealthy,
                boltapi::LinkReason {
                    code: boltapi::LinkReasonCode::TaskStopped,
                    detail: None,
                },
            );
            // A closed pool represents a completed generation. Reacquire the
            // newly created generation before installing the replacement pool.
            lease = self
                .link_table
                .acquire(name, requested)
                .map_err(|_| TransportError::Internal("stale AnyTLS link acquisition"))?;
        }

        let client = Arc::new(AnytlsClient::new(config));
        client.start_idle_cleanup();
        let managed = ManagedRuntime {
            generation: lease.generation.number(),
            record: lease.generation.clone(),
            runtime: client,
        };
        let concurrent = {
            let mut clients = self.clients.lock().await;
            if let Some(existing) = clients.get(name)
                && existing.generation == managed.generation
                && !existing.runtime.is_closed()
            {
                Some(existing.clone())
            } else {
                clients.insert(name.to_string(), managed.clone());
                None
            }
        };
        if let Some(existing) = concurrent {
            managed.runtime.close().await;
            return Ok(existing);
        }
        if !self
            .link_table
            .is_current_generation(name, lease.generation.number())
        {
            self.stop_generation(name, lease.generation.number()).await;
            return Err(TransportError::Internal(
                "AnyTLS generation changed during client creation",
            ));
        }
        self.refresh_runtime(&managed).await;
        Ok(managed)
    }

    pub(crate) async fn stop_generation(&self, name: &str, generation: u64) {
        let runtime = {
            let mut clients = self.clients.lock().await;
            if clients
                .get(name)
                .is_some_and(|runtime| runtime.generation == generation)
            {
                clients.remove(name)
            } else {
                None
            }
        };
        if let Some(runtime) = runtime {
            self.close_runtime(runtime).await;
        }
    }

    pub(crate) async fn refresh_evidence(&self) {
        let runtimes: Vec<_> = self
            .clients
            .lock()
            .await
            .iter()
            .map(|(name, runtime)| (name.clone(), runtime.clone()))
            .collect();
        for (name, runtime) in runtimes {
            let (state, health, endpoints, evidence) = runtime.runtime.link_snapshot().await;
            if matches!(
                state,
                boltapi::LinkState::Closed | boltapi::LinkState::Failed
            ) {
                {
                    let mut clients = self.clients.lock().await;
                    if clients
                        .get(&name)
                        .is_some_and(|current| current.generation == runtime.generation)
                    {
                        clients.remove(&name);
                    }
                }
                runtime
                    .record
                    .retain_final_snapshot(health, endpoints, evidence);
                self.link_table.mark_terminal(
                    &name,
                    runtime.generation,
                    boltapi::LinkState::Failed,
                    health,
                    boltapi::LinkReason {
                        code: boltapi::LinkReasonCode::TaskStopped,
                        detail: None,
                    },
                );
            } else {
                runtime
                    .record
                    .set_live_snapshot(state, health, endpoints, evidence);
            }
        }
    }

    async fn refresh_generation(&self, name: &str, generation: u64) {
        let runtime = self.clients.lock().await.get(name).cloned();
        if let Some(runtime) = runtime
            && runtime.generation == generation
        {
            self.refresh_runtime(&runtime).await;
        }
    }

    async fn refresh_runtime(&self, runtime: &ManagedRuntime<AnytlsClient>) {
        let (state, health, endpoints, evidence) = runtime.runtime.link_snapshot().await;
        runtime
            .record
            .set_live_snapshot(state, health, endpoints, evidence);
    }

    async fn finish_failed_if_unused(&self, name: &str, generation: u64, error: &TransportError) {
        let runtime = self.clients.lock().await.get(name).cloned();
        let Some(runtime) = runtime.filter(|runtime| runtime.generation == generation) else {
            return;
        };
        let (_, _, _, evidence) = runtime.runtime.link_snapshot().await;
        let unused = matches!(evidence, boltapi::LinkEvidence::Anytls { sessions: 0, .. });
        if !unused {
            self.refresh_runtime(&runtime).await;
            return;
        }

        self.stop_generation(name, generation).await;
        let code = match error {
            TransportError::Dns(_) => boltapi::LinkReasonCode::DnsFailed,
            TransportError::Handshake(_) | TransportError::Anytls(_) => {
                boltapi::LinkReasonCode::ProtocolFailed
            }
            _ => boltapi::LinkReasonCode::ConnectFailed,
        };
        self.link_table.mark_terminal(
            name,
            generation,
            boltapi::LinkState::Failed,
            boltapi::LinkHealth::Unhealthy,
            boltapi::LinkReason {
                code,
                detail: Some(crate::proxy::bounded_error_detail(&error.to_string())),
            },
        );
    }

    async fn close_runtime(&self, runtime: ManagedRuntime<AnytlsClient>) {
        let (_, health, endpoints, evidence) = runtime.runtime.link_snapshot().await;
        runtime.runtime.close().await;
        runtime
            .record
            .retain_final_snapshot(health, endpoints, evidence);
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
    let stream = tls_conn
        .connect(server_name, outbound)
        .await
        .map_err(|error| TransportError::Handshake(error.to_string()))?;
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
        NetworkAddr::Socket {
            address: SocketAddr::V4(v4),
        } => {
            data.push(0);
            data.extend(v4.ip().octets());
            data.extend(v4.port().to_be_bytes());
        }
        NetworkAddr::Socket {
            address: SocketAddr::V6(v6),
        } => {
            data.push(1);
            data.extend(v6.ip().octets());
            data.extend(v6.port().to_be_bytes());
        }
        NetworkAddr::Domain {
            name: domain_name,
            port,
        } => {
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
            Ok(NetworkAddr::from(SocketAddr::new(
                Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]).into(),
                u16::from_be_bytes([buf[4], buf[5]]),
            )))
        }
        1 => {
            let mut buf = [0u8; 18];
            reader.read_exact(&mut buf).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);
            Ok(NetworkAddr::from(SocketAddr::new(
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
            Ok(NetworkAddr::Domain {
                name: String::from_utf8(domain)
                    .map_err(|_| TransportError::Anytls("AnyTLS UDP domain is not UTF-8"))?,
                port: u16::from_be_bytes(port),
            })
        }
        _ => Err(TransportError::Anytls("Invalid AnyTLS UDP address type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{ConfiguredLinkRoute, LinkConfig, NamedLinkConfig};
    use crate::common::cert::CertVerify;

    fn configs(name: &str) -> (NamedLinkConfig, LinkRuntimeConfig<AnytlsConfig>) {
        let protocol = AnytlsConfig::new(
            NetworkAddr::Domain {
                name: "anytls.example".to_string(),
                port: 443,
            },
            "secret",
            "anytls.example",
            CertVerify::Verify,
        );
        let routes = vec![ConfiguredLinkRoute {
            chain: name.to_string(),
            hops: vec![name.to_string()],
            interface: None,
        }];
        (
            NamedLinkConfig::new(LinkConfig::Anytls(protocol.clone()), routes.clone()),
            LinkRuntimeConfig::new(protocol, routes),
        )
    }

    #[tokio::test]
    async fn pools_are_keyed_by_proxy_name() {
        let (first_named, first) = configs("first");
        let (second_named, second) = configs("second");
        let table = Arc::new(LinkTable::new(HashMap::from([
            ("first".to_string(), first_named),
            ("second".to_string(), second_named),
        ])));
        let manager = AnytlsManager::new(table);

        let first_pool = manager.get_client("first", &first).await.unwrap();
        let first_again = manager.get_client("first", &first).await.unwrap();
        let second_pool = manager.get_client("second", &second).await.unwrap();

        assert_eq!(first_pool.generation, 1);
        assert!(Arc::ptr_eq(&first_pool.runtime, &first_again.runtime));
        assert!(!Arc::ptr_eq(&first_pool.runtime, &second_pool.runtime));

        first_pool.runtime.close().await;
        second_pool.runtime.close().await;
    }

    #[tokio::test]
    async fn stop_closes_only_the_addressed_generation_and_recreation_increments() {
        let (named, config) = configs("link");
        let table = Arc::new(LinkTable::new(HashMap::from([("link".to_string(), named)])));
        let manager = AnytlsManager::new(table.clone());
        let first = manager.get_client("link", &config).await.unwrap();

        let stopped = table.stop("link").unwrap();
        manager.stop_generation("link", stopped.generation).await;
        assert!(first.runtime.is_closed());

        let replacement = manager.get_client("link", &config).await.unwrap();
        assert_eq!(replacement.generation, first.generation + 1);
        assert!(!replacement.runtime.is_closed());

        // A delayed stop for generation 1 cannot find or close generation 2.
        manager.stop_generation("link", first.generation).await;
        assert!(!replacement.runtime.is_closed());
        let current = manager.clients.lock().await.get("link").cloned().unwrap();
        assert_eq!(current.generation, replacement.generation);
        assert!(Arc::ptr_eq(&current.runtime, &replacement.runtime));

        // Avoid leaving the cleanup task alive past the test runtime.
        replacement.runtime.close().await;
    }

    #[tokio::test]
    async fn refresh_removes_dead_pool_and_retains_terminal_evidence() {
        let (named, config) = configs("link");
        let table = Arc::new(LinkTable::new(HashMap::from([("link".to_string(), named)])));
        let manager = AnytlsManager::new(table.clone());
        let first = manager.get_client("link", &config).await.unwrap();
        first.runtime.close().await;

        manager.refresh_evidence().await;
        assert!(manager.clients.lock().await.get("link").is_none());
        let detail = table.detail("link", u64::MAX).unwrap();
        assert_eq!(detail.summary.state, boltapi::LinkState::Failed);
        assert_eq!(detail.summary.health, boltapi::LinkHealth::Unhealthy);
        assert_eq!(
            detail.summary.reason.unwrap().code,
            boltapi::LinkReasonCode::TaskStopped
        );
        assert!(matches!(
            detail.evidence,
            boltapi::LinkEvidence::Anytls { sessions: 0, .. }
        ));

        let replacement = manager.get_client("link", &config).await.unwrap();
        assert_eq!(replacement.generation, first.generation + 1);
        replacement.runtime.close().await;
    }
}
