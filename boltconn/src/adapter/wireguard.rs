use crate::adapter::{
    AddrConnector, AddrConnectorWrapper, Connector, InitializationDecision, LinkDnsRuntime,
    LinkInitializationTable, LinkRuntimeConfig, LinkTable, ManagedRuntime, Outbound, OutboundType,
};

use crate::adapter;
use crate::adapter::udp_over_tcp::UdpOverTcpAdapter;
use crate::common::{AbortCanary, MAX_PKT_SIZE, StreamOutboundTrait, local_async_run};
use crate::network::dns::{Dns, GenericDns};
use crate::network::egress::Egress;
use crate::proxy::error::{DnsError, TransportError};
use crate::proxy::{ConnAbortHandle, ConnHandle, NetworkAddr};
use crate::transport::smol::{SmolDnsProvider, SmolStack, VirtualIpDevice};
use crate::transport::wireguard::{WireguardConfig, WireguardTunnel};
use crate::transport::{AdapterOrSocket, InterfaceAddress, UdpSocketAdapter};
use async_trait::async_trait;
use bytes::Bytes;
use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::net::runtime::{DnsUdpSocket, TokioTime};
use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::select;
use tokio::sync::{Mutex, Notify, RwLock, broadcast};
use tokio::task::JoinHandle;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

// Shared Wireguard Tunnel between multiple client connections
pub struct Endpoint {
    name: String,
    wg: Arc<WireguardTunnel>,
    stack: Arc<Mutex<SmolStack>>,
    stop_sender: broadcast::Sender<()>,
    notify: Arc<Notify>,
    is_active: AbortCanary,
    last_active: Arc<Mutex<Instant>>,
    last_packet_at_ms: Arc<AtomicU64>,
    connected_endpoint: SocketAddr,
}

impl Endpoint {
    pub async fn new(
        name: &str,
        outbound: AdapterOrSocket,
        config: &WireguardConfig,
        connected_endpoint: SocketAddr,
        timeout: Duration,
    ) -> Result<Arc<Self>, TransportError> {
        let notify = Arc::new(Notify::new());

        // control conn
        let (stop_send, mut stop_recv) = broadcast::channel(1);

        let (mut wg_smol_tx, wg_smol_rx) = flume::bounded(4096);
        let (smol_wg_tx, mut smol_wg_rx) = flume::unbounded();
        let tunnel = Arc::new(
            WireguardTunnel::new(outbound, config, connected_endpoint, notify.clone()).await?,
        );
        let device = VirtualIpDevice::new(config.mtu, wg_smol_rx, smol_wg_tx);
        let smol_stack = {
            let iface =
                InterfaceAddress::from_dual(config.ip_addr, config.ip_addr6).ok_or_else(|| {
                    TransportError::Internal(
                        "Unexpected behavior: no ip address configured for WireGuard; should be checked during configuration",
                    )
                })?;
            Arc::new_cyclic(|me| {
                // create dns
                let mut opts = ResolverOpts::default();
                opts.timeout = Duration::from_millis(1500);
                opts.attempts = 3;
                let resolver = {
                    Resolver::builder_with_config(
                        config.dns.clone(),
                        SmolDnsProvider::new(
                            me.clone(),
                            ConnAbortHandle::placeholder(),
                            notify.clone(),
                        ),
                    )
                    .with_options(opts)
                    .build()
                    .expect("rustls miscompiled")
                };
                let dns = Arc::new(GenericDns::new_with_resolver_config(
                    name,
                    resolver,
                    config.dns_preference,
                    &config.dns.name_servers,
                ));
                Mutex::new(SmolStack::new(
                    name,
                    iface,
                    device,
                    dns,
                    Duration::from_secs(120),
                ))
            })
        };

        let last_active = Arc::new(Mutex::new(Instant::now()));
        let last_packet_at_ms = Arc::new(AtomicU64::new(0));
        let (indicator, indi_write) = AbortCanary::pair();

        // drive wg tunnel
        let wg_out = {
            let tunnel = tunnel.clone();
            let stop_send = stop_send.clone();
            let timer = last_active.clone();
            let last_packet_at_ms = last_packet_at_ms.clone();
            let name = name.to_string();
            tokio::spawn(async move {
                let mut buf = [0u8; MAX_PKT_SIZE];
                loop {
                    if let Err(e) = tunnel.send_outgoing_packet(&mut smol_wg_rx, &mut buf).await {
                        let _ = stop_send.send(());
                        tracing::trace!(
                            "[WireGuard] Close connection #{name} for send_outgoing_packet for {e}",
                        );
                        return;
                    }
                    *timer.lock().await = Instant::now();
                    last_packet_at_ms.store(now_ms(), Ordering::Relaxed);
                }
            })
        };

        let wg_in = {
            let tunnel = tunnel.clone();
            let stop_send = stop_send.clone();
            let timer = last_active.clone();
            let last_packet_at_ms = last_packet_at_ms.clone();
            let name = name.to_string();
            tokio::spawn(async move {
                let mut buf = [0u8; MAX_PKT_SIZE];
                let mut wg_buf = [0u8; MAX_PKT_SIZE];
                loop {
                    match tunnel
                        .receive_incoming_packet(&mut wg_smol_tx, &mut buf, &mut wg_buf)
                        .await
                    {
                        Ok(true) => {
                            *timer.lock().await = Instant::now();
                            last_packet_at_ms.store(now_ms(), Ordering::Relaxed);
                        }
                        Ok(false) => {}
                        Err(e) => {
                            let _ = stop_send.send(());
                            tracing::trace!("[WireGuard] Close connection #{} for {}", name, e);
                            return;
                        }
                    }
                }
            })
        };

        let wg_tick = {
            let tunnel = tunnel.clone();
            let stop_send = stop_send.clone();
            let name = config.name.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; MAX_PKT_SIZE];
                let mut continuous_err_cnt = 0;
                loop {
                    match tunnel.tick(&mut buf).await {
                        Err(e) => {
                            continuous_err_cnt += 1;
                            if continuous_err_cnt >= 2 {
                                // Stop the current WireGuard connection
                                let _ = stop_send.send(());
                                tracing::warn!("[WireGuard] Close connection #{} for {}", name, e);
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(30)).await;
                        }
                        Ok(has_sent) => {
                            if has_sent {
                                continuous_err_cnt = 0;
                            }
                            // From boringtun, the recommended interval is 100ms.
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            })
        };

        // drive smol
        {
            let smol_stack = smol_stack.clone();
            let notifier = notify.clone();
            let smol_canary = indicator.clone();

            local_async_run(Some(format!("ST-{}", name)), async move {
                let mut immediate_next_loop = false;
                notifier.notified().await;
                while smol_canary.alive() {
                    let mut stack_handle = smol_stack.lock().await;
                    stack_handle.drive_iface();
                    immediate_next_loop |= stack_handle.poll_all_tcp().await;
                    immediate_next_loop |= stack_handle.poll_all_udp().await;
                    stack_handle.purge_invalid_tcp();
                    stack_handle.purge_timeout_udp();
                    let wait_time = if immediate_next_loop {
                        Duration::from_secs(0)
                    } else {
                        stack_handle
                            .suggested_wait_time()
                            .unwrap_or(Duration::from_secs(3))
                    };
                    drop(stack_handle);
                    if !immediate_next_loop {
                        select! {
                            _ = tokio::time::sleep(wait_time) =>{}
                            _ = notifier.notified() =>{}
                        }
                    }
                    immediate_next_loop = false;
                }
                smol_canary.abort();
            });
        }

        // timeout inactive tunnel
        {
            let stop_send = stop_send.clone();
            let indi_write = indicator.clone();
            let name = config.name.clone();
            let last_active = last_active.clone();
            tokio::spawn(async move {
                loop {
                    if last_active.lock().await.elapsed() > timeout {
                        if indi_write.alive() {
                            indi_write.abort();
                            let _ = stop_send.send(());
                            tracing::debug!(
                                "[WireGuard] Stop inactive tunnel #{} after for {}s.",
                                name,
                                timeout.as_secs()
                            );
                        }
                        break;
                    }
                    tokio::time::sleep(timeout / 2).await;
                }
            });
        }

        {
            let name = name.to_string();
            let stack = smol_stack.clone();
            tokio::spawn(async move {
                // kill all coroutine
                let _ = stop_recv.recv().await;
                indi_write.abort();
                wg_out.abort();
                wg_in.abort();
                wg_tick.abort();
                // reset smol stack to drop all channel sender,
                // so the receiver can report errors correctly
                stack.lock().await.terminate_all();
                tracing::trace!("[WireGuard] connection #{} killed", name);
            });
        }

        tracing::info!("[WireGuard] Established shared link #{}", name);

        Ok(Arc::new(Self {
            name: name.to_string(),
            wg: tunnel,
            stack: smol_stack,
            stop_sender: stop_send,
            notify,
            is_active: indicator,
            last_active,
            last_packet_at_ms,
            connected_endpoint,
        }))
    }

    pub fn clone_notify(&self) -> Arc<Notify> {
        self.notify.clone()
    }

    pub fn abort_connection(&self) {
        // Flip liveness synchronously so terminal evidence cannot race the
        // asynchronous cleanup task that drains the broadcast stop signal.
        self.is_active.abort();
        let _ = self.stop_sender.send(());
    }

    async fn link_snapshot(
        &self,
    ) -> (
        boltapi::LinkState,
        boltapi::LinkHealth,
        boltapi::LinkEvidence,
    ) {
        let task_alive = self.is_active.alive();
        let (expired, handshake_elapsed) = self.wg.stats().await;
        let observed_at_ms = now_ms();
        let last_handshake_at_ms = handshake_elapsed.map(|elapsed| {
            observed_at_ms.saturating_sub(elapsed.as_millis().try_into().unwrap_or(u64::MAX))
        });
        let evidence = boltapi::LinkEvidence::Wireguard {
            task_alive,
            last_handshake_at_ms,
            handshake_expires_at_ms: last_handshake_at_ms
                .map(|handshake| handshake.saturating_add(180_000)),
            last_packet_at_ms: match self.last_packet_at_ms.load(Ordering::Relaxed) {
                0 => None,
                timestamp => Some(timestamp),
            },
        };
        let health = if !task_alive || expired {
            boltapi::LinkHealth::Unhealthy
        } else if last_handshake_at_ms.is_none() {
            boltapi::LinkHealth::Degraded
        } else {
            boltapi::LinkHealth::Healthy
        };
        let state = if task_alive {
            boltapi::LinkState::Ready
        } else {
            boltapi::LinkState::Failed
        };
        (state, health, evidence)
    }
}

pub struct WireguardManager {
    iface: String,
    active_conn: RwLock<HashMap<String, ManagedRuntime<Endpoint>>>,
    initializing_conn: LinkInitializationTable,
    endpoint_resolver: Arc<Dns>,
    timeout: Duration,
    link_table: Arc<LinkTable>,
}

impl WireguardManager {
    pub fn new(iface: &str, dns: Arc<Dns>, timeout: Duration) -> Self {
        Self::new_with_link_table(
            iface,
            dns,
            timeout,
            Arc::new(LinkTable::new(HashMap::new())),
        )
    }

    pub(crate) fn new_with_link_table(
        iface: &str,
        dns: Arc<Dns>,
        timeout: Duration,
        link_table: Arc<LinkTable>,
    ) -> Self {
        Self {
            iface: iface.to_string(),
            active_conn: Default::default(),
            initializing_conn: Default::default(),
            endpoint_resolver: dns,
            timeout,
            link_table,
        }
    }

    pub async fn get_wg_conn(
        &self,
        name: &str,
        requested: &LinkRuntimeConfig<WireguardConfig>,
        adapter: Option<AdapterOrSocket>,
        creating_new_conn: tokio::sync::oneshot::Sender<bool>,
    ) -> Result<ManagedRuntime<Endpoint>, TransportError> {
        let config = &requested.config;
        let mut lease = self
            .link_table
            .acquire(name, requested)
            .map_err(|_| TransportError::Internal("stale WireGuard link acquisition"))?;

        let active = self.active_conn.read().await.get(name).cloned();
        if let Some(active) = active {
            if active.generation == lease.generation.number() && active.runtime.is_active.alive() {
                let _ = creating_new_conn.send(false);
                return Ok(active);
            }
            self.remove_and_finalize_dead(name, active).await;
            // A dead cached runtime terminalizes its generation. Reacquire so
            // the replacement is tagged with the next generation rather than
            // doing network setup against an already-terminal record.
            lease = self
                .link_table
                .acquire(name, requested)
                .map_err(|_| TransportError::Internal("stale WireGuard link acquisition"))?;
        }

        match self
            .initializing_conn
            .begin(name, lease.generation.number())
            .await
        {
            InitializationDecision::Wait(completed) => {
                let _ = creating_new_conn.send(false);
                LinkInitializationTable::wait(completed).await;
                if let Some(active) = self.active_conn.read().await.get(name)
                    && active.generation == lease.generation.number()
                    && active.runtime.is_active.alive()
                {
                    return Ok(active.clone());
                }
                Err(TransportError::WireGuard(
                    "get_wg_conn: endpoint creation failed",
                ))
            }
            InitializationDecision::Create => {
                let _ = creating_new_conn.send(true);
                let result = tokio::time::timeout(
                    Duration::from_secs(10),
                    self.create_endpoint(name, config, adapter, &lease.generation),
                )
                .await
                .unwrap_or_else(|_| Err(TransportError::Timeout("WireGuard initialization")));
                let endpoint = match result {
                    Ok(endpoint) => endpoint,
                    Err(error) => {
                        self.initializing_conn
                            .finish(name, lease.generation.number())
                            .await;
                        self.mark_creation_failure(name, lease.generation.number(), &error);
                        return Err(error);
                    }
                };

                if !self
                    .link_table
                    .is_current_generation(name, lease.generation.number())
                {
                    endpoint.abort_connection();
                    self.retain_endpoint_snapshot(&lease.generation, &endpoint)
                        .await;
                    self.initializing_conn
                        .finish(name, lease.generation.number())
                        .await;
                    return Err(TransportError::Internal(
                        "WireGuard generation changed during initialization",
                    ));
                }

                let managed = ManagedRuntime {
                    generation: lease.generation.number(),
                    record: lease.generation.clone(),
                    runtime: endpoint.clone(),
                };
                if self
                    .link_table
                    .publish_creation_route(
                        name,
                        lease.generation.number(),
                        &requested.creation_route,
                    )
                    .is_err()
                {
                    endpoint.abort_connection();
                    self.retain_endpoint_snapshot(&lease.generation, &endpoint)
                        .await;
                    self.initializing_conn
                        .finish(name, lease.generation.number())
                        .await;
                    self.link_table.mark_terminal(
                        name,
                        lease.generation.number(),
                        boltapi::LinkState::Failed,
                        boltapi::LinkHealth::Unhealthy,
                        boltapi::LinkReason {
                            code: boltapi::LinkReasonCode::DependencyFailed,
                            detail: Some("could not resolve WireGuard creation route".to_string()),
                        },
                        boltapi::ConnResultCode::LinkLost,
                    );
                    return Err(TransportError::Internal(
                        "WireGuard link creation route is unavailable",
                    ));
                }
                self.active_conn
                    .write()
                    .await
                    .insert(name.to_string(), managed.clone());
                // Reload may invalidate the generation between the pre-insert
                // check and map insertion. A post-insert check closes that race.
                if !self
                    .link_table
                    .is_current_generation(name, lease.generation.number())
                {
                    self.stop_generation(name, lease.generation.number()).await;
                    return Err(TransportError::Internal(
                        "WireGuard generation changed during initialization",
                    ));
                }
                // Publish the initialized runtime before waking same-generation
                // waiters so they cannot observe a successful-but-not-inserted gap.
                self.initializing_conn
                    .finish(name, lease.generation.number())
                    .await;
                Ok(managed)
            }
        }
    }

    async fn create_endpoint(
        &self,
        name: &str,
        config: &WireguardConfig,
        adapter: Option<AdapterOrSocket>,
        record: &Arc<crate::adapter::LinkGeneration>,
    ) -> Result<Arc<Endpoint>, TransportError> {
        let server_addr =
            adapter::get_link_dst(&self.endpoint_resolver, &config.endpoint, name, record).await?;
        let outbound = match adapter {
            Some(a) => a,
            None => {
                if config.over_tcp {
                    let stream = Egress::new(&self.iface).tcp_stream(server_addr).await?;
                    AdapterOrSocket::Adapter(Arc::new(UdpOverTcpAdapter::new(stream, server_addr)?))
                } else {
                    AdapterOrSocket::Socket(match server_addr {
                        SocketAddr::V4(_) => {
                            let socket = Egress::new(&self.iface).udpv4_socket().await?;
                            socket.connect(server_addr).await?;
                            socket
                        }
                        SocketAddr::V6(_) => {
                            let socket = Egress::new(&self.iface).udpv6_socket().await?;
                            socket.connect(server_addr).await?;
                            socket
                        }
                    })
                }
            }
        };
        let endpoint = Endpoint::new(name, outbound, config, server_addr, self.timeout).await?;
        let dns = endpoint.stack.lock().await.get_dns();
        record.attach_dns_runtime(LinkDnsRuntime::Wireguard(dns));
        let (_, health, evidence) = endpoint.link_snapshot().await;
        record.set_live_snapshot(
            boltapi::LinkState::Ready,
            health,
            vec![server_addr],
            evidence,
        );
        Ok(endpoint)
    }

    pub async fn stop_named_link(&self, name: &str) {
        match self.link_table.stop(name) {
            Ok(invalidation) => {
                self.stop_generation(name, invalidation.generation).await;
                tracing::info!("Stop WireGuard link #{}", name);
            }
            Err(_) => {
                tracing::warn!("Stop WireGuard link #{} failed: no such link", name);
            }
        }
    }

    pub(crate) async fn stop_generation(&self, name: &str, generation: u64) {
        self.initializing_conn.cancel(name, generation).await;
        let runtime = {
            let mut active = self.active_conn.write().await;
            if active
                .get(name)
                .is_some_and(|runtime| runtime.generation == generation)
            {
                active.remove(name)
            } else {
                None
            }
        };
        if let Some(runtime) = runtime {
            runtime.runtime.abort_connection();
            self.retain_endpoint_snapshot(&runtime.record, &runtime.runtime)
                .await;
        }
    }

    pub(crate) async fn refresh_evidence(&self) {
        let runtimes: Vec<_> = self.active_conn.read().await.values().cloned().collect();
        for runtime in runtimes {
            let (state, health, evidence) = runtime.runtime.link_snapshot().await;
            if state == boltapi::LinkState::Failed {
                let name = runtime.runtime.name.clone();
                self.remove_and_finalize_dead(&name, runtime).await;
            } else {
                runtime.record.set_live_snapshot(
                    state,
                    health,
                    vec![runtime.runtime.connected_endpoint],
                    evidence,
                );
            }
        }
    }

    async fn remove_and_finalize_dead(&self, name: &str, runtime: ManagedRuntime<Endpoint>) {
        {
            let mut active = self.active_conn.write().await;
            if active
                .get(name)
                .is_some_and(|current| current.generation == runtime.generation)
            {
                active.remove(name);
            }
        }
        self.retain_endpoint_snapshot(&runtime.record, &runtime.runtime)
            .await;
        self.link_table.mark_terminal(
            name,
            runtime.generation,
            boltapi::LinkState::Failed,
            boltapi::LinkHealth::Unhealthy,
            boltapi::LinkReason {
                code: boltapi::LinkReasonCode::TaskStopped,
                detail: None,
            },
            boltapi::ConnResultCode::LinkLost,
        );
    }

    async fn retain_endpoint_snapshot(
        &self,
        record: &Arc<crate::adapter::LinkGeneration>,
        endpoint: &Endpoint,
    ) {
        let (_, health, evidence) = endpoint.link_snapshot().await;
        record.retain_final_snapshot(health, vec![endpoint.connected_endpoint], evidence);
    }

    fn mark_creation_failure(&self, name: &str, generation: u64, error: &TransportError) {
        let code = match error {
            TransportError::Dns(_) => boltapi::LinkReasonCode::DnsFailed,
            TransportError::WireGuard(_) => boltapi::LinkReasonCode::ProtocolFailed,
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
            boltapi::ConnResultCode::LinkLost,
        );
    }
}

#[derive(Clone)]
pub struct WireguardHandle {
    name: String,
    src: SocketAddr,
    dst: NetworkAddr,
    config: LinkRuntimeConfig<WireguardConfig>,
    manager: Arc<WireguardManager>,
}

impl WireguardHandle {
    pub fn new(
        name: &str,
        src: SocketAddr,
        dst: NetworkAddr,
        config: LinkRuntimeConfig<WireguardConfig>,
        manager: Arc<WireguardManager>,
    ) -> Self {
        Self {
            name: name.to_string(),
            src,
            dst,
            config,
            manager,
        }
    }

    async fn attach_tcp(
        self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
        adapter: Option<AdapterOrSocket>,
        ret_tx: tokio::sync::oneshot::Sender<bool>,
        conn: Option<ConnHandle>,
    ) -> Result<(), TransportError> {
        let managed = self.get_endpoint(adapter, ret_tx).await?;
        if let Some(conn) = &conn {
            conn.consider_link_path(managed.record.dependency_path());
        }
        let endpoint = managed.runtime;
        let notify = endpoint.clone_notify();
        let smol_dns = endpoint.stack.lock().await.get_dns();
        let dst = match self.dst {
            NetworkAddr::Socket { address: s } => s,
            NetworkAddr::Domain {
                name: domain_name,
                port,
            } => SocketAddr::new(
                match smol_dns
                    .genuine_lookup_for(
                        domain_name.as_str(),
                        boltapi::DnsLookupPurpose::Destination,
                        conn.as_ref(),
                    )
                    .await
                {
                    Ok(Some(addr)) => addr,
                    _ => return Err(TransportError::Dns(DnsError::ResolveDomain(domain_name))),
                },
                port,
            ),
        };
        let mut stack = endpoint.stack.lock().await;
        let result = stack
            .open_tcp(self.src, dst, inbound, abort_handle, notify)
            .map_err(TransportError::from);
        drop(stack);
        if result.is_ok()
            && let Some(conn) = conn
        {
            conn.activate_from(&self.name);
        }
        result
    }

    async fn get_endpoint(
        &self,
        adapter: Option<AdapterOrSocket>,
        ret_tx: tokio::sync::oneshot::Sender<bool>,
    ) -> Result<ManagedRuntime<Endpoint>, TransportError> {
        self.manager
            .get_wg_conn(&self.name, &self.config, adapter, ret_tx)
            .await
    }

    async fn attach_udp(
        self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        adapter: Option<AdapterOrSocket>,
        ret_tx: tokio::sync::oneshot::Sender<bool>,
        conn: Option<ConnHandle>,
    ) -> Result<(), TransportError> {
        let managed = self.get_endpoint(adapter, ret_tx).await?;
        if let Some(conn) = &conn {
            conn.consider_link_path(managed.record.dependency_path());
        }
        let endpoint = managed.runtime;
        let notify = endpoint.clone_notify();
        let mut stack = endpoint.stack.lock().await;
        let result = stack
            .open_udp_tracked(self.src, inbound, abort_handle, notify, conn.clone())
            .map_err(TransportError::from);
        drop(stack);
        if result.is_ok()
            && let Some(conn) = conn
        {
            conn.activate_from(&self.name);
        }
        result
    }
}

#[async_trait]
impl Outbound for WireguardHandle {
    fn id(&self) -> String {
        self.name.clone()
    }

    fn outbound_type(&self) -> OutboundType {
        OutboundType::Wireguard
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
        conn: Option<ConnHandle>,
    ) -> JoinHandle<Result<(), TransportError>> {
        let (tx, _) = tokio::sync::oneshot::channel();
        let connect = self
            .clone()
            .attach_tcp(inbound, abort_handle, None, tx, conn);
        tokio::spawn(connect)
    }

    async fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
        conn: Option<ConnHandle>,
    ) -> Result<bool, TransportError> {
        if tcp_outbound.is_some() || udp_outbound.is_none() {
            tracing::error!("Invalid Wireguard UDP outbound ancestor");
            return Err(TransportError::Internal("Invalid outbound"));
        }
        let udp_outbound = udp_outbound.unwrap();
        let (ret_tx, ret_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(self.clone().attach_tcp(
            inbound,
            abort_handle,
            Some(AdapterOrSocket::Adapter(Arc::from(udp_outbound))),
            ret_tx,
            conn,
        ));
        ret_rx
            .await
            .map_err(|_| TransportError::Internal("Return rx closed"))
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
        conn: Option<ConnHandle>,
    ) -> JoinHandle<Result<(), TransportError>> {
        let (ret_tx, _) = tokio::sync::oneshot::channel();
        let connect = self
            .clone()
            .attach_udp(inbound, abort_handle, None, ret_tx, conn);
        tokio::spawn(connect)
    }

    async fn spawn_udp_with_outbound(
        &self,
        inbound: AddrConnector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
        conn: Option<ConnHandle>,
    ) -> Result<bool, TransportError> {
        if tcp_outbound.is_some() || udp_outbound.is_none() {
            tracing::error!("Invalid Wireguard UDP outbound ancestor");
            return Err(TransportError::Internal("Invalid outbound"));
        }
        let udp_outbound = udp_outbound.unwrap();
        let (ret_tx, ret_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(self.clone().attach_udp(
            inbound,
            abort_handle,
            Some(AdapterOrSocket::Adapter(Arc::from(udp_outbound))),
            ret_tx,
            conn,
        ));
        ret_rx
            .await
            .map_err(|_| TransportError::Internal("Return rx closed"))
    }
}

impl DnsUdpSocket for AddrConnectorWrapper {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        data: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        // By design, only one of AddrConnectorWrapper::rx should be used. So a blocking lock is ok.
        let mut guard = match self.rx.try_lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!("Lock should not fail");
                return Poll::Pending;
            }
        };
        match ready!(guard.poll_recv(cx)) {
            None => Poll::Ready(Err(ErrorKind::ConnectionAborted.into())),
            Some((buf, addr)) => {
                let len = if data.len() < buf.len() {
                    let len = data.len();
                    data[..len].copy_from_slice(&buf[..len]);
                    len
                } else {
                    let len = buf.len();
                    data[..len].copy_from_slice(&buf[..len]);
                    len
                };
                let addr = match addr {
                    NetworkAddr::Socket { address: s } => s,
                    NetworkAddr::Domain { name: _, port } => {
                        tracing::warn!("AddrConnector: should be unreachable");
                        SocketAddr::new(IpAddr::from([0, 0, 0, 0]), port)
                    }
                };
                Poll::Ready(Ok((len, addr)))
            }
        }
    }

    fn poll_send_to(
        &self,
        _cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let len = buf.len();
        match self.tx.try_send((
            Bytes::copy_from_slice(buf),
            NetworkAddr::Socket { address: target },
        )) {
            Ok(_) => Poll::Ready(Ok(len)),
            Err(_) => Poll::Pending,
        }
    }
}
