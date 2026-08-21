use crate::dispatch::ProxyImpl;
use crate::network::dns::GenericDns;
use crate::proxy::{ConnHandle, NetworkAddr};
use crate::transport::anytls::AnytlsConfig;
use crate::transport::smol::SmolDnsProvider;
use crate::transport::ssh::{SshAuthentication, SshConfig};
use crate::transport::wireguard::WireguardConfig;
use boltapi::{
    ApiError, ApiErrorCode, ConnResultCode, DnsActivity, DnsCacheStatus, DnsLookupDetail,
    DnsLookupRequest, DnsOutcome, DnsOutcomeCounts, DnsResolverDetail, DnsResolverSummary,
    LinkDetail, LinkEvidence, LinkHealth, LinkKind, LinkReason, LinkReasonCode, LinkState,
    LinkSummary, Snapshot, Traffic,
};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// The complete effective configuration of one reusable link.
///
/// This deliberately does not implement `PartialEq`: WireGuard and SSH already
/// have narrower equality implementations used by their runtime caches. Reload
/// reconciliation must instead call `same_effective_config`, which compares all
/// settings that can change runtime behavior.
#[derive(Clone)]
pub(crate) enum LinkConfig {
    Wireguard(WireguardConfig),
    Ssh(SshConfig),
    Anytls(AnytlsConfig),
}

impl LinkConfig {
    pub(crate) fn from_proxy(proxy: &ProxyImpl) -> Option<Self> {
        match proxy {
            ProxyImpl::Wireguard(config) => Some(Self::Wireguard((**config).clone())),
            ProxyImpl::Ssh(config) => Some(Self::Ssh(config.clone())),
            ProxyImpl::Anytls(config) => Some(Self::Anytls(config.clone())),
            _ => None,
        }
    }

    pub(crate) fn kind(&self) -> LinkKind {
        match self {
            Self::Wireguard(_) => LinkKind::Wireguard,
            Self::Ssh(_) => LinkKind::Ssh,
            Self::Anytls(_) => LinkKind::Anytls,
        }
    }

    pub(crate) fn server(&self) -> NetworkAddr {
        match self {
            Self::Wireguard(config) => config.endpoint.clone(),
            Self::Ssh(config) => config.server.clone(),
            Self::Anytls(config) => config.server_addr.clone(),
        }
    }

    pub(crate) fn same_effective_config(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Wireguard(left), Self::Wireguard(right)) => same_wireguard(left, right),
            (Self::Ssh(left), Self::Ssh(right)) => same_ssh(left, right),
            (Self::Anytls(left), Self::Anytls(right)) => same_anytls(left, right),
            _ => false,
        }
    }
}

fn same_wireguard(left: &WireguardConfig, right: &WireguardConfig) -> bool {
    left.name == right.name
        && left.ip_addr == right.ip_addr
        && left.ip_addr6 == right.ip_addr6
        && left.private_key.to_bytes() == right.private_key.to_bytes()
        && left.public_key == right.public_key
        && left.endpoint == right.endpoint
        && left.mtu == right.mtu
        && left.preshared_key == right.preshared_key
        && left.keepalive == right.keepalive
        && same_resolver_config(&left.dns, &right.dns)
        && left.dns_preference == right.dns_preference
        && left.reserved == right.reserved
        && left.over_tcp == right.over_tcp
}

fn same_resolver_config(left: &ResolverConfig, right: &ResolverConfig) -> bool {
    left.domain == right.domain
        && left.search == right.search
        && left.name_servers.len() == right.name_servers.len()
        && left
            .name_servers
            .iter()
            .zip(&right.name_servers)
            .all(|(left, right)| same_name_server(left, right))
}

fn same_name_server(left: &NameServerConfig, right: &NameServerConfig) -> bool {
    left.ip == right.ip
        && left.trust_negative_responses == right.trust_negative_responses
        && left.connections.len() == right.connections.len()
        && left
            .connections
            .iter()
            .zip(&right.connections)
            .all(|(left, right)| same_dns_connection(left, right))
}

fn same_dns_connection(left: &ConnectionConfig, right: &ConnectionConfig) -> bool {
    left.port == right.port && left.protocol == right.protocol && left.bind_addr == right.bind_addr
}

fn same_ssh(left: &SshConfig, right: &SshConfig) -> bool {
    left.server == right.server
        && left.user == right.user
        && same_ssh_auth(&left.auth, &right.auth)
        && same_host_keys(left.host_pubkey.as_deref(), right.host_pubkey.as_deref())
}

fn same_ssh_auth(left: &SshAuthentication, right: &SshAuthentication) -> bool {
    match (left, right) {
        (SshAuthentication::Password(left), SshAuthentication::Password(right)) => left == right,
        (SshAuthentication::PrivateKey(left), SshAuthentication::PrivateKey(right)) => {
            same_private_key(left, right)
        }
        _ => false,
    }
}

fn same_private_key(left: &PrivateKeyWithHashAlg, right: &PrivateKeyWithHashAlg) -> bool {
    if left.algorithm() != right.algorithm() || left.hash_alg() != right.hash_alg() {
        return false;
    }
    match (left.to_bytes(), right.to_bytes()) {
        (Ok(left), Ok(right)) => left.as_slice() == right.as_slice(),
        // Serialization should succeed for every parsed key. Treat failure as a
        // change so reload never preserves a runtime whose credential is unclear.
        _ => false,
    }
}

fn same_host_keys(
    left: Option<&[(String, PublicKey)]>,
    right: Option<&[(String, PublicKey)]>,
) -> bool {
    fn canonical(keys: Option<&[(String, PublicKey)]>) -> Option<Vec<Vec<u8>>> {
        let mut keys = keys?
            .iter()
            .map(|(_, key)| key.to_bytes().ok())
            .collect::<Option<Vec<_>>>()?;
        // Host keys are an allow-list; order and duplicate entries do not alter
        // verification behavior. The parsed algorithm label is also omitted:
        // `SshTunnel` verifies the decoded key itself, not that source label.
        keys.sort_unstable();
        keys.dedup();
        Some(keys)
    }

    match (left, right) {
        (None, None) => true,
        (Some(_), Some(_)) => canonical(left).is_some_and(|left| canonical(right) == Some(left)),
        _ => false,
    }
}

fn same_anytls(left: &AnytlsConfig, right: &AnytlsConfig) -> bool {
    left.server_addr == right.server_addr
        && left.password == right.password
        && left.sni == right.sni
        && left.cert_verify == right.cert_verify
        && left.udp == right.udp
        && left.reuse_session == right.reuse_session
        && left.idle_session_check_interval == right.idle_session_check_interval
        && left.idle_session_timeout == right.idle_session_timeout
        && left.min_idle_session == right.min_idle_session
        && left.client_name == right.client_name
}

/// One configured route in which a named reusable link occurs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConfiguredLinkRoute {
    pub(crate) chain: String,
    pub(crate) hops: Vec<String>,
    pub(crate) interface: Option<String>,
}

/// Reconciliation input emitted alongside a newly built `Dispatching`.
#[derive(Clone)]
pub(crate) struct NamedLinkConfig {
    pub(crate) config: LinkConfig,
    pub(crate) routes: Vec<ConfiguredLinkRoute>,
}

impl NamedLinkConfig {
    pub(crate) fn new(config: LinkConfig, mut routes: Vec<ConfiguredLinkRoute>) -> Self {
        routes.sort_unstable();
        routes.dedup();
        Self { config, routes }
    }

    pub(crate) fn same_effective_config(&self, other: &Self) -> bool {
        self.config.same_effective_config(&other.config) && self.routes == other.routes
    }
}

/// The protocol-typed configuration carried by dataplane handles and managers.
///
/// `NamedLinkConfig` remains heterogeneous because the shared table reconciles
/// all link kinds. Once dispatch has selected a concrete proxy kind, this type
/// prevents a WireGuard/SSH/AnyTLS handle from receiving another kind.
#[derive(Clone)]
pub(crate) struct LinkRuntimeConfig<T> {
    pub(crate) config: T,
    routes: Vec<ConfiguredLinkRoute>,
    // This route belongs to one concrete dispatch selection, so it is runtime
    // evidence rather than part of the name-wide reconciliation identity.
    pub(crate) creation_route: Vec<LinkRouteSpec>,
}

impl<T> LinkRuntimeConfig<T> {
    pub(crate) fn new(
        config: T,
        routes: Vec<ConfiguredLinkRoute>,
        creation_route: Vec<LinkRouteSpec>,
    ) -> Self {
        Self {
            config,
            routes,
            creation_route,
        }
    }
}

/// One selected hop in traffic/configuration order. Link generations are
/// resolved only after lazy runtime creation, when their generation numbers are
/// known.
#[derive(Clone, Debug)]
pub(crate) struct LinkRouteSpec {
    pub(crate) group: Option<String>,
    pub(crate) proxy: String,
    pub(crate) proxy_type: String,
    pub(crate) link_kind: Option<LinkKind>,
}

pub(crate) trait LinkProtocolConfig: Clone {
    fn same_config_as(&self, configured: &LinkConfig) -> bool;
}

impl LinkProtocolConfig for WireguardConfig {
    fn same_config_as(&self, configured: &LinkConfig) -> bool {
        matches!(configured, LinkConfig::Wireguard(config) if same_wireguard(self, config))
    }
}

impl LinkProtocolConfig for SshConfig {
    fn same_config_as(&self, configured: &LinkConfig) -> bool {
        matches!(configured, LinkConfig::Ssh(config) if same_ssh(self, config))
    }
}

impl LinkProtocolConfig for AnytlsConfig {
    fn same_config_as(&self, configured: &LinkConfig) -> bool {
        matches!(configured, LinkConfig::Anytls(config) if same_anytls(self, config))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkAcquireError {
    NotConfigured,
    StaleConfig,
    Closing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkRouteError {
    StaleGeneration,
    InvalidRoute,
    DependencyUnavailable,
}

pub(crate) struct LinkLease {
    pub(crate) generation: Arc<LinkGeneration>,
    pub(crate) created: bool,
}

/// Typed runtime ownership remains in the protocol manager while the shared
/// generation record remains in `LinkTable`.
pub(crate) struct ManagedRuntime<T> {
    pub(crate) generation: u64,
    pub(crate) record: Arc<LinkGeneration>,
    pub(crate) runtime: Arc<T>,
}

impl<T> Clone for ManagedRuntime<T> {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            record: self.record.clone(),
            runtime: self.runtime.clone(),
        }
    }
}

pub(crate) enum InitializationDecision {
    Create,
    Wait(tokio::sync::watch::Receiver<bool>),
}

struct InitializingGeneration {
    generation: u64,
    completed: tokio::sync::watch::Sender<bool>,
}

/// Per-name initialization coordination shared by the WireGuard and SSH
/// managers. A replacement generation wakes old waiters without allowing the
/// old initializer to remove the replacement's entry when it eventually exits.
#[derive(Default)]
pub(crate) struct LinkInitializationTable {
    inner: tokio::sync::Mutex<HashMap<String, InitializingGeneration>>,
}

impl LinkInitializationTable {
    pub(crate) async fn begin(&self, name: &str, generation: u64) -> InitializationDecision {
        let mut inner = self.inner.lock().await;
        if let Some(initializing) = inner.get(name)
            && initializing.generation == generation
        {
            return InitializationDecision::Wait(initializing.completed.subscribe());
        }

        if let Some(stale) = inner.remove(name) {
            let _ = stale.completed.send(true);
        }
        let (completed, _) = tokio::sync::watch::channel(false);
        inner.insert(
            name.to_string(),
            InitializingGeneration {
                generation,
                completed,
            },
        );
        InitializationDecision::Create
    }

    pub(crate) async fn finish(&self, name: &str, generation: u64) {
        let mut inner = self.inner.lock().await;
        if inner
            .get(name)
            .is_some_and(|initializing| initializing.generation == generation)
            && let Some(initializing) = inner.remove(name)
        {
            let _ = initializing.completed.send(true);
        }
    }

    pub(crate) async fn cancel(&self, name: &str, generation: u64) {
        self.finish(name, generation).await;
    }

    pub(crate) async fn wait(mut completed: tokio::sync::watch::Receiver<bool>) {
        if !*completed.borrow() {
            let _ = completed.wait_for(|done| *done).await;
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LinkInvalidation {
    pub(crate) name: String,
    pub(crate) generation: u64,
    pub(crate) reason: LinkReasonCode,
    pub(crate) connection_result: ConnResultCode,
}

pub(crate) struct LinkTable {
    links: RwLock<HashMap<String, Arc<Link>>>,
}

struct Link {
    name: String,
    inner: Mutex<LinkInner>,
    completed_upload: AtomicU64,
    completed_download: AtomicU64,
    last_active_ms: AtomicU64,
}

struct LinkInner {
    configured: Option<NamedLinkConfig>,
    last_generation: u64,
    latest: Option<Arc<LinkGeneration>>,
}

pub(crate) struct LinkGeneration {
    name: String,
    number: u64,
    kind: LinkKind,
    server: NetworkAddr,
    created_at_ms: u64,
    state: Mutex<LinkGenerationState>,
    completed_upload: AtomicU64,
    completed_download: AtomicU64,
    last_active_ms: AtomicU64,
    active_connections: Mutex<HashMap<u64, ConnHandle>>,
}

impl Debug for LinkGeneration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinkGeneration")
            .field("name", &self.name)
            .field("number", &self.number)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct LinkGenerationState {
    state: LinkState,
    health: LinkHealth,
    ended_at_ms: Option<u64>,
    reason: Option<LinkReason>,
    connected_endpoints: Vec<SocketAddr>,
    chain: Vec<boltapi::RouteHop>,
    upstream_dependencies: Vec<Arc<LinkGeneration>>,
    evidence: LinkEvidence,
    dns: DnsActivity,
    dns_runtime: Option<LinkDnsRuntime>,
}

#[derive(Clone)]
pub(crate) enum LinkDnsRuntime {
    Wireguard(Arc<GenericDns<SmolDnsProvider>>),
}

impl LinkDnsRuntime {
    fn activity(&self) -> DnsActivity {
        match self {
            Self::Wireguard(dns) => dns.dns_activity(),
        }
    }

    fn resolver_summaries(&self, observed_at_ms: u64) -> Vec<DnsResolverSummary> {
        match self {
            Self::Wireguard(dns) => dns.resolver_snapshot_at(observed_at_ms).items,
        }
    }

    fn resolver_ids(&self) -> Vec<String> {
        match self {
            Self::Wireguard(dns) => dns.resolver_ids(),
        }
    }

    fn resolver_detail(
        &self,
        id: &str,
        observed_at_ms: u64,
    ) -> Result<DnsResolverDetail, ApiError> {
        match self {
            Self::Wireguard(dns) => dns.resolver_detail_at(id, observed_at_ms),
        }
    }

    async fn diagnostic_lookup(
        &self,
        request: DnsLookupRequest,
    ) -> Result<DnsLookupDetail, ApiError> {
        match self {
            Self::Wireguard(dns) => dns.diagnostic_lookup_detail(request).await,
        }
    }
}

impl LinkGeneration {
    fn new(name: &str, number: u64, config: &LinkConfig) -> Self {
        Self {
            name: name.to_string(),
            number,
            kind: config.kind(),
            server: config.server(),
            created_at_ms: now_ms(),
            state: Mutex::new(LinkGenerationState {
                state: LinkState::Initializing,
                health: LinkHealth::Unknown,
                ended_at_ms: None,
                reason: None,
                connected_endpoints: Vec::new(),
                chain: Vec::new(),
                upstream_dependencies: Vec::new(),
                evidence: empty_evidence(config.kind()),
                dns: empty_dns_activity(),
                dns_runtime: None,
            }),
            completed_upload: AtomicU64::new(0),
            completed_download: AtomicU64::new(0),
            last_active_ms: AtomicU64::new(0),
            active_connections: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn number(&self) -> u64 {
        self.number
    }

    pub(crate) fn link_ref(&self) -> boltapi::LinkRef {
        boltapi::LinkRef {
            name: self.name.clone(),
            kind: self.kind,
            generation: self.number,
        }
    }

    pub(crate) fn set_live_snapshot(
        &self,
        state: LinkState,
        health: LinkHealth,
        mut connected_endpoints: Vec<SocketAddr>,
        evidence: LinkEvidence,
    ) -> bool {
        if is_terminal(state) || !evidence_matches_kind(&evidence, self.kind) {
            return false;
        }
        connected_endpoints.sort_unstable();
        connected_endpoints.dedup();
        let mut current = self.state.lock().unwrap();
        if is_terminal(current.state) {
            return false;
        }
        current.state = state;
        current.health = health;
        current.connected_endpoints = connected_endpoints;
        current.evidence = evidence;
        true
    }

    pub(crate) fn set_live_evidence(
        &self,
        state: LinkState,
        health: LinkHealth,
        evidence: LinkEvidence,
    ) -> bool {
        if is_terminal(state) || !evidence_matches_kind(&evidence, self.kind) {
            return false;
        }
        let mut current = self.state.lock().unwrap();
        if is_terminal(current.state) {
            return false;
        }
        current.state = state;
        current.health = health;
        current.evidence = evidence;
        true
    }

    /// Managers call this before dropping a runtime. It intentionally updates a
    /// terminal record as well, preserving the final observable protocol state.
    pub(crate) fn retain_final_snapshot(
        &self,
        health: LinkHealth,
        mut connected_endpoints: Vec<SocketAddr>,
        evidence: LinkEvidence,
    ) {
        if !evidence_matches_kind(&evidence, self.kind) {
            return;
        }
        connected_endpoints.sort_unstable();
        connected_endpoints.dedup();
        let mut current = self.state.lock().unwrap();
        // Reload and explicit-stop paths terminalize the record before the
        // manager closes its runtime. Preserve that authoritative terminal
        // health while still copying the runtime's last endpoints/evidence.
        if !is_terminal(current.state) {
            current.health = health;
        }
        current.connected_endpoints = connected_endpoints;
        current.evidence = evidence;
        if let Some(runtime) = current.dns_runtime.take() {
            merge_dns_activity(&mut current.dns, runtime.activity());
        }
    }

    pub(crate) fn retain_final_evidence(&self, health: LinkHealth, evidence: LinkEvidence) {
        if !evidence_matches_kind(&evidence, self.kind) {
            return;
        }
        let mut current = self.state.lock().unwrap();
        if !is_terminal(current.state) {
            current.health = health;
        }
        current.evidence = evidence;
        if let Some(runtime) = current.dns_runtime.take() {
            merge_dns_activity(&mut current.dns, runtime.activity());
        }
    }

    pub(crate) fn attach_dns_runtime(&self, runtime: LinkDnsRuntime) -> bool {
        let mut current = self.state.lock().unwrap();
        if is_terminal(current.state) {
            return false;
        }
        current.dns_runtime = Some(runtime);
        true
    }

    pub(crate) fn record_dns_lookup(&self, lookup: DnsLookupDetail) {
        let mut current = self.state.lock().unwrap();
        observe_dns_lookup(&mut current.dns, lookup);
    }

    fn set_creation_route(
        &self,
        chain: Vec<boltapi::RouteHop>,
        upstream_dependencies: Vec<Arc<LinkGeneration>>,
    ) -> bool {
        let mut current = self.state.lock().unwrap();
        if is_terminal(current.state) || !current.chain.is_empty() {
            return false;
        }
        current.chain = chain;
        current.upstream_dependencies = upstream_dependencies;
        true
    }

    fn creation_route(&self) -> Option<(Vec<boltapi::RouteHop>, Vec<Arc<LinkGeneration>>)> {
        let current = self.state.lock().unwrap();
        (!current.chain.is_empty())
            .then(|| (current.chain.clone(), current.upstream_dependencies.clone()))
    }

    pub(crate) fn dependency_path(self: &Arc<Self>) -> Vec<Arc<LinkGeneration>> {
        let mut dependencies = self.state.lock().unwrap().upstream_dependencies.clone();
        dependencies.push(self.clone());
        dependencies
    }

    pub(crate) fn register_connection(&self, connection: ConnHandle) -> bool {
        // Hold lifecycle state until insertion so terminalization cannot miss a
        // connection that has observed this generation as live.
        let state = self.state.lock().unwrap();
        if is_terminal(state.state) {
            return false;
        }
        self.active_connections
            .lock()
            .unwrap()
            .insert(connection.id(), connection);
        true
    }

    pub(crate) fn complete_connection(&self, id: u64, traffic: Option<(u64, u64, u64)>) -> bool {
        let mut active = self.active_connections.lock().unwrap();
        if active.remove(&id).is_none() {
            return false;
        }
        if let Some((upload, download, last_active_ms)) = traffic {
            self.completed_upload.fetch_add(upload, Ordering::Relaxed);
            self.completed_download
                .fetch_add(download, Ordering::Relaxed);
            self.last_active_ms
                .fetch_max(last_active_ms, Ordering::Relaxed);
        }
        true
    }

    fn terminate_dependents(&self, result: ConnResultCode) {
        let connections: Vec<_> = self
            .active_connections
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for connection in connections {
            connection.finish_for_link(result);
        }
    }

    fn folded_activity(&self) -> (u64, u64, u64, u64) {
        // Capture the completed base and live membership under the same lock.
        // A concurrent completion is therefore represented by exactly one side.
        let (mut upload, mut download, mut last_active_ms, connections) = {
            let active = self.active_connections.lock().unwrap();
            (
                self.completed_upload.load(Ordering::Relaxed),
                self.completed_download.load(Ordering::Relaxed),
                self.last_active_ms.load(Ordering::Relaxed),
                active.values().cloned().collect::<Vec<_>>(),
            )
        };
        let mut active_count = 0u64;
        for connection in connections {
            let snapshot = connection.snapshot();
            if snapshot.state.state == boltapi::ConnState::Active {
                active_count = active_count.saturating_add(1);
            }
            upload = upload.saturating_add(snapshot.upload_bytes);
            download = download.saturating_add(snapshot.download_bytes);
            last_active_ms = last_active_ms.max(snapshot.last_active_ms);
        }
        (upload, download, last_active_ms, active_count)
    }
}

impl LinkTable {
    pub(crate) fn new(configured: HashMap<String, NamedLinkConfig>) -> Self {
        let links = configured
            .into_iter()
            .map(|(name, configured)| {
                let link = Link::new(name.clone(), Some(configured));
                (name, Arc::new(link))
            })
            .collect();
        Self {
            links: RwLock::new(links),
        }
    }

    /// Reconciles all names under the table write lock, then closes each latest
    /// generation under its per-link lock. Acquisition clones a link before
    /// locking it, so either it wins and is invalidated here, or it observes the
    /// new configuration and rejects a stale dispatcher's request.
    pub(crate) fn reconcile(
        &self,
        configured: HashMap<String, NamedLinkConfig>,
    ) -> Vec<LinkInvalidation> {
        let mut remaining = configured;
        let mut table = self.links.write().unwrap();
        let mut invalidations = Vec::new();

        for (name, link) in table.iter() {
            let next = remaining.remove(name);
            let mut inner = link.inner.lock().unwrap();
            let change = match (&inner.configured, &next) {
                (Some(previous), Some(next)) if previous.same_effective_config(next) => None,
                (Some(_), Some(_)) => Some((
                    LinkReasonCode::ConfigChanged,
                    ConnResultCode::LinkReconfigured,
                )),
                // Re-adding a removed name does not resurrect its terminal
                // generation; the next acquisition creates generation N+1.
                (None, Some(_)) => None,
                (Some(_), None) => {
                    Some((LinkReasonCode::ConfigRemoved, ConnResultCode::LinkRemoved))
                }
                (None, None) => None,
            };

            // Replace even an effectively equal parsed value so future runtime
            // creation uses the newest immutable configuration object.
            inner.configured = next;
            if let Some((reason, connection_result)) = change
                && let Some(generation) = invalidate_latest(&inner, reason, connection_result)
            {
                invalidations.push(LinkInvalidation {
                    name: name.clone(),
                    generation,
                    reason,
                    connection_result,
                });
            }
        }

        for (name, configured) in remaining {
            table.insert(name.clone(), Arc::new(Link::new(name, Some(configured))));
        }
        invalidations.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        invalidations
    }

    /// Acquires the latest generation only if the calling dispatcher's complete
    /// config still matches the table. This is the stale-acquisition barrier
    /// used while an old `Dispatching` drains during reload.
    pub(crate) fn acquire<T: LinkProtocolConfig>(
        &self,
        name: &str,
        requested: &LinkRuntimeConfig<T>,
    ) -> Result<LinkLease, LinkAcquireError> {
        let link = self
            .links
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or(LinkAcquireError::NotConfigured)?;
        let mut inner = link.inner.lock().unwrap();
        let configured = inner
            .configured
            .as_ref()
            .ok_or(LinkAcquireError::NotConfigured)?;
        if configured.routes != requested.routes
            || !requested.config.same_config_as(&configured.config)
        {
            return Err(LinkAcquireError::StaleConfig);
        }
        let generation_config = configured.config.clone();

        if let Some(latest) = &inner.latest {
            let state = latest.state.lock().unwrap().state;
            if state == LinkState::Closing {
                return Err(LinkAcquireError::Closing);
            }
            if !is_terminal(state) {
                return Ok(LinkLease {
                    generation: latest.clone(),
                    created: false,
                });
            }
        }

        retire_latest(&link, &mut inner);
        inner.last_generation = inner.last_generation.saturating_add(1);
        let generation = Arc::new(LinkGeneration::new(
            name,
            inner.last_generation,
            &generation_config,
        ));
        inner.latest = Some(generation.clone());
        Ok(LinkLease {
            generation,
            created: true,
        })
    }

    pub(crate) fn is_current_generation(&self, name: &str, generation: u64) -> bool {
        let Some(link) = self.links.read().unwrap().get(name).cloned() else {
            return false;
        };
        let inner = link.inner.lock().unwrap();
        if inner.configured.is_none() {
            return false;
        }
        inner.latest.as_ref().is_some_and(|latest| {
            latest.number == generation && !is_terminal(latest.state.lock().unwrap().state)
        })
    }

    /// Freezes a generation's concrete route after its runtime is usable. For a
    /// dependent link, reuse the nearest upstream link's already-frozen route,
    /// then append only the ordinary tail and this generation.
    pub(crate) fn publish_creation_route(
        &self,
        name: &str,
        generation: u64,
        specs: &[LinkRouteSpec],
    ) -> Result<Arc<LinkGeneration>, LinkRouteError> {
        let current = self
            .latest_generation(name, generation)
            .ok_or(LinkRouteError::StaleGeneration)?;
        if current.creation_route().is_some() {
            return Ok(current);
        }
        let Some(last) = specs.last() else {
            return Err(LinkRouteError::InvalidRoute);
        };
        if last.proxy != name || last.link_kind != Some(current.kind) {
            return Err(LinkRouteError::InvalidRoute);
        }

        let upstream = specs[..specs.len() - 1]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, spec)| spec.link_kind.map(|_| (index, spec)));
        let (mut chain, mut dependencies, start) = if let Some((index, spec)) = upstream {
            let upstream = self
                .latest_live_generation(&spec.proxy)
                .ok_or(LinkRouteError::DependencyUnavailable)?;
            if upstream.kind != spec.link_kind.unwrap() {
                return Err(LinkRouteError::DependencyUnavailable);
            }
            let (chain, mut dependencies) = upstream
                .creation_route()
                .ok_or(LinkRouteError::DependencyUnavailable)?;
            dependencies.push(upstream);
            (chain, dependencies, index + 1)
        } else {
            (Vec::new(), Vec::new(), 0)
        };

        for spec in &specs[start..] {
            let link = match spec.link_kind {
                None => None,
                Some(kind) if spec.proxy == name && kind == current.kind => {
                    Some(current.link_ref())
                }
                Some(_) => return Err(LinkRouteError::DependencyUnavailable),
            };
            chain.push(boltapi::RouteHop {
                group: spec.group.clone(),
                proxy: spec.proxy.clone(),
                proxy_type: spec.proxy_type.clone(),
                link,
            });
        }
        current.set_creation_route(chain, std::mem::take(&mut dependencies));
        Ok(current)
    }

    fn latest_generation(&self, name: &str, generation: u64) -> Option<Arc<LinkGeneration>> {
        let link = self.links.read().unwrap().get(name).cloned()?;
        let inner = link.inner.lock().unwrap();
        inner
            .latest
            .as_ref()
            .filter(|latest| latest.number == generation)
            .cloned()
    }

    fn latest_live_generation(&self, name: &str) -> Option<Arc<LinkGeneration>> {
        let link = self.links.read().unwrap().get(name).cloned()?;
        let inner = link.inner.lock().unwrap();
        inner.latest.as_ref().and_then(|latest| {
            (!is_terminal(latest.state.lock().unwrap().state)).then(|| latest.clone())
        })
    }

    /// First terminal callback for the current generation wins. A delayed
    /// callback carrying an older generation can never close its replacement.
    pub(crate) fn mark_terminal(
        &self,
        name: &str,
        generation: u64,
        state: LinkState,
        health: LinkHealth,
        reason: LinkReason,
        connection_result: ConnResultCode,
    ) -> bool {
        if !is_terminal(state) {
            return false;
        }
        let mut terminalized = None;
        let changed = self.with_latest(name, generation, |latest| {
            let mut current = latest.state.lock().unwrap();
            if is_terminal(current.state) {
                return false;
            }
            current.state = state;
            current.health = health;
            current.ended_at_ms = Some(now_ms());
            current.reason = Some(reason);
            if let Some(runtime) = current.dns_runtime.take() {
                merge_dns_activity(&mut current.dns, runtime.activity());
            }
            terminalized = Some(latest.clone());
            true
        });
        if let Some(latest) = terminalized {
            latest.terminate_dependents(connection_result);
        }
        changed
    }

    pub(crate) fn stop(&self, name: &str) -> Result<LinkInvalidation, ApiError> {
        let link = self
            .links
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| link_error(ApiErrorCode::LinkNotFound, "link was not found"))?;
        let inner = link.inner.lock().unwrap();
        let generation = inner.latest.as_ref().ok_or_else(|| {
            if inner.configured.is_some() {
                link_error(
                    ApiErrorCode::LinkNotInitialized,
                    "link has not been initialized",
                )
            } else {
                link_error(ApiErrorCode::LinkNotFound, "link was not found")
            }
        })?;
        let number = generation.number;
        drop(inner);
        self.stop_generation(name, number)
    }

    pub(crate) fn stop_generation(
        &self,
        name: &str,
        generation: u64,
    ) -> Result<LinkInvalidation, ApiError> {
        let stopped = self.mark_terminal(
            name,
            generation,
            LinkState::Closed,
            LinkHealth::Unknown,
            LinkReason {
                code: LinkReasonCode::UserStopped,
                detail: None,
            },
            ConnResultCode::LinkStopped,
        );
        if !stopped {
            return Err(link_error(
                ApiErrorCode::LinkNotActive,
                "link generation is not active",
            ));
        }
        Ok(LinkInvalidation {
            name: name.to_string(),
            generation,
            reason: LinkReasonCode::UserStopped,
            connection_result: ConnResultCode::LinkStopped,
        })
    }

    pub(crate) fn snapshot(&self, observed_at_ms: u64) -> Snapshot<LinkSummary> {
        let links: Vec<_> = self.links.read().unwrap().values().cloned().collect();
        let mut items: Vec<_> = links
            .iter()
            .filter_map(|link| link.summary(observed_at_ms))
            .collect();
        items.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        Snapshot {
            observed_at_ms,
            items,
        }
    }

    pub(crate) fn detail_result(
        &self,
        name: &str,
        observed_at_ms: u64,
    ) -> Result<LinkDetail, ApiError> {
        let link = self
            .links
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| link_error(ApiErrorCode::LinkNotFound, "link was not found"))?;
        let inner = link.inner.lock().unwrap();
        if inner.latest.is_none() {
            return Err(if inner.configured.is_some() {
                link_error(
                    ApiErrorCode::LinkNotInitialized,
                    "link has not been initialized",
                )
            } else {
                link_error(ApiErrorCode::LinkNotFound, "link was not found")
            });
        }
        drop(inner);
        link.detail(observed_at_ms)
            .ok_or_else(|| link_error(ApiErrorCode::Internal, "link detail is unavailable"))
    }

    pub(crate) fn dns_resolver_summaries(&self, observed_at_ms: u64) -> Vec<DnsResolverSummary> {
        let runtimes = self.live_dns_runtimes();
        runtimes
            .into_iter()
            .flat_map(|(runtime, _)| runtime.resolver_summaries(observed_at_ms))
            .collect()
    }

    pub(crate) fn dns_resolver_ids(&self) -> Vec<String> {
        let mut ids = self
            .live_dns_runtimes()
            .into_iter()
            .flat_map(|(runtime, _)| runtime.resolver_ids())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    pub(crate) fn dns_resolver_detail(
        &self,
        id: &str,
        observed_at_ms: u64,
    ) -> Option<DnsResolverDetail> {
        for (runtime, chain) in self.live_dns_runtimes() {
            if !runtime
                .resolver_ids()
                .iter()
                .any(|candidate| candidate == id)
            {
                continue;
            }
            if let Ok(mut detail) = runtime.resolver_detail(id, observed_at_ms) {
                detail.chain = chain;
                return Some(detail);
            }
        }
        None
    }

    pub(crate) async fn diagnostic_dns_lookup(
        &self,
        id: &str,
        domain: String,
    ) -> Result<DnsLookupDetail, ApiError> {
        let runtime = self
            .live_dns_runtimes()
            .into_iter()
            .find_map(|(runtime, _)| {
                runtime
                    .resolver_ids()
                    .iter()
                    .any(|candidate| candidate == id)
                    .then_some(runtime)
            })
            .ok_or_else(|| ApiError {
                code: ApiErrorCode::ResolverUnavailable,
                message: format!("resolver {id} is not available in a live link generation"),
            })?;
        runtime
            .diagnostic_lookup(DnsLookupRequest {
                domain,
                resolver_id: Some(id.to_string()),
            })
            .await
    }

    fn live_dns_runtimes(&self) -> Vec<(LinkDnsRuntime, Vec<boltapi::RouteHop>)> {
        let links = self
            .links
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        links
            .into_iter()
            .filter_map(|link| {
                let latest = link.inner.lock().unwrap().latest.clone()?;
                let state = latest.state.lock().unwrap();
                let runtime = state.dns_runtime.clone()?;
                Some((runtime, state.chain.clone()))
            })
            .collect()
    }

    fn with_latest(
        &self,
        name: &str,
        generation: u64,
        operation: impl FnOnce(&Arc<LinkGeneration>) -> bool,
    ) -> bool {
        let Some(link) = self.links.read().unwrap().get(name).cloned() else {
            return false;
        };
        let inner = link.inner.lock().unwrap();
        let Some(latest) = &inner.latest else {
            return false;
        };
        if latest.number != generation {
            return false;
        }
        operation(latest)
    }
}

impl Link {
    fn new(name: String, configured: Option<NamedLinkConfig>) -> Self {
        Self {
            name,
            inner: Mutex::new(LinkInner {
                configured,
                last_generation: 0,
                latest: None,
            }),
            completed_upload: AtomicU64::new(0),
            completed_download: AtomicU64::new(0),
            last_active_ms: AtomicU64::new(0),
        }
    }

    fn summary(&self, observed_at_ms: u64) -> Option<LinkSummary> {
        let inner = self.inner.lock().unwrap();
        let latest = inner.latest.as_ref()?;
        let state = latest.state.lock().unwrap().clone();
        Some(self.summary_from(latest, &state, observed_at_ms))
    }

    fn detail(&self, observed_at_ms: u64) -> Option<LinkDetail> {
        let inner = self.inner.lock().unwrap();
        let latest = inner.latest.as_ref()?;
        let state = latest.state.lock().unwrap().clone();
        let summary = self.summary_from(latest, &state, observed_at_ms);
        let mut dns = state.dns;
        if let Some(runtime) = state.dns_runtime {
            merge_dns_activity(&mut dns, runtime.activity());
        }
        Some(LinkDetail {
            observed_at_ms,
            summary,
            created_at_ms: latest.created_at_ms,
            ended_at_ms: state.ended_at_ms,
            duration_ms: state
                .ended_at_ms
                .unwrap_or(observed_at_ms)
                .saturating_sub(latest.created_at_ms),
            server: latest.server.clone(),
            connected_endpoints: state.connected_endpoints,
            chain: state.chain,
            evidence: state.evidence,
            dns,
        })
    }

    fn summary_from(
        &self,
        latest: &LinkGeneration,
        state: &LinkGenerationState,
        _observed_at_ms: u64,
    ) -> LinkSummary {
        let (upload, download, generation_last_active, folded_active_count) =
            latest.folded_activity();
        let last_active = generation_last_active.max(self.last_active_ms.load(Ordering::Relaxed));
        LinkSummary {
            name: self.name.clone(),
            kind: latest.kind,
            state: state.state,
            health: state.health,
            generation: latest.number,
            active_conn_count: if is_terminal(state.state) {
                0
            } else {
                folded_active_count
            },
            last_active_at_ms: (last_active != 0).then_some(last_active),
            traffic: Traffic {
                upload_bytes: upload,
                download_bytes: download,
            },
            total_traffic: Traffic {
                upload_bytes: self
                    .completed_upload
                    .load(Ordering::Relaxed)
                    .saturating_add(upload),
                download_bytes: self
                    .completed_download
                    .load(Ordering::Relaxed)
                    .saturating_add(download),
            },
            reason: state.reason.clone(),
        }
    }
}

fn retire_latest(link: &Link, inner: &mut LinkInner) {
    if let Some(previous) = inner.latest.take() {
        let (upload, download, last_active_ms, _) = previous.folded_activity();
        link.completed_upload.fetch_add(upload, Ordering::Relaxed);
        link.completed_download
            .fetch_add(download, Ordering::Relaxed);
        link.last_active_ms
            .fetch_max(last_active_ms, Ordering::Relaxed);
    }
}

fn invalidate_latest(
    inner: &LinkInner,
    reason: LinkReasonCode,
    connection_result: ConnResultCode,
) -> Option<u64> {
    let latest = inner.latest.as_ref()?;
    let mut state = latest.state.lock().unwrap();
    if is_terminal(state.state) {
        return None;
    }
    state.state = LinkState::Closed;
    state.health = LinkHealth::Unknown;
    state.ended_at_ms.get_or_insert_with(now_ms);
    state.reason = Some(LinkReason {
        code: reason,
        detail: None,
    });
    if let Some(runtime) = state.dns_runtime.take() {
        merge_dns_activity(&mut state.dns, runtime.activity());
    }
    drop(state);
    latest.terminate_dependents(connection_result);
    Some(latest.number)
}

fn is_terminal(state: LinkState) -> bool {
    matches!(state, LinkState::Closed | LinkState::Failed)
}

fn empty_evidence(kind: LinkKind) -> LinkEvidence {
    match kind {
        LinkKind::Wireguard => LinkEvidence::Wireguard {
            task_alive: false,
            last_handshake_at_ms: None,
            handshake_expires_at_ms: None,
            last_packet_at_ms: None,
        },
        LinkKind::Ssh => LinkEvidence::Ssh {
            task_alive: false,
            open_channels: 0,
            last_channel_open_at_ms: None,
            probe: None,
        },
        LinkKind::Anytls => LinkEvidence::Anytls {
            sessions: 0,
            active_streams: 0,
            idle_sessions: 0,
            peer_versions: Vec::new(),
            problematic_session: None,
        },
    }
}

fn empty_dns_activity() -> DnsActivity {
    DnsActivity {
        lookups: 0,
        outcomes: DnsOutcomeCounts {
            cache_hits: 0,
            answered: 0,
            timeout: 0,
            error: 0,
            errors: Vec::new(),
        },
        latest_lookup: None,
    }
}

fn evidence_matches_kind(evidence: &LinkEvidence, kind: LinkKind) -> bool {
    matches!(
        (evidence, kind),
        (LinkEvidence::Wireguard { .. }, LinkKind::Wireguard)
            | (LinkEvidence::Ssh { .. }, LinkKind::Ssh)
            | (LinkEvidence::Anytls { .. }, LinkKind::Anytls)
    )
}

fn observe_dns_lookup(activity: &mut DnsActivity, lookup: DnsLookupDetail) {
    activity.lookups = activity.lookups.saturating_add(1);
    if matches!(lookup.cache, DnsCacheStatus::Hit { .. }) {
        activity.outcomes.cache_hits = activity.outcomes.cache_hits.saturating_add(1);
    }
    match &lookup.result {
        DnsOutcome::Answered { .. } => {
            activity.outcomes.answered = activity.outcomes.answered.saturating_add(1);
        }
        DnsOutcome::Timeout => {
            activity.outcomes.timeout = activity.outcomes.timeout.saturating_add(1);
        }
        DnsOutcome::Error { code, .. } => {
            activity.outcomes.error = activity.outcomes.error.saturating_add(1);
            if let Some(error) = activity
                .outcomes
                .errors
                .iter_mut()
                .find(|error| error.code == *code)
            {
                error.count = error.count.saturating_add(1);
            } else {
                activity.outcomes.errors.push(boltapi::DnsErrorCount {
                    code: *code,
                    count: 1,
                });
                activity
                    .outcomes
                    .errors
                    .sort_by_key(|error| error.code as u8);
            }
        }
    }
    activity.latest_lookup = Some(lookup);
}

fn merge_dns_activity(activity: &mut DnsActivity, additional: DnsActivity) {
    activity.lookups = activity.lookups.saturating_add(additional.lookups);
    activity.outcomes.cache_hits = activity
        .outcomes
        .cache_hits
        .saturating_add(additional.outcomes.cache_hits);
    activity.outcomes.answered = activity
        .outcomes
        .answered
        .saturating_add(additional.outcomes.answered);
    activity.outcomes.timeout = activity
        .outcomes
        .timeout
        .saturating_add(additional.outcomes.timeout);
    activity.outcomes.error = activity
        .outcomes
        .error
        .saturating_add(additional.outcomes.error);
    for additional_error in additional.outcomes.errors {
        if let Some(error) = activity
            .outcomes
            .errors
            .iter_mut()
            .find(|error| error.code == additional_error.code)
        {
            error.count = error.count.saturating_add(additional_error.count);
        } else {
            activity.outcomes.errors.push(additional_error);
        }
    }
    activity
        .outcomes
        .errors
        .sort_by_key(|error| error.code as u8);
    if additional.latest_lookup.is_some() {
        activity.latest_lookup = additional.latest_lookup;
    }
}

fn link_error(code: ApiErrorCode, message: &str) -> ApiError {
    ApiError {
        code,
        message: message.to_string(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::cert::CertVerify;
    use crate::config::DnsPreference;
    use crate::dispatch::{ConnInfo, InboundInfo};
    use crate::platform::process::NetworkType;
    use crate::proxy::{ConnAbortHandle, ContextManager};
    use boltapi::ConnState;
    use std::sync::Barrier;

    fn anytls(password: &str) -> NamedLinkConfig {
        named_anytls("link", password)
    }

    fn named_anytls(name: &str, password: &str) -> NamedLinkConfig {
        NamedLinkConfig::new(
            LinkConfig::Anytls(AnytlsConfig::new(
                NetworkAddr::Domain {
                    name: format!("{name}.example"),
                    port: 443,
                },
                password,
                format!("{name}.example"),
                CertVerify::Verify,
            )),
            vec![ConfiguredLinkRoute {
                chain: "route".to_string(),
                hops: vec!["ordinary".to_string(), name.to_string()],
                interface: None,
            }],
        )
    }

    fn configs(config: NamedLinkConfig) -> HashMap<String, NamedLinkConfig> {
        HashMap::from([("link".to_string(), config)])
    }

    fn acquire(table: &LinkTable, config: &NamedLinkConfig) -> Result<LinkLease, LinkAcquireError> {
        acquire_named(table, "link", config, Vec::new())
    }

    fn acquire_named(
        table: &LinkTable,
        name: &str,
        config: &NamedLinkConfig,
        creation_route: Vec<LinkRouteSpec>,
    ) -> Result<LinkLease, LinkAcquireError> {
        let LinkConfig::Anytls(protocol) = &config.config else {
            panic!("test helper expects AnyTLS")
        };
        table.acquire(
            name,
            &LinkRuntimeConfig::new(protocol.clone(), config.routes.clone(), creation_route),
        )
    }

    fn ordinary(group: Option<&str>, name: &str, proxy_type: &str) -> LinkRouteSpec {
        LinkRouteSpec {
            group: group.map(str::to_string),
            proxy: name.to_string(),
            proxy_type: proxy_type.to_string(),
            link_kind: None,
        }
    }

    fn shared(name: &str) -> LinkRouteSpec {
        LinkRouteSpec {
            group: None,
            proxy: name.to_string(),
            proxy_type: "anytls".to_string(),
            link_kind: Some(LinkKind::Anytls),
        }
    }

    fn acquire_ready(
        table: &LinkTable,
        name: &str,
        config: &NamedLinkConfig,
        route: Vec<LinkRouteSpec>,
    ) -> Arc<LinkGeneration> {
        let generation = acquire_named(table, name, config, route.clone())
            .unwrap()
            .generation;
        table
            .publish_creation_route(name, generation.number(), &route)
            .unwrap();
        assert!(generation.set_live_evidence(
            LinkState::Ready,
            LinkHealth::Healthy,
            empty_evidence(LinkKind::Anytls),
        ));
        generation
    }

    fn begin_connection(manager: &ContextManager, port: u16) -> ConnHandle {
        let destination = NetworkAddr::from(SocketAddr::from(([192, 0, 2, 10], 443)));
        manager.begin(
            ConnInfo {
                src: SocketAddr::from(([127, 0, 0, 1], port)),
                dst: destination.clone(),
                local_ip: None,
                inbound: InboundInfo::Tun,
                resolved_dst: None,
                connection_type: NetworkType::Tcp,
                process_info: None,
            },
            destination,
            None,
            ConnAbortHandle::placeholder(),
        )
    }

    #[test]
    fn configured_but_never_used_is_omitted() {
        let table = LinkTable::new(configs(anytls("secret")));
        assert!(table.snapshot(now_ms()).items.is_empty());
        assert_eq!(
            table.detail_result("link", now_ms()).unwrap_err().code,
            ApiErrorCode::LinkNotInitialized
        );
        assert_eq!(
            table.stop("link").unwrap_err().code,
            ApiErrorCode::LinkNotInitialized
        );
        assert_eq!(
            table.detail_result("missing", now_ms()).unwrap_err().code,
            ApiErrorCode::LinkNotFound
        );
    }

    #[test]
    fn unchanged_config_preserves_generation() {
        let config = anytls("secret");
        let table = LinkTable::new(configs(config.clone()));
        let first = acquire(&table, &config).unwrap();
        assert!(first.created);

        assert!(table.reconcile(configs(config.clone())).is_empty());
        let second = acquire(&table, &config).unwrap();
        assert!(!second.created);
        assert!(Arc::ptr_eq(&first.generation, &second.generation));
    }

    #[test]
    fn changed_config_closes_old_and_rejects_stale_acquisition() {
        let old = anytls("old-secret");
        let new = anytls("new-secret");
        let table = LinkTable::new(configs(old.clone()));
        let first = acquire(&table, &old).unwrap();

        let invalidations = table.reconcile(configs(new.clone()));
        assert_eq!(invalidations.len(), 1);
        assert_eq!(invalidations[0].reason, LinkReasonCode::ConfigChanged);
        assert_eq!(
            acquire(&table, &old).err(),
            Some(LinkAcquireError::StaleConfig)
        );
        let summary = &table.snapshot(now_ms()).items[0];
        assert_eq!(summary.state, LinkState::Closed);
        assert_eq!(
            summary.reason.as_ref().map(|reason| reason.code),
            Some(LinkReasonCode::ConfigChanged)
        );

        let replacement = acquire(&table, &new).unwrap();
        assert_eq!(
            replacement.generation.number(),
            first.generation.number() + 1
        );
    }

    #[test]
    fn removed_and_readded_name_keeps_lineage() {
        let config = anytls("secret");
        let table = LinkTable::new(configs(config.clone()));
        let first = acquire(&table, &config).unwrap();

        let invalidations = table.reconcile(HashMap::new());
        assert_eq!(invalidations[0].reason, LinkReasonCode::ConfigRemoved);
        assert_eq!(
            acquire(&table, &config).err(),
            Some(LinkAcquireError::NotConfigured)
        );
        let removed = &table.snapshot(now_ms()).items[0];
        assert_eq!(
            removed.reason.as_ref().map(|reason| reason.code),
            Some(LinkReasonCode::ConfigRemoved)
        );

        assert!(table.reconcile(configs(config.clone())).is_empty());
        let replacement = acquire(&table, &config).unwrap();
        assert_eq!(
            replacement.generation.number(),
            first.generation.number() + 1
        );
    }

    #[test]
    fn removed_never_used_name_stays_omitted_and_starts_at_one_after_readd() {
        let config = anytls("secret");
        let table = LinkTable::new(configs(config.clone()));
        assert!(table.reconcile(HashMap::new()).is_empty());
        assert!(table.snapshot(now_ms()).items.is_empty());

        assert!(table.reconcile(configs(config.clone())).is_empty());
        assert_eq!(acquire(&table, &config).unwrap().generation.number(), 1);
    }

    #[test]
    fn delayed_old_generation_operation_cannot_affect_replacement() {
        let old = anytls("old-secret");
        let new = anytls("new-secret");
        let table = LinkTable::new(configs(old.clone()));
        let first = acquire(&table, &old).unwrap();
        table.reconcile(configs(new.clone()));
        let replacement = acquire(&table, &new).unwrap();

        assert!(!table.mark_terminal(
            "link",
            first.generation.number(),
            LinkState::Failed,
            LinkHealth::Unhealthy,
            LinkReason {
                code: LinkReasonCode::TaskStopped,
                detail: None,
            },
            ConnResultCode::LinkLost,
        ));
        let summary = &table.snapshot(now_ms()).items[0];
        assert_eq!(summary.generation, replacement.generation.number());
        assert_eq!(summary.state, LinkState::Initializing);
        assert!(summary.reason.is_none());
    }

    #[test]
    fn racing_old_stop_cannot_close_reload_replacement() {
        let old = anytls("old-secret");
        let new = anytls("new-secret");
        let table = Arc::new(LinkTable::new(configs(old.clone())));
        let old_generation = acquire(&table, &old).unwrap().generation.number();
        let barrier = Arc::new(Barrier::new(3));

        std::thread::scope(|scope| {
            let reload_table = table.clone();
            let reload_barrier = barrier.clone();
            let reload_config = new.clone();
            scope.spawn(move || {
                reload_barrier.wait();
                reload_table.reconcile(configs(reload_config.clone()));
                acquire(&reload_table, &reload_config).unwrap();
            });

            let stop_table = table.clone();
            let stop_barrier = barrier.clone();
            scope.spawn(move || {
                stop_barrier.wait();
                let _ = stop_table.stop_generation("link", old_generation);
            });
            barrier.wait();
        });

        let summary = &table.snapshot(now_ms()).items[0];
        assert_eq!(summary.generation, old_generation + 1);
        assert_eq!(summary.state, LinkState::Initializing);
        assert!(summary.reason.is_none());
    }

    fn wireguard(private_key_byte: u8) -> WireguardConfig {
        let private_key = x25519_dalek::StaticSecret::from([private_key_byte; 32]);
        let peer_secret = x25519_dalek::StaticSecret::from([99; 32]);
        WireguardConfig {
            name: "wireguard".to_string(),
            ip_addr: Some("10.0.0.2".parse().unwrap()),
            ip_addr6: None,
            private_key,
            public_key: x25519_dalek::PublicKey::from(&peer_secret),
            endpoint: NetworkAddr::Domain {
                name: "wg.example".to_string(),
                port: 51820,
            },
            mtu: 1420,
            preshared_key: Some([7; 32]),
            keepalive: Some(25),
            dns: ResolverConfig::default(),
            dns_preference: DnsPreference::PreferIpv4,
            reserved: Some([1, 2, 3]),
            over_tcp: false,
        }
    }

    #[test]
    fn wireguard_effective_comparison_includes_secrets_transport_and_dns() {
        let base = wireguard(1);
        assert!(
            !LinkConfig::Wireguard(base.clone())
                .same_effective_config(&LinkConfig::Wireguard(wireguard(2)))
        );

        let mut changed = base.clone();
        changed.over_tcp = true;
        assert!(
            !LinkConfig::Wireguard(base.clone())
                .same_effective_config(&LinkConfig::Wireguard(changed))
        );

        let mut changed = base.clone();
        changed
            .dns
            .name_servers
            .push(NameServerConfig::udp("1.1.1.1".parse().unwrap()));
        assert!(
            !LinkConfig::Wireguard(base).same_effective_config(&LinkConfig::Wireguard(changed))
        );
    }

    #[test]
    fn ssh_effective_comparison_includes_authentication_and_key_policy() {
        let base = SshConfig {
            server: NetworkAddr::Domain {
                name: "ssh.example".to_string(),
                port: 22,
            },
            user: "operator".to_string(),
            auth: SshAuthentication::Password("first".to_string()),
            host_pubkey: None,
        };
        let mut changed = base.clone();
        changed.auth = SshAuthentication::Password("second".to_string());
        assert!(!LinkConfig::Ssh(base.clone()).same_effective_config(&LinkConfig::Ssh(changed)));

        let mut changed = base.clone();
        changed.host_pubkey = Some(Vec::new());
        assert!(!LinkConfig::Ssh(base).same_effective_config(&LinkConfig::Ssh(changed)));
    }

    #[test]
    fn anytls_effective_comparison_includes_session_and_verification_settings() {
        let base = match anytls("secret").config {
            LinkConfig::Anytls(config) => config,
            _ => unreachable!(),
        };
        let mut changed = base.clone();
        changed.reuse_session = false;
        assert!(
            !LinkConfig::Anytls(base.clone()).same_effective_config(&LinkConfig::Anytls(changed))
        );

        let mut changed = base.clone();
        changed.cert_verify = CertVerify::SkipVerify;
        assert!(!LinkConfig::Anytls(base).same_effective_config(&LinkConfig::Anytls(changed)));
    }

    #[test]
    fn route_change_is_an_effective_change() {
        let left = anytls("secret");
        let mut right = left.clone();
        right.routes[0].interface = Some("en1".to_string());
        assert!(!left.same_effective_config(&right));
    }

    #[tokio::test]
    async fn initialization_is_coordinated_per_name_and_generation() {
        let initializing = LinkInitializationTable::default();
        assert!(matches!(
            initializing.begin("link", 1).await,
            InitializationDecision::Create
        ));
        let waiter = match initializing.begin("link", 1).await {
            InitializationDecision::Wait(waiter) => waiter,
            InitializationDecision::Create => panic!("same generation initialized twice"),
        };

        initializing.finish("link", 1).await;
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            LinkInitializationTable::wait(waiter),
        )
        .await
        .expect("waiter was not released");
    }

    #[tokio::test]
    async fn stale_initializer_cannot_finish_replacement_coordination() {
        let initializing = LinkInitializationTable::default();
        assert!(matches!(
            initializing.begin("link", 1).await,
            InitializationDecision::Create
        ));
        let old_waiter = match initializing.begin("link", 1).await {
            InitializationDecision::Wait(waiter) => waiter,
            InitializationDecision::Create => panic!("same generation initialized twice"),
        };
        assert!(matches!(
            initializing.begin("link", 2).await,
            InitializationDecision::Create
        ));

        // Starting generation 2 wakes generation 1, while a delayed generation
        // 1 completion must leave generation 2's coordination entry intact.
        LinkInitializationTable::wait(old_waiter).await;
        initializing.finish("link", 1).await;
        let replacement_waiter = match initializing.begin("link", 2).await {
            InitializationDecision::Wait(waiter) => waiter,
            InitializationDecision::Create => panic!("stale completion removed replacement"),
        };
        initializing.finish("link", 2).await;
        LinkInitializationTable::wait(replacement_waiter).await;
    }

    #[test]
    fn terminal_generation_retains_protocol_endpoint_and_dns_evidence() {
        let config = anytls("secret");
        let table = LinkTable::new(configs(config.clone()));
        let generation = acquire(&table, &config).unwrap().generation;
        generation.record_dns_lookup(DnsLookupDetail {
            purpose: boltapi::DnsLookupPurpose::LinkServer {
                link: "link".to_string(),
            },
            name: "link.example".to_string(),
            selection: boltapi::DnsSelection::Global,
            cache: DnsCacheStatus::Miss,
            attempts: Vec::new(),
            answers: Vec::new(),
            result: DnsOutcome::Error {
                code: boltapi::DnsErrorCode::Servfail,
                detail: Some("upstream failed".to_string()),
            },
            duration_ms: 12,
        });
        assert!(table.mark_terminal(
            "link",
            generation.number(),
            LinkState::Failed,
            LinkHealth::Unhealthy,
            LinkReason {
                code: LinkReasonCode::ProtocolFailed,
                detail: Some("session reader stopped".to_string()),
            },
            ConnResultCode::LinkLost,
        ));
        let endpoint = "192.0.2.10:443".parse().unwrap();
        generation.retain_final_snapshot(
            LinkHealth::Healthy,
            vec![endpoint],
            LinkEvidence::Anytls {
                sessions: 1,
                active_streams: 0,
                idle_sessions: 0,
                peer_versions: vec![1],
                problematic_session: None,
            },
        );

        let detail = table.detail_result("link", now_ms()).unwrap();
        assert_eq!(detail.summary.state, LinkState::Failed);
        // Runtime evidence cannot overwrite the terminal health/reason selected
        // by the lifecycle owner.
        assert_eq!(detail.summary.health, LinkHealth::Unhealthy);
        assert_eq!(detail.connected_endpoints, vec![endpoint]);
        assert_eq!(detail.dns.lookups, 1);
        assert_eq!(detail.dns.outcomes.error, 1);
        assert!(matches!(
            detail.evidence,
            LinkEvidence::Anytls {
                sessions: 1,
                peer_versions,
                ..
            } if peer_versions == vec![1]
        ));
    }

    #[test]
    fn dependent_generation_reuses_upstream_route_and_freezes_connection_links() {
        let upstream_config = named_anytls("upstream", "upstream-secret");
        let child_config = named_anytls("child", "child-secret");
        let table = LinkTable::new(HashMap::from([
            ("upstream".to_string(), upstream_config.clone()),
            ("child".to_string(), child_config.clone()),
        ]));

        let upstream_route = vec![
            ordinary(Some("entry-group"), "entry", "socks5"),
            shared("upstream"),
        ];
        let upstream = acquire_ready(&table, "upstream", &upstream_config, upstream_route.clone());
        let child_route = vec![
            upstream_route[0].clone(),
            upstream_route[1].clone(),
            ordinary(None, "middle", "http"),
            shared("child"),
        ];
        let child = acquire_ready(&table, "child", &child_config, child_route);

        let detail = table.detail_result("child", now_ms()).unwrap();
        assert_eq!(
            detail
                .chain
                .iter()
                .map(|hop| (
                    hop.group.as_deref(),
                    hop.proxy.as_str(),
                    hop.proxy_type.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                (Some("entry-group"), "entry", "socks5"),
                (None, "upstream", "anytls"),
                (None, "middle", "http"),
                (None, "child", "anytls"),
            ]
        );
        let route_links: Vec<_> = detail
            .chain
            .iter()
            .filter_map(|hop| hop.link.as_ref())
            .map(|link| (link.name.as_str(), link.generation))
            .collect();
        assert_eq!(
            route_links,
            vec![("upstream", upstream.number()), ("child", child.number())]
        );

        let manager = ContextManager::new(10);
        let connection = begin_connection(&manager, 10_001);
        assert!(connection.consider_link_path(child.dependency_path()));
        assert_eq!(
            connection
                .snapshot()
                .state
                .links
                .iter()
                .map(|link| (link.name.as_str(), link.generation))
                .collect::<Vec<_>>(),
            vec![("upstream", upstream.number()), ("child", child.number())]
        );
        connection.more_upload(5);
        assert!(connection.set_state(ConnState::Active));
        for summary in table.snapshot(now_ms()).items {
            assert_eq!(summary.active_conn_count, 1);
            assert_eq!(summary.traffic.upload_bytes, 5);
        }
        assert!(connection.finish(ConnResultCode::Completed, None, None));
        for summary in table.snapshot(now_ms()).items {
            assert_eq!(summary.active_conn_count, 0);
            assert_eq!(summary.traffic.upload_bytes, 5);
        }
    }

    #[test]
    fn active_traffic_is_folded_then_committed_once_and_survives_recreation() {
        let config = anytls("secret");
        let route = vec![ordinary(None, "entry", "direct"), shared("link")];
        let table = LinkTable::new(configs(config.clone()));
        let generation = acquire_ready(&table, "link", &config, route.clone());
        let manager = ContextManager::new(10);
        let connection = begin_connection(&manager, 10_001);
        assert!(connection.consider_link_path(generation.dependency_path()));

        connection.more_upload(11);
        connection.more_download(17);
        let preactive = table.snapshot(now_ms()).items.remove(0);
        assert_eq!(preactive.active_conn_count, 0);
        assert_eq!(
            (
                preactive.traffic.upload_bytes,
                preactive.traffic.download_bytes
            ),
            (0, 0)
        );

        assert!(connection.set_state(ConnState::Active));
        let active = table.snapshot(now_ms()).items.remove(0);
        assert_eq!(active.active_conn_count, 1);
        assert_eq!(
            (active.traffic.upload_bytes, active.traffic.download_bytes),
            (11, 17)
        );

        assert!(connection.finish(ConnResultCode::Completed, None, None));
        let completed = table.snapshot(now_ms()).items.remove(0);
        assert_eq!(completed.active_conn_count, 0);
        assert_eq!(
            (
                completed.traffic.upload_bytes,
                completed.traffic.download_bytes
            ),
            (11, 17)
        );
        assert!(!connection.finish(ConnResultCode::TransferError, None, None));
        let after_duplicate = table.snapshot(now_ms()).items.remove(0);
        assert_eq!(
            (
                after_duplicate.traffic.upload_bytes,
                after_duplicate.traffic.download_bytes,
            ),
            (11, 17)
        );

        table.stop("link").unwrap();
        assert_eq!(
            table.stop("link").unwrap_err().code,
            ApiErrorCode::LinkNotActive
        );
        let replacement = acquire_ready(&table, "link", &config, route);
        assert_eq!(replacement.number(), generation.number() + 1);
        let replacement_summary = table.snapshot(now_ms()).items.remove(0);
        assert_eq!(
            (
                replacement_summary.traffic.upload_bytes,
                replacement_summary.traffic.download_bytes,
            ),
            (0, 0)
        );
        assert_eq!(
            (
                replacement_summary.total_traffic.upload_bytes,
                replacement_summary.total_traffic.download_bytes,
            ),
            (11, 17)
        );
    }

    #[test]
    fn failed_before_active_does_not_contribute_link_traffic() {
        let config = anytls("secret");
        let route = vec![shared("link")];
        let table = LinkTable::new(configs(config.clone()));
        let generation = acquire_ready(&table, "link", &config, route);
        let manager = ContextManager::new(10);
        let connection = begin_connection(&manager, 10_001);
        assert!(connection.consider_link_path(generation.dependency_path()));
        connection.more_upload(23);
        connection.more_download(29);
        assert!(connection.finish(
            ConnResultCode::ConnectError,
            Some(boltapi::ConnStage::Connecting),
            None,
        ));

        let summary = table.snapshot(now_ms()).items.remove(0);
        assert_eq!(summary.active_conn_count, 0);
        assert_eq!(
            (summary.traffic.upload_bytes, summary.traffic.download_bytes),
            (0, 0)
        );
        assert_eq!(
            (
                summary.total_traffic.upload_bytes,
                summary.total_traffic.download_bytes,
            ),
            (0, 0)
        );
    }

    #[test]
    fn active_link_filter_uses_frozen_owned_dependencies() {
        let config = anytls("secret");
        let route = vec![shared("link")];
        let table = LinkTable::new(configs(config.clone()));
        let generation = acquire_ready(&table, "link", &config, route);
        let manager = ContextManager::new(10);
        let matching = begin_connection(&manager, 10_001);
        let unrelated = begin_connection(&manager, 10_002);
        let preactive = begin_connection(&manager, 10_003);

        assert!(matching.consider_link_path(generation.dependency_path()));
        assert!(matching.set_state(ConnState::Active));
        assert!(unrelated.set_state(ConnState::Active));
        assert!(preactive.consider_link_path(generation.dependency_path()));
        assert_eq!(
            manager
                .get_active_for_link("link")
                .iter()
                .map(ConnHandle::id)
                .collect::<Vec<_>>(),
            vec![matching.id()]
        );

        assert!(matching.finish(ConnResultCode::Completed, None, None));
        assert!(manager.get_active_for_link("link").is_empty());
    }

    #[derive(Clone, Copy)]
    enum StopCause {
        User,
        Reconfigure,
        Remove,
        Lost,
    }

    #[test]
    fn each_link_stop_cause_terminates_only_its_active_dependents() {
        let cases = [
            (
                StopCause::User,
                ConnResultCode::LinkStopped,
                LinkReasonCode::UserStopped,
            ),
            (
                StopCause::Reconfigure,
                ConnResultCode::LinkReconfigured,
                LinkReasonCode::ConfigChanged,
            ),
            (
                StopCause::Remove,
                ConnResultCode::LinkRemoved,
                LinkReasonCode::ConfigRemoved,
            ),
            (
                StopCause::Lost,
                ConnResultCode::LinkLost,
                LinkReasonCode::TaskStopped,
            ),
        ];

        for (index, (cause, expected_result, expected_reason)) in cases.into_iter().enumerate() {
            let config = anytls("secret");
            let table = LinkTable::new(configs(config.clone()));
            let generation = acquire_ready(&table, "link", &config, vec![shared("link")]);
            let manager = ContextManager::new(10);
            let dependent = begin_connection(&manager, 11_000 + index as u16);
            let unrelated = begin_connection(&manager, 12_000 + index as u16);
            assert!(dependent.consider_link_path(generation.dependency_path()));
            assert!(dependent.set_state(ConnState::Active));
            assert!(unrelated.set_state(ConnState::Active));

            match cause {
                StopCause::User => {
                    table.stop("link").unwrap();
                }
                StopCause::Reconfigure => {
                    table.reconcile(configs(anytls("changed-secret")));
                }
                StopCause::Remove => {
                    table.reconcile(HashMap::new());
                }
                StopCause::Lost => {
                    assert!(table.mark_terminal(
                        "link",
                        generation.number(),
                        LinkState::Failed,
                        LinkHealth::Unhealthy,
                        LinkReason {
                            code: LinkReasonCode::TaskStopped,
                            detail: None,
                        },
                        ConnResultCode::LinkLost,
                    ));
                }
            }

            assert_eq!(
                dependent.snapshot().state.termination.unwrap().code,
                expected_result
            );
            assert!(!unrelated.done());
            assert_eq!(
                table
                    .detail_result("link", now_ms())
                    .unwrap()
                    .summary
                    .reason
                    .unwrap()
                    .code,
                expected_reason
            );
        }
    }
}
