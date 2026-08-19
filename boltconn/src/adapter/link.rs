use crate::dispatch::ProxyImpl;
use crate::proxy::NetworkAddr;
use crate::transport::anytls::AnytlsConfig;
use crate::transport::ssh::{SshAuthentication, SshConfig};
use crate::transport::wireguard::WireguardConfig;
use boltapi::{
    ApiError, ApiErrorCode, ConnResultCode, DnsActivity, DnsOutcomeCounts, LinkDetail,
    LinkEvidence, LinkHealth, LinkKind, LinkReason, LinkReasonCode, LinkState, LinkSummary,
    Snapshot, Traffic,
};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use std::collections::HashMap;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkAcquireError {
    NotConfigured,
    StaleConfig,
    Closing,
}

pub(crate) struct LinkLease {
    pub(crate) generation: Arc<LinkGeneration>,
    pub(crate) created: bool,
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
    number: u64,
    kind: LinkKind,
    server: NetworkAddr,
    created_at_ms: u64,
    state: Mutex<LinkGenerationState>,
    completed_upload: AtomicU64,
    completed_download: AtomicU64,
    active_conn_count: AtomicU64,
    last_active_ms: AtomicU64,
}

#[derive(Clone)]
struct LinkGenerationState {
    state: LinkState,
    health: LinkHealth,
    ended_at_ms: Option<u64>,
    reason: Option<LinkReason>,
    connected_endpoints: Vec<std::net::SocketAddr>,
    chain: Vec<boltapi::RouteHop>,
    evidence: LinkEvidence,
    dns: DnsActivity,
}

impl LinkGeneration {
    fn new(number: u64, config: &LinkConfig) -> Self {
        Self {
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
                evidence: empty_evidence(config.kind()),
                dns: empty_dns_activity(),
            }),
            completed_upload: AtomicU64::new(0),
            completed_download: AtomicU64::new(0),
            active_conn_count: AtomicU64::new(0),
            last_active_ms: AtomicU64::new(0),
        }
    }

    pub(crate) fn number(&self) -> u64 {
        self.number
    }

    pub(crate) fn kind(&self) -> LinkKind {
        self.kind
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
                && let Some(generation) = invalidate_latest(&inner, reason)
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
    pub(crate) fn acquire(
        &self,
        name: &str,
        requested: &NamedLinkConfig,
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
        if !configured.same_effective_config(requested) {
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
            inner.last_generation,
            &generation_config,
        ));
        inner.latest = Some(generation.clone());
        Ok(LinkLease {
            generation,
            created: true,
        })
    }

    /// Applies a non-terminal transition only to the currently owned generation.
    pub(crate) fn transition(
        &self,
        name: &str,
        generation: u64,
        state: LinkState,
        health: LinkHealth,
    ) -> bool {
        if is_terminal(state) {
            return false;
        }
        self.with_latest(name, generation, |latest| {
            let mut current = latest.state.lock().unwrap();
            if is_terminal(current.state) {
                return false;
            }
            current.state = state;
            current.health = health;
            true
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
    ) -> bool {
        if !is_terminal(state) {
            return false;
        }
        self.with_latest(name, generation, |latest| {
            let mut current = latest.state.lock().unwrap();
            if is_terminal(current.state) {
                return false;
            }
            current.state = state;
            current.health = health;
            current.ended_at_ms = Some(now_ms());
            current.reason = Some(reason);
            true
        })
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
            link_error(
                ApiErrorCode::LinkNotInitialized,
                "link has not been initialized",
            )
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

    pub(crate) fn detail(&self, name: &str, observed_at_ms: u64) -> Option<LinkDetail> {
        self.links
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .and_then(|link| link.detail(observed_at_ms))
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
            dns: state.dns,
        })
    }

    fn summary_from(
        &self,
        latest: &LinkGeneration,
        state: &LinkGenerationState,
        _observed_at_ms: u64,
    ) -> LinkSummary {
        let upload = latest.completed_upload.load(Ordering::Relaxed);
        let download = latest.completed_download.load(Ordering::Relaxed);
        let last_active = latest
            .last_active_ms
            .load(Ordering::Relaxed)
            .max(self.last_active_ms.load(Ordering::Relaxed));
        LinkSummary {
            name: self.name.clone(),
            kind: latest.kind,
            state: state.state,
            health: state.health,
            generation: latest.number,
            active_conn_count: latest.active_conn_count.load(Ordering::Relaxed),
            last_active_at_ms: (last_active != 0).then_some(last_active),
            traffic: Traffic {
                upload_bytes: upload,
                download_bytes: download,
            },
            total_traffic: Traffic {
                upload_bytes: self.completed_upload.load(Ordering::Relaxed) + upload,
                download_bytes: self.completed_download.load(Ordering::Relaxed) + download,
            },
            reason: state.reason.clone(),
        }
    }
}

fn retire_latest(link: &Link, inner: &mut LinkInner) {
    if let Some(previous) = inner.latest.take() {
        link.completed_upload.fetch_add(
            previous.completed_upload.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        link.completed_download.fetch_add(
            previous.completed_download.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        link.last_active_ms.fetch_max(
            previous.last_active_ms.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }
}

fn invalidate_latest(inner: &LinkInner, reason: LinkReasonCode) -> Option<u64> {
    let latest = inner.latest.as_ref()?;
    let mut state = latest.state.lock().unwrap();
    state.state = LinkState::Closed;
    state.health = LinkHealth::Unknown;
    state.ended_at_ms.get_or_insert_with(now_ms);
    state.reason = Some(LinkReason {
        code: reason,
        detail: None,
    });
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
    use std::sync::Barrier;

    fn anytls(password: &str) -> NamedLinkConfig {
        NamedLinkConfig::new(
            LinkConfig::Anytls(AnytlsConfig::new(
                NetworkAddr::Domain {
                    name: "link.example".to_string(),
                    port: 443,
                },
                password,
                "link.example",
                CertVerify::Verify,
            )),
            vec![ConfiguredLinkRoute {
                chain: "route".to_string(),
                hops: vec!["ordinary".to_string(), "link".to_string()],
                interface: None,
            }],
        )
    }

    fn configs(config: NamedLinkConfig) -> HashMap<String, NamedLinkConfig> {
        HashMap::from([("link".to_string(), config)])
    }

    #[test]
    fn configured_but_never_used_is_omitted() {
        let table = LinkTable::new(configs(anytls("secret")));
        assert!(table.snapshot(now_ms()).items.is_empty());
        assert!(table.detail("link", now_ms()).is_none());
    }

    #[test]
    fn unchanged_config_preserves_generation() {
        let config = anytls("secret");
        let table = LinkTable::new(configs(config.clone()));
        let first = table.acquire("link", &config).unwrap();
        assert!(first.created);

        assert!(table.reconcile(configs(config.clone())).is_empty());
        let second = table.acquire("link", &config).unwrap();
        assert!(!second.created);
        assert!(Arc::ptr_eq(&first.generation, &second.generation));
    }

    #[test]
    fn changed_config_closes_old_and_rejects_stale_acquisition() {
        let old = anytls("old-secret");
        let new = anytls("new-secret");
        let table = LinkTable::new(configs(old.clone()));
        let first = table.acquire("link", &old).unwrap();

        let invalidations = table.reconcile(configs(new.clone()));
        assert_eq!(invalidations.len(), 1);
        assert_eq!(invalidations[0].reason, LinkReasonCode::ConfigChanged);
        assert_eq!(
            table.acquire("link", &old).err(),
            Some(LinkAcquireError::StaleConfig)
        );
        let summary = &table.snapshot(now_ms()).items[0];
        assert_eq!(summary.state, LinkState::Closed);
        assert_eq!(
            summary.reason.as_ref().map(|reason| reason.code),
            Some(LinkReasonCode::ConfigChanged)
        );

        let replacement = table.acquire("link", &new).unwrap();
        assert_eq!(
            replacement.generation.number(),
            first.generation.number() + 1
        );
    }

    #[test]
    fn removed_and_readded_name_keeps_lineage() {
        let config = anytls("secret");
        let table = LinkTable::new(configs(config.clone()));
        let first = table.acquire("link", &config).unwrap();

        let invalidations = table.reconcile(HashMap::new());
        assert_eq!(invalidations[0].reason, LinkReasonCode::ConfigRemoved);
        assert_eq!(
            table.acquire("link", &config).err(),
            Some(LinkAcquireError::NotConfigured)
        );
        let removed = &table.snapshot(now_ms()).items[0];
        assert_eq!(
            removed.reason.as_ref().map(|reason| reason.code),
            Some(LinkReasonCode::ConfigRemoved)
        );

        assert!(table.reconcile(configs(config.clone())).is_empty());
        let replacement = table.acquire("link", &config).unwrap();
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
        assert_eq!(
            table.acquire("link", &config).unwrap().generation.number(),
            1
        );
    }

    #[test]
    fn delayed_old_generation_operation_cannot_affect_replacement() {
        let old = anytls("old-secret");
        let new = anytls("new-secret");
        let table = LinkTable::new(configs(old.clone()));
        let first = table.acquire("link", &old).unwrap();
        table.reconcile(configs(new.clone()));
        let replacement = table.acquire("link", &new).unwrap();

        assert!(!table.mark_terminal(
            "link",
            first.generation.number(),
            LinkState::Failed,
            LinkHealth::Unhealthy,
            LinkReason {
                code: LinkReasonCode::TaskStopped,
                detail: None,
            },
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
        let old_generation = table.acquire("link", &old).unwrap().generation.number();
        let barrier = Arc::new(Barrier::new(3));

        std::thread::scope(|scope| {
            let reload_table = table.clone();
            let reload_barrier = barrier.clone();
            let reload_config = new.clone();
            scope.spawn(move || {
                reload_barrier.wait();
                reload_table.reconcile(configs(reload_config.clone()));
                reload_table.acquire("link", &reload_config).unwrap();
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
}
