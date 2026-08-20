use super::NameServerConfigEnum;
use boltapi::{
    DnsEndpoint, DnsErrorCode, DnsErrorCount, DnsFailureCount, DnsFailureEpisode, DnsFailureKind,
    DnsLatency, DnsOutcome, DnsOutcomeCounts, DnsProtocol, DnsResolverDetail, DnsResolverSummary,
    DnsScope, NetworkAddr, RouteEgress, RouteHop,
};
use hickory_resolver::config::{NameServerConfig, ProtocolConfig};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) const CACHE_HIT_THRESHOLD: Duration = Duration::from_millis(1);
const LATENCY_SAMPLE_LIMIT: usize = 200;
const FAILURE_EPISODE_LIMIT: usize = 3;

/// Immutable, secret-free description of one resolver connectivity identity.
/// Runtime statistics are deliberately kept outside this value so an unchanged
/// identity can reuse its record while adopting new scopes or retry settings.
#[derive(Clone, Debug)]
pub(super) struct DnsResolverIdentity {
    pub id: String,
    pub protocol: DnsProtocol,
    pub endpoint: DnsEndpoint,
    pub via: RouteEgress,
    pub current_endpoints: Vec<SocketAddr>,
    pub tls_server_name: Option<String>,
    pub timeout_ms: u64,
    pub max_attempts: u32,
}

#[derive(Debug)]
pub(super) struct DnsResolverRecord {
    id: String,
    tracking_started_at_ms: u64,
    state: Mutex<DnsResolverRecordState>,
}

#[derive(Debug, Default)]
struct DnsResolverRecordState {
    cache_hits: u64,
    answered: u64,
    timeout: u64,
    error: u64,
    errors: HashMap<DnsErrorCode, u64>,
    last_result: Option<DnsOutcome>,
    last_active_at_ms: Option<u64>,
    answered_latency_ms: VecDeque<u64>,
    failure_episodes: VecDeque<DnsFailureEpisode>,
    current_endpoints: Vec<SocketAddr>,
}

impl DnsResolverRecord {
    pub fn new(identity: &DnsResolverIdentity) -> Self {
        Self {
            id: identity.id.clone(),
            tracking_started_at_ms: now_ms(),
            state: Mutex::new(DnsResolverRecordState {
                current_endpoints: identity.current_endpoints.clone(),
                ..DnsResolverRecordState::default()
            }),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Refreshes variable endpoint evidence without resetting statistics. This
    /// is used both after a compatible reload and after DHCP refresh.
    pub fn set_current_endpoints(&self, mut endpoints: Vec<SocketAddr>) {
        endpoints.sort_unstable();
        endpoints.dedup();
        self.state.lock().unwrap().current_endpoints = endpoints;
    }

    pub fn lookups(&self) -> u64 {
        let state = self.state.lock().unwrap();
        state
            .answered
            .saturating_add(state.timeout)
            .saturating_add(state.error)
    }

    /// Records one resolver-and-record-type invocation. The caller measures
    /// duration before taking this lock so unrelated lookups never inflate it.
    pub fn observe(&self, duration: Duration, outcome: DnsOutcome) {
        let observed_at_ms = now_ms();
        let mut state = self.state.lock().unwrap();
        state.last_active_at_ms = Some(observed_at_ms);
        state.last_result = Some(outcome.clone());

        match &outcome {
            DnsOutcome::Answered { .. } => {
                state.answered = state.answered.saturating_add(1);
                if duration < CACHE_HIT_THRESHOLD {
                    state.cache_hits = state.cache_hits.saturating_add(1);
                } else {
                    if state.answered_latency_ms.len() == LATENCY_SAMPLE_LIMIT {
                        state.answered_latency_ms.pop_front();
                    }
                    state
                        .answered_latency_ms
                        .push_back(duration_ms_rounded_up(duration));
                }
                if let Some(episode) = state.failure_episodes.back_mut()
                    && episode.recovered_at_ms.is_none()
                {
                    episode.recovered_at_ms = Some(observed_at_ms);
                }
            }
            DnsOutcome::Timeout => {
                state.timeout = state.timeout.saturating_add(1);
                record_failure(&mut state, observed_at_ms, DnsFailureKind::Timeout);
            }
            DnsOutcome::Error { code, .. } => {
                state.error = state.error.saturating_add(1);
                let count = state.errors.entry(*code).or_default();
                *count = count.saturating_add(1);
                record_failure(
                    &mut state,
                    observed_at_ms,
                    DnsFailureKind::Error { code: *code },
                );
            }
        }
    }

    pub fn summary(
        &self,
        identity: &DnsResolverIdentity,
        scopes: Vec<DnsScope>,
    ) -> DnsResolverSummary {
        let state = self.state.lock().unwrap();
        let mut latency = state
            .answered_latency_ms
            .iter()
            .copied()
            .collect::<Vec<_>>();
        latency.sort_unstable();
        DnsResolverSummary {
            id: self.id.clone(),
            scopes,
            protocol: identity.protocol,
            endpoint: endpoint_with_current_server(
                &identity.endpoint,
                state.current_endpoints.first().copied(),
            ),
            via: identity.via.clone(),
            lookups: state
                .answered
                .saturating_add(state.timeout)
                .saturating_add(state.error),
            p50_latency_ms: percentile(&latency, 50),
            last_result: state.last_result.clone(),
            last_active_at_ms: state.last_active_at_ms,
        }
    }

    pub fn detail(
        &self,
        observed_at_ms: u64,
        identity: &DnsResolverIdentity,
        scopes: Vec<DnsScope>,
        chain: Vec<RouteHop>,
    ) -> DnsResolverDetail {
        let state = self.state.lock().unwrap();
        let mut latency = state
            .answered_latency_ms
            .iter()
            .copied()
            .collect::<Vec<_>>();
        latency.sort_unstable();
        let mut errors = state
            .errors
            .iter()
            .map(|(code, count)| DnsErrorCount {
                code: *code,
                count: *count,
            })
            .collect::<Vec<_>>();
        errors.sort_by_key(|item| dns_error_order(item.code));

        DnsResolverDetail {
            observed_at_ms,
            summary: DnsResolverSummary {
                id: self.id.clone(),
                scopes,
                protocol: identity.protocol,
                endpoint: endpoint_with_current_server(
                    &identity.endpoint,
                    state.current_endpoints.first().copied(),
                ),
                via: identity.via.clone(),
                lookups: state
                    .answered
                    .saturating_add(state.timeout)
                    .saturating_add(state.error),
                p50_latency_ms: percentile(&latency, 50),
                last_result: state.last_result.clone(),
                last_active_at_ms: state.last_active_at_ms,
            },
            current_endpoints: state.current_endpoints.clone(),
            tls_server_name: identity.tls_server_name.clone(),
            chain,
            timeout_ms: identity.timeout_ms,
            max_attempts: identity.max_attempts,
            tracking_started_at_ms: self.tracking_started_at_ms,
            outcomes: DnsOutcomeCounts {
                cache_hits: state.cache_hits,
                answered: state.answered,
                timeout: state.timeout,
                error: state.error,
                errors,
            },
            latency: DnsLatency {
                sample_count: latency.len().try_into().unwrap_or(u32::MAX),
                p50_ms: percentile(&latency, 50),
                p90_ms: percentile(&latency, 90),
            },
            failure_episodes: state.failure_episodes.iter().cloned().collect(),
        }
    }
}

fn endpoint_with_current_server(
    endpoint: &DnsEndpoint,
    current_server: Option<SocketAddr>,
) -> DnsEndpoint {
    match endpoint {
        DnsEndpoint::Dhcp { interface, .. } => DnsEndpoint::Dhcp {
            interface: interface.clone(),
            current_server,
        },
        _ => endpoint.clone(),
    }
}

fn record_failure(
    state: &mut DnsResolverRecordState,
    observed_at_ms: u64,
    failure: DnsFailureKind,
) {
    if let Some(episode) = state.failure_episodes.back_mut()
        && episode.recovered_at_ms.is_none()
    {
        episode.last_failure_at_ms = observed_at_ms;
        episode.failures = episode.failures.saturating_add(1);
        increment_failure(&mut episode.breakdown, failure);
        return;
    }

    if state.failure_episodes.len() == FAILURE_EPISODE_LIMIT {
        state.failure_episodes.pop_front();
    }
    state.failure_episodes.push_back(DnsFailureEpisode {
        started_at_ms: observed_at_ms,
        last_failure_at_ms: observed_at_ms,
        recovered_at_ms: None,
        failures: 1,
        breakdown: vec![DnsFailureCount { failure, count: 1 }],
    });
}

fn increment_failure(breakdown: &mut Vec<DnsFailureCount>, failure: DnsFailureKind) {
    if let Some(existing) = breakdown
        .iter_mut()
        .find(|item| same_failure_kind(&item.failure, &failure))
    {
        existing.count = existing.count.saturating_add(1);
    } else {
        breakdown.push(DnsFailureCount { failure, count: 1 });
    }
}

fn same_failure_kind(left: &DnsFailureKind, right: &DnsFailureKind) -> bool {
    match (left, right) {
        (DnsFailureKind::Timeout, DnsFailureKind::Timeout) => true,
        (DnsFailureKind::Error { code: left }, DnsFailureKind::Error { code: right }) => {
            left == right
        }
        _ => false,
    }
}

pub(super) fn identity_from_config(
    config: &NameServerConfigEnum,
    via: RouteEgress,
    timeout_ms: u64,
    max_attempts: u32,
) -> DnsResolverIdentity {
    match config {
        NameServerConfigEnum::Normal(configs) => {
            identity_from_normal(configs, via, timeout_ms, max_attempts)
        }
        NameServerConfigEnum::Dhcp(interface) => {
            let interface = interface.trim().to_string();
            let descriptor = format!(
                "boltconn-dns-resolver-v1\nprotocol=udp\nendpoints=dhcp:{}\negress={}\ntls=",
                interface,
                canonical_egress(&via)
            );
            DnsResolverIdentity {
                id: sha256_hex(&descriptor),
                protocol: DnsProtocol::Udp,
                endpoint: DnsEndpoint::Dhcp {
                    interface,
                    current_server: None,
                },
                via,
                current_endpoints: Vec::new(),
                tls_server_name: None,
                timeout_ms,
                max_attempts,
            }
        }
    }
}

pub(super) fn identity_from_normal(
    configs: &[NameServerConfig],
    via: RouteEgress,
    timeout_ms: u64,
    max_attempts: u32,
) -> DnsResolverIdentity {
    let representative = configs
        .iter()
        .flat_map(|config| config.connections.iter().map(move |conn| (config, conn)))
        .next();
    let protocol = representative
        .map(|(_, conn)| protocol_kind(&conn.protocol))
        .unwrap_or(DnsProtocol::Udp);

    let mut canonical_endpoints = Vec::new();
    let mut display_addresses = Vec::new();
    let mut current_endpoints = Vec::new();
    let mut tls_names = Vec::new();
    let mut https_uris = Vec::new();

    for (config, connection) in configs
        .iter()
        .flat_map(|config| config.connections.iter().map(move |conn| (config, conn)))
        .filter(|(_, connection)| protocol_kind(&connection.protocol) == protocol)
    {
        let server_name = tls_server_name(&connection.protocol);
        if let Some(name) = &server_name {
            tls_names.push(name.clone());
        }
        let current = SocketAddr::new(config.ip, connection.port);
        current_endpoints.push(current);

        match &connection.protocol {
            ProtocolConfig::Https { path, .. } => {
                let name = server_name.unwrap_or_else(|| config.ip.to_string());
                let uri = format!("https://{}{}", name, normalize_https_path(path));
                canonical_endpoints.push(format!("https:{uri}"));
                https_uris.push(uri);
            }
            ProtocolConfig::Tls { .. } => {
                let address = match server_name {
                    Some(name) => NetworkAddr::Domain {
                        name,
                        port: connection.port,
                    },
                    None => NetworkAddr::Socket { address: current },
                };
                canonical_endpoints.push(canonical_network_addr(&address));
                display_addresses.push(address);
            }
            _ => {
                let address = NetworkAddr::Socket { address: current };
                canonical_endpoints.push(canonical_network_addr(&address));
                display_addresses.push(address);
            }
        }
    }

    canonical_endpoints.sort();
    canonical_endpoints.dedup();
    display_addresses.sort_by_key(canonical_network_addr);
    display_addresses.dedup();
    current_endpoints.sort_unstable();
    current_endpoints.dedup();
    tls_names.sort();
    tls_names.dedup();
    https_uris.sort();
    https_uris.dedup();

    let tls_server_name = (tls_names.len() == 1).then(|| tls_names[0].clone());
    let endpoint = if protocol == DnsProtocol::Doh {
        DnsEndpoint::Https {
            uri: https_uris.first().cloned().unwrap_or_default(),
        }
    } else {
        DnsEndpoint::Network {
            addresses: display_addresses,
        }
    };
    let descriptor = format!(
        "boltconn-dns-resolver-v1\nprotocol={}\nendpoints={}\negress={}\ntls={}",
        canonical_protocol(protocol),
        canonical_endpoints.join(","),
        canonical_egress(&via),
        tls_names.join(",")
    );
    DnsResolverIdentity {
        id: sha256_hex(&descriptor),
        protocol,
        endpoint,
        via,
        current_endpoints,
        tls_server_name,
        timeout_ms,
        max_attempts,
    }
}

#[allow(unreachable_patterns)]
fn protocol_kind(protocol: &ProtocolConfig) -> DnsProtocol {
    match protocol {
        ProtocolConfig::Udp => DnsProtocol::Udp,
        ProtocolConfig::Tcp => DnsProtocol::Tcp,
        ProtocolConfig::Tls { .. } => DnsProtocol::Dot,
        ProtocolConfig::Https { .. } => DnsProtocol::Doh,
        _ => DnsProtocol::Udp,
    }
}

fn tls_server_name(protocol: &ProtocolConfig) -> Option<String> {
    match protocol {
        ProtocolConfig::Tls { server_name } | ProtocolConfig::Https { server_name, .. } => {
            Some(normalize_hostname(server_name))
        }
        _ => None,
    }
}

fn normalize_hostname(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_https_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn canonical_network_addr(address: &NetworkAddr) -> String {
    match address {
        NetworkAddr::Socket { address } => format!("socket:{address}"),
        NetworkAddr::Domain { name, port } => {
            format!("domain:{}:{port}", normalize_hostname(name))
        }
    }
}

fn canonical_protocol(protocol: DnsProtocol) -> &'static str {
    match protocol {
        DnsProtocol::Udp => "udp",
        DnsProtocol::Tcp => "tcp",
        DnsProtocol::Dot => "dot",
        DnsProtocol::Doh => "doh",
    }
}

fn canonical_egress(via: &RouteEgress) -> String {
    match via {
        RouteEgress::Direct => "direct".to_string(),
        RouteEgress::Interface { name } => format!("interface:{name}"),
        RouteEgress::Proxy { selection } => format!(
            "proxy:{}:{}",
            selection.group.as_deref().unwrap_or_default(),
            selection.selected
        ),
        RouteEgress::Link { name } => format!("link:{name}"),
    }
}

fn sha256_hex(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn percentile(sorted: &[u64], percentile: usize) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    // Nearest-rank keeps small samples intuitive and never interpolates a
    // latency value that was not actually observed.
    let rank = percentile.saturating_mul(sorted.len()).div_ceil(100);
    sorted.get(rank.saturating_sub(1)).copied()
}

fn duration_ms_rounded_up(duration: Duration) -> u64 {
    duration
        .as_micros()
        .div_ceil(1000)
        .try_into()
        .unwrap_or(u64::MAX)
}

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn dns_error_order(code: DnsErrorCode) -> u8 {
    match code {
        DnsErrorCode::Servfail => 0,
        DnsErrorCode::Refused => 1,
        DnsErrorCode::Response => 2,
        DnsErrorCode::Transport => 3,
        DnsErrorCode::Tls => 4,
        DnsErrorCode::Http => 5,
        DnsErrorCode::Dependency => 6,
        DnsErrorCode::Local => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::ConnectionConfig;
    use std::net::{IpAddr, Ipv4Addr};

    fn udp_config(address: [u8; 4]) -> NameServerConfig {
        NameServerConfig::new(
            IpAddr::V4(Ipv4Addr::from(address)),
            true,
            vec![ConnectionConfig::udp()],
        )
    }

    #[test]
    fn identity_ignores_endpoint_order_duplicates_and_runtime_options() {
        let first = NameServerConfigEnum::Normal(vec![
            udp_config([1, 1, 1, 1]),
            udp_config([8, 8, 8, 8]),
            udp_config([1, 1, 1, 1]),
        ]);
        let second =
            NameServerConfigEnum::Normal(vec![udp_config([8, 8, 8, 8]), udp_config([1, 1, 1, 1])]);
        let via = RouteEgress::Interface {
            name: "en0".to_string(),
        };

        let first = identity_from_config(&first, via.clone(), 1600, 3);
        let second = identity_from_config(&second, via, 5000, 9);

        assert_eq!(first.id, second.id);
        assert_eq!(first.id.len(), 64);
        assert!(
            first
                .id
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
    }

    #[test]
    fn record_bounds_latency_and_failure_episode_history() {
        let identity = identity_from_config(
            &NameServerConfigEnum::Normal(vec![udp_config([1, 1, 1, 1])]),
            RouteEgress::Direct,
            1600,
            3,
        );
        let record = DnsResolverRecord::new(&identity);
        record.observe(
            Duration::from_micros(99),
            DnsOutcome::Answered {
                response: boltapi::DnsResponseKind::Answer,
            },
        );
        for sample in 1..=205 {
            record.observe(
                Duration::from_millis(sample),
                DnsOutcome::Answered {
                    response: boltapi::DnsResponseKind::Answer,
                },
            );
        }
        for _ in 0..4 {
            record.observe(Duration::from_secs(1), DnsOutcome::Timeout);
            record.observe(
                Duration::from_millis(1),
                DnsOutcome::Answered {
                    response: boltapi::DnsResponseKind::Answer,
                },
            );
        }

        let detail = record.detail(0, &identity, Vec::new(), Vec::new());
        assert_eq!(detail.outcomes.cache_hits, 1);
        assert_eq!(detail.latency.sample_count, 200);
        assert_eq!(detail.failure_episodes.len(), 3);
        assert!(
            detail
                .failure_episodes
                .iter()
                .all(|episode| episode.recovered_at_ms.is_some())
        );
    }

    #[test]
    fn latency_percentiles_and_outcome_breakdown_are_exact() {
        let identity = identity_from_config(
            &NameServerConfigEnum::Normal(vec![udp_config([1, 1, 1, 1])]),
            RouteEgress::Direct,
            1600,
            3,
        );
        let record = DnsResolverRecord::new(&identity);
        for duration in [10, 20, 30, 40, 50] {
            record.observe(
                Duration::from_millis(duration),
                DnsOutcome::Answered {
                    response: boltapi::DnsResponseKind::Answer,
                },
            );
        }
        record.observe(Duration::from_secs(1), DnsOutcome::Timeout);
        record.observe(
            Duration::from_millis(2),
            DnsOutcome::Error {
                code: DnsErrorCode::Servfail,
                detail: None,
            },
        );

        let detail = record.detail(0, &identity, Vec::new(), Vec::new());
        assert_eq!(detail.summary.lookups, 7);
        assert_eq!(detail.latency.sample_count, 5);
        assert_eq!(detail.latency.p50_ms, Some(30));
        assert_eq!(detail.latency.p90_ms, Some(50));
        assert_eq!(detail.outcomes.answered, 5);
        assert_eq!(detail.outcomes.timeout, 1);
        assert_eq!(detail.outcomes.error, 1);
        assert_eq!(detail.outcomes.errors.len(), 1);
        assert_eq!(detail.outcomes.errors[0].code, DnsErrorCode::Servfail);
        assert_eq!(detail.outcomes.errors[0].count, 1);
        assert_eq!(detail.failure_episodes.len(), 1);
        assert_eq!(detail.failure_episodes[0].failures, 2);
    }

    #[test]
    fn encrypted_identity_uses_hostname_not_bootstrap_address() {
        let config = |address: [u8; 4]| {
            NameServerConfigEnum::Normal(vec![NameServerConfig::new(
                IpAddr::V4(Ipv4Addr::from(address)),
                false,
                vec![ConnectionConfig::https(
                    "dns.example".into(),
                    Some("/dns-query".into()),
                )],
            )])
        };
        let first = identity_from_config(&config([192, 0, 2, 1]), RouteEgress::Direct, 1600, 3);
        let second = identity_from_config(&config([192, 0, 2, 2]), RouteEgress::Direct, 1600, 3);

        assert_eq!(first.id, second.id);
        assert_eq!(first.tls_server_name.as_deref(), Some("dns.example"));
        assert!(matches!(
            first.endpoint,
            DnsEndpoint::Https { ref uri } if uri == "https://dns.example/dns-query"
        ));
        assert_ne!(first.current_endpoints, second.current_endpoints);
    }
}
