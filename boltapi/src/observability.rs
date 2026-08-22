use crate::ProcessSchema;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot<T> {
    pub observed_at_ms: u64,
    pub items: Vec<T>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Traffic {
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkAddr {
    Socket { address: SocketAddr },
    Domain { name: String, port: u16 },
}

impl NetworkAddr {
    pub fn port(&self) -> u16 {
        match self {
            Self::Socket { address } => address.port(),
            Self::Domain { port, .. } => *port,
        }
    }

    /// Returns true only when the two values cannot refer to the same endpoint.
    ///
    /// A domain and a resolved socket may still be equal, so that pair is only
    /// considered unequal when its ports differ.
    pub fn definitely_not_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Socket { address: left }, Self::Socket { address: right }) => left != right,
            (Self::Socket { address }, Self::Domain { port, .. })
            | (Self::Domain { port, .. }, Self::Socket { address }) => address.port() != *port,
            (
                Self::Domain {
                    name: left_name,
                    port: left_port,
                },
                Self::Domain {
                    name: right_name,
                    port: right_port,
                },
            ) => left_name != right_name || left_port != right_port,
        }
    }
}

impl Display for NetworkAddr {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket { address } => Display::fmt(address, formatter),
            Self::Domain { name, port } => write!(formatter, "{name}:{port}"),
        }
    }
}

impl From<SocketAddr> for NetworkAddr {
    fn from(address: SocketAddr) -> Self {
        Self::Socket { address }
    }
}

impl FromStr for NetworkAddr {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = value.parse::<SocketAddr>() {
            return Ok(Self::Socket { address });
        }

        let (name, port) = value.rsplit_once(':').ok_or(())?;
        if name.is_empty() {
            return Err(());
        }
        Ok(Self::Domain {
            name: name.to_string(),
            port: port.parse().map_err(|_| ())?,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionProtocol {
    Tcp,
    Udp,
    Http,
    Tls,
    Quic,
}

impl Display for SessionProtocol {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Quic => "quic",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ApiErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    InvalidRequest,
    ConnNotFound,
    ConnNotActive,
    LinkNotFound,
    LinkNotInitialized,
    LinkNotActive,
    ResolverNotFound,
    ResolverIdAmbiguous,
    ResolverUnavailable,
    DnsMappingNotFound,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConnListRequest {
    pub link: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnStopResult {
    pub stopped_connections: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeIpMapping {
    pub fake_ip: IpAddr,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnSummary {
    pub id: u64,
    pub state: ConnState,
    pub started_at_ms: u64,
    pub duration_ms: u64,
    pub origin: ConnOrigin,
    pub protocol: SessionProtocol,
    pub target: NetworkAddr,
    pub via: Option<RouteSelection>,
    pub traffic: Traffic,
    pub result: Option<ConnResultCode>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnState {
    Accepted,
    Inspecting,
    Routing,
    Resolving,
    Connecting,
    Active,
    Closing,
    Closed,
    Failed,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConnOrigin {
    Process { name: String, tag: Option<String> },
    Network { source_ip: IpAddr },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSelection {
    pub group: Option<String>,
    pub selected: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnResultCode {
    Completed,
    ClientClosed,
    RemoteClosed,
    UserStopped,
    LinkStopped,
    LinkReconfigured,
    LinkRemoved,
    LinkLost,
    RouteRejected,
    Blackholed,
    DnsTimeout,
    DnsError,
    ConnectTimeout,
    ConnectError,
    HandshakeError,
    TransferError,
    InternalError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnDetail {
    pub observed_at_ms: u64,
    pub summary: ConnSummary,
    pub established_at_ms: Option<u64>,
    pub ended_at_ms: Option<u64>,
    pub flow: ConnFlow,
    pub process: Option<ProcessSchema>,
    pub route: Option<RouteDecision>,
    pub dns: ConnDnsActivity,
    pub links: Vec<LinkRef>,
    pub termination: Option<ConnTermination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnDnsActivity {
    pub total_lookups: u64,
    pub lookups: Vec<DnsLookupDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnFlow {
    pub inbound: String,
    pub source: SocketAddr,
    pub accepted: NetworkAddr,
    pub identified: Option<IdentifiedTarget>,
    pub resolution: DestinationResolution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifiedTarget {
    pub target: NetworkAddr,
    pub source: IdentificationSource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentificationSource {
    FakeIpMapping,
    TlsSni,
    HttpHost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DestinationResolution {
    NotStarted,
    InProgress,
    Resolved { address: SocketAddr },
    Delegated,
    NotRequired,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnTermination {
    pub code: ConnResultCode,
    pub stage: Option<ConnStage>,
    pub detail: Option<String>,
}

impl ConnTermination {
    pub fn new(code: ConnResultCode, stage: ConnStage, detail: Option<String>) -> Self {
        Self {
            code,
            stage: Some(stage),
            detail,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnStage {
    Inspecting,
    Routing,
    Resolving,
    Connecting,
    Handshaking,
    Transferring,
    Closing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDecision {
    pub matched_rule: String,
    pub origin: RuleOrigin,
    pub expanded_from: Vec<ConfigSourceLocation>,
    pub selected: RouteSelection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleOrigin {
    Config { location: ConfigSourceLocation },
    Temporary,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSourceLocation {
    pub path: String,
    pub document_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRef {
    pub name: String,
    pub kind: LinkKind,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Wireguard,
    Ssh,
    Anytls,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    Initializing,
    Ready,
    Idle,
    Closing,
    Closed,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkHealth {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkReasonCode {
    NoRecentProbe,
    TaskStopped,
    DnsFailed,
    ConnectFailed,
    AuthenticationFailed,
    ProtocolFailed,
    DependencyFailed,
    ConfigChanged,
    ConfigRemoved,
    UserStopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteHop {
    pub group: Option<String>,
    pub proxy: String,
    pub proxy_type: String,
    pub link: Option<LinkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSummary {
    pub name: String,
    pub kind: LinkKind,
    pub state: LinkState,
    pub health: LinkHealth,
    pub generation: u64,
    pub active_conn_count: u64,
    pub last_active_at_ms: Option<u64>,
    pub traffic: Traffic,
    pub total_traffic: Traffic,
    pub reason: Option<LinkReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkDetail {
    pub observed_at_ms: u64,
    pub summary: LinkSummary,
    pub created_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub duration_ms: u64,
    pub server: NetworkAddr,
    pub connected_endpoints: Vec<SocketAddr>,
    pub chain: Vec<RouteHop>,
    pub dns: DnsActivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkReason {
    pub code: LinkReasonCode,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsActivity {
    pub lookups: u64,
    pub outcomes: DnsOutcomeCounts,
    pub latest_lookup: Option<DnsLookupDetail>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsProtocol {
    Udp,
    Tcp,
    Dot,
    Doh,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordType {
    A,
    Aaaa,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsLookupPurpose {
    Destination,
    ProxyServer { proxy: String },
    LinkServer { link: String },
    Diagnostic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DnsErrorCode {
    Servfail,
    Refused,
    Response,
    Transport,
    Tls,
    Http,
    Dependency,
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolverSummary {
    pub id: String,
    pub scopes: Vec<DnsScope>,
    pub protocol: DnsProtocol,
    pub endpoint: DnsEndpoint,
    pub via: RouteEgress,
    pub lookups: u64,
    pub p50_latency_ms: Option<u64>,
    pub last_result: Option<DnsOutcome>,
    pub last_active_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsScope {
    Global { order: u32 },
    Policy { matchers: Vec<String> },
    Link { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsEndpoint {
    Network {
        addresses: Vec<NetworkAddr>,
    },
    Https {
        uri: String,
    },
    Dhcp {
        interface: String,
        current_server: Option<SocketAddr>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteEgress {
    Direct,
    Interface { name: String },
    Proxy { selection: RouteSelection },
    Link { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolverDetail {
    pub observed_at_ms: u64,
    pub summary: DnsResolverSummary,
    pub current_endpoints: Vec<SocketAddr>,
    pub tls_server_name: Option<String>,
    pub chain: Vec<RouteHop>,
    pub timeout_ms: u64,
    pub max_attempts: u32,
    pub tracking_started_at_ms: u64,
    pub outcomes: DnsOutcomeCounts,
    pub latency: DnsLatency,
    pub failure_episodes: Vec<DnsFailureEpisode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsOutcomeCounts {
    pub cache_hits: u64,
    pub answered: u64,
    pub timeout: u64,
    pub error: u64,
    pub errors: Vec<DnsErrorCount>,
}

/// Aggregate count for one typed DNS error.
///
/// `api.md` references this type from `DnsOutcomeCounts` without spelling out
/// its fields. Keeping the stable error code separate from the count mirrors
/// `DnsFailureCount` and avoids requiring clients to parse display strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsErrorCount {
    pub code: DnsErrorCode,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLatency {
    pub sample_count: u32,
    pub p50_ms: Option<u64>,
    pub p90_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFailureEpisode {
    pub started_at_ms: u64,
    pub last_failure_at_ms: u64,
    pub recovered_at_ms: Option<u64>,
    pub failures: u64,
    pub breakdown: Vec<DnsFailureCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFailureCount {
    pub failure: DnsFailureKind,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsFailureKind {
    Timeout,
    Error { code: DnsErrorCode },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsLookupRequest {
    pub domain: String,
    // HTTP spells this query key `resolver`; the alias keeps the typed UDS/JSON
    // field name explicit without introducing a second transport-only request.
    #[serde(alias = "resolver")]
    pub resolver_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookupResponse {
    pub observed_at_ms: u64,
    pub lookup: DnsLookupDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookupDetail {
    pub purpose: DnsLookupPurpose,
    pub name: String,
    pub selection: DnsSelection,
    pub cache: DnsCacheStatus,
    pub attempts: Vec<DnsResolverAttempt>,
    pub answers: Vec<DnsAnswer>,
    pub result: DnsOutcome,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolverAttempt {
    pub resolver_id: String,
    pub scope: DnsAttemptScope,
    pub record_type: DnsRecordType,
    pub duration_ms: u64,
    pub result: DnsOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsAttemptScope {
    Global { order: u32 },
    Policy { matcher: String },
    Link { name: String },
    Explicit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsOutcome {
    Answered {
        response: DnsResponseKind,
    },
    Timeout,
    Error {
        code: DnsErrorCode,
        detail: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsResponseKind {
    Answer,
    NxDomain,
    NoData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub record_type: DnsRecordType,
    pub address: IpAddr,
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsSelection {
    Hosts,
    Global,
    Policy { matcher: String },
    Link { name: String },
    Explicit { resolver_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsCacheStatus {
    Hit { resolver_id: String },
    Miss,
    NotApplicable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serializes_tagged_addresses_and_snake_case_enums() {
        let address = NetworkAddr::Domain {
            name: "example.com".to_string(),
            port: 443,
        };

        assert_eq!(
            serde_json::to_value(address).unwrap(),
            json!({ "kind": "domain", "name": "example.com", "port": 443 })
        );
        assert_eq!(
            serde_json::to_value(ConnResultCode::LinkReconfigured).unwrap(),
            json!("link_reconfigured")
        );
        assert_eq!(
            serde_json::to_value(DnsOutcome::Answered {
                response: DnsResponseKind::NxDomain,
            })
            .unwrap(),
            json!({ "kind": "answered", "response": "nx_domain" })
        );
    }

    #[test]
    fn requests_reject_unknown_fields() {
        let conn = serde_json::from_value::<ConnListRequest>(json!({
            "link": null,
            "unexpected": true,
        }));
        assert!(conn.is_err());

        let dns = serde_json::from_value::<DnsLookupRequest>(json!({
            "domain": "example.com",
            "resolver_id": null,
            "unexpected": true,
        }));
        assert!(dns.is_err());

        let dns_query = serde_json::from_value::<DnsLookupRequest>(json!({
            "domain": "example.com",
            "resolver": "0123456789ab",
        }))
        .unwrap();
        assert_eq!(dns_query.resolver_id.as_deref(), Some("0123456789ab"));
    }

    #[test]
    fn round_trips_representative_connection_snapshot() {
        let snapshot = Snapshot {
            observed_at_ms: 1_786_460_641_000,
            items: vec![ConnSummary {
                id: 4821,
                state: ConnState::Active,
                started_at_ms: 1_786_460_640_000,
                duration_ms: 1000,
                origin: ConnOrigin::Process {
                    name: "curl".to_string(),
                    tag: Some("api-test".to_string()),
                },
                protocol: SessionProtocol::Tls,
                target: NetworkAddr::Domain {
                    name: "example.com".to_string(),
                    port: 443,
                },
                via: Some(RouteSelection {
                    group: Some("US".to_string()),
                    selected: "ssh-us-2".to_string(),
                }),
                traffic: Traffic {
                    upload_bytes: 2048,
                    download_bytes: 8192,
                },
                result: None,
            }],
        };

        let encoded = serde_json::to_string(&snapshot).unwrap();
        let decoded: Snapshot<ConnSummary> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.observed_at_ms, snapshot.observed_at_ms);
        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0].id, 4821);
        assert_eq!(decoded.items[0].result, None);
    }
}
