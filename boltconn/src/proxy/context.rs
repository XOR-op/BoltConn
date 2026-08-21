use crate::adapter::{LinkGeneration, OutboundType};
use crate::common::evictable_vec::EvictableVec;
use crate::dispatch::ConnInfo;
use crate::platform::process::{NetworkType, ProcessInfo};
use arc_swap::ArcSwap;
use boltapi::{
    CapturedBodySchema, ConnDnsActivity, ConnFlow, ConnResultCode, ConnStage, ConnState,
    ConnTermination, DestinationResolution, DnsLookupDetail, IdentificationSource,
    IdentifiedTarget, LinkRef, RouteDecision,
};
pub use boltapi::{NetworkAddr, SessionProtocol};
use fast_socks5::util::target_addr::TargetAddr;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

pub fn network_addr_to_socks(value: NetworkAddr) -> TargetAddr {
    match value {
        NetworkAddr::Socket { address } => TargetAddr::Ip(address),
        NetworkAddr::Domain { name, port } => TargetAddr::Domain(name, port),
    }
}

pub fn socks_to_network_addr(value: TargetAddr) -> NetworkAddr {
    match value {
        TargetAddr::Ip(address) => NetworkAddr::Socket { address },
        TargetAddr::Domain(name, port) => NetworkAddr::Domain { name, port },
    }
}

/// The destination as accepted at the inbound boundary and after identification.
#[derive(Clone, Debug)]
pub struct ConnTarget {
    pub accepted: NetworkAddr,
    pub effective: NetworkAddr,
    pub identification: Option<IdentificationSource>,
}

impl ConnTarget {
    pub fn identified(
        accepted: NetworkAddr,
        effective: NetworkAddr,
        source: IdentificationSource,
    ) -> Self {
        Self {
            accepted,
            effective,
            identification: Some(source),
        }
    }
}

impl From<NetworkAddr> for ConnTarget {
    fn from(address: NetworkAddr) -> Self {
        Self {
            accepted: address.clone(),
            effective: address,
            identification: None,
        }
    }
}

// Abort Handle
#[derive(Clone, Debug)]
pub struct ConnAbortHandle(Arc<AbortHandle>);

#[derive(Copy, Clone, PartialEq, Debug)]
enum CancelState {
    NotReady,
    Ready,
    Cancelled,
}

#[derive(Debug)]
struct AbortHandle {
    handles: ArcSwap<Vec<(String, JoinHandle<()>)>>,
    state: AtomicU8,
    reason: Mutex<Option<ConnTermination>>,
}

const INIT: u8 = 0;
const EARLY_CANCELLED: u8 = 1;
const FULFILL_CHANGING: u8 = 2;
const READY: u8 = 3;
const CANCELLING: u8 = 4;
const CANCELLED: u8 = 5;

impl ConnAbortHandle {
    pub fn new() -> Self {
        Self(Arc::new(AbortHandle {
            handles: ArcSwap::new(Arc::new(vec![])),
            state: AtomicU8::new(INIT),
            reason: Mutex::new(None),
        }))
    }

    pub fn placeholder() -> Self {
        Self(Arc::new(AbortHandle {
            handles: ArcSwap::new(Arc::new(vec![])),
            state: AtomicU8::new(READY),
            reason: Mutex::new(None),
        }))
    }

    /// Records why sibling tasks are being aborted before triggering cancellation.
    /// The first reason wins so concurrent shutdown paths cannot rewrite the cause.
    pub(crate) fn cancel(&self, reason: ConnTermination) {
        let mut current = self.0.reason.lock().unwrap();
        if current.is_none() {
            *current = Some(reason);
        }
        drop(current);
        self.abort_tasks();
    }

    pub(crate) fn cancel_reason(&self) -> Option<ConnTermination> {
        self.0.reason.lock().unwrap().clone()
    }

    fn abort_tasks(&self) {
        loop {
            let state = self.0.state.load(Ordering::Acquire);
            match state {
                INIT => {
                    if self
                        .0
                        .state
                        .compare_exchange(
                            INIT,
                            EARLY_CANCELLED,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_err()
                    {
                        // maybe it's fulfilling
                        continue;
                    }
                    return;
                }
                READY => {
                    if self
                        .0
                        .state
                        .compare_exchange(READY, CANCELLING, Ordering::AcqRel, Ordering::Relaxed)
                        .is_err()
                    {
                        // other thread is cancelling
                        return;
                    }
                    for (_, handle) in self.0.handles.load().iter() {
                        handle.abort()
                    }
                    self.0
                        .state
                        .compare_exchange(
                            CANCELLING,
                            CANCELLED,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .unwrap();
                    return;
                }
                FULFILL_CHANGING => continue,
                EARLY_CANCELLED | CANCELLING | CANCELLED => return,
                _ => unreachable!(),
            }
        }
    }

    pub fn fulfill(&self, handles: Vec<(String, JoinHandle<()>)>) {
        if self
            .0
            .state
            .compare_exchange(INIT, FULFILL_CHANGING, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            if let Err(err) = self.0.state.compare_exchange(
                EARLY_CANCELLED,
                CANCELLING,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                tracing::error!("Fulfill a cancel handle twice from state{}!", err);
            } else {
                for (_, i) in handles.iter() {
                    i.abort()
                }
                self.0
                    .state
                    .compare_exchange(CANCELLING, CANCELLED, Ordering::AcqRel, Ordering::Relaxed)
                    .unwrap();
            }
        } else {
            self.0.handles.store(Arc::new(handles));
            // should not fail
            self.0
                .state
                .compare_exchange(FULFILL_CHANGING, READY, Ordering::AcqRel, Ordering::Relaxed)
                .unwrap();
        }
    }
}

/// Immutable metadata captured when a connection enters the dataplane.
#[derive(Clone, Debug)]
pub struct ConnMetadata {
    pub id: u64,
    pub started_at_ms: u64,
    pub start_time: SystemTime,
    pub conn_info: ConnInfo,
}

#[derive(Clone, Debug)]
pub struct ConnRecordState {
    pub state: ConnState,
    pub session_protocol: SessionProtocol,
    pub outbound_name: Option<String>,
    pub outbound_type: Option<OutboundType>,
    pub established_at_ms: Option<u64>,
    pub ended_at_ms: Option<u64>,
    pub flow: ConnFlow,
    pub route: Option<RouteDecision>,
    pub dns: ConnDnsActivity,
    pub links: Vec<LinkRef>,
    pub termination: Option<ConnTermination>,
}

/// A consistent view of one connection record at a point in time.
#[derive(Clone, Debug)]
pub struct ConnRecordSnapshot {
    pub start: ConnMetadata,
    pub state: ConnRecordState,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub last_active_ms: u64,
}

#[derive(Debug)]
struct ConnRecord {
    metadata: ConnMetadata,
    state: Mutex<ConnRecordState>,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    last_active_ms: AtomicU64,
    global_upload: Arc<AtomicU64>,
    global_download: Arc<AtomicU64>,
    abort_handle: ConnAbortHandle,
    link_dependencies: Mutex<Vec<Arc<LinkGeneration>>>,
    activation_owner: Mutex<Option<String>>,
}

/// The only mutable connection capability handed to dataplane callers.
///
/// Record state remains private so all terminal transitions go through `finish`
/// and can atomically update both the record and the manager's active index.
#[derive(Clone, Debug)]
pub struct ConnHandle {
    record: Arc<ConnRecord>,
    index: std::sync::Weak<ContextIndex>,
}

impl ConnHandle {
    fn new(record: Arc<ConnRecord>, index: &Arc<ContextIndex>) -> Self {
        Self {
            record,
            index: Arc::downgrade(index),
        }
    }

    pub fn id(&self) -> u64 {
        self.record.metadata.id
    }

    pub fn metadata(&self) -> &ConnMetadata {
        &self.record.metadata
    }

    pub fn snapshot(&self) -> ConnRecordSnapshot {
        ConnRecordSnapshot {
            start: self.record.metadata.clone(),
            state: self.record.state.lock().unwrap().clone(),
            upload_bytes: self.record.upload_bytes.load(Ordering::Relaxed),
            download_bytes: self.record.download_bytes.load(Ordering::Relaxed),
            last_active_ms: self.record.last_active_ms.load(Ordering::Relaxed),
        }
    }

    pub fn state(&self) -> ConnState {
        self.record.state.lock().unwrap().state
    }

    /// Moves a live record to another non-terminal lifecycle state.
    ///
    /// Returning `false` means the record has already completed, or the caller
    /// attempted to bypass `finish` with a terminal target state.
    pub fn set_state(&self, state: ConnState) -> bool {
        if is_terminal_state(state) {
            return false;
        }
        if state == ConnState::Active {
            return self.activate();
        }
        let mut current = self.record.state.lock().unwrap();
        if is_terminal_state(current.state) {
            return false;
        }
        current.state = state;
        true
    }

    /// Restricts activation to the destination-facing hop of a chain. Upstream
    /// shared hops may still publish dependency candidates without marking the
    /// child connection active before the whole chain is usable.
    pub(crate) fn set_activation_owner(&self, owner: String) -> bool {
        let state = self.record.state.lock().unwrap();
        if matches!(
            state.state,
            ConnState::Active
                | ConnState::Closing
                | ConnState::Closed
                | ConnState::Failed
                | ConnState::Rejected
        ) {
            return false;
        }
        *self.record.activation_owner.lock().unwrap() = Some(owner);
        true
    }

    pub(crate) fn activate_from(&self, owner: &str) -> bool {
        if self
            .record
            .activation_owner
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|expected| expected != owner)
        {
            return false;
        }
        self.activate()
    }

    fn activate(&self) -> bool {
        let dependencies = self.record.link_dependencies.lock().unwrap().clone();
        let mut registered = Vec::new();
        for dependency in &dependencies {
            if dependency.register_connection(self.clone()) {
                registered.push(dependency.clone());
            } else {
                for registered in registered {
                    registered.complete_connection(self.id(), None);
                }
                let reason = ConnTermination::new(
                    ConnResultCode::LinkLost,
                    ConnStage::Connecting,
                    Some("link generation ended before activation".to_string()),
                );
                self.finish(reason.code, reason.stage, reason.detail.clone());
                self.record.abort_handle.cancel(reason);
                return false;
            }
        }

        let mut state = self.record.state.lock().unwrap();
        if is_terminal_state(state.state) {
            drop(state);
            for registered in registered {
                registered.complete_connection(self.id(), None);
            }
            return false;
        }
        state.state = ConnState::Active;
        state.established_at_ms.get_or_insert_with(now_ms);
        true
    }

    pub fn update_proto(&self, packet: &[u8]) {
        let mut state = self.record.state.lock().unwrap();
        if is_terminal_state(state.state) {
            return;
        }
        if state.session_protocol == SessionProtocol::Tcp {
            state.session_protocol = check_tcp_protocol(packet);
        } else if state.session_protocol == SessionProtocol::Udp {
            state.session_protocol = check_udp_protocol(packet);
        }
    }

    pub fn set_protocol(&self, protocol: SessionProtocol) -> bool {
        let mut state = self.record.state.lock().unwrap();
        if is_terminal_state(state.state) {
            return false;
        }
        state.session_protocol = protocol;
        true
    }

    pub fn set_identified_target(&self, target: NetworkAddr, source: IdentificationSource) -> bool {
        let mut state = self.record.state.lock().unwrap();
        if is_terminal_state(state.state) {
            return false;
        }
        state.flow.identified = Some(IdentifiedTarget { target, source });
        true
    }

    pub fn set_resolution(&self, resolution: DestinationResolution) -> bool {
        let mut state = self.record.state.lock().unwrap();
        if is_terminal_state(state.state) {
            return false;
        }
        state.flow.resolution = resolution;
        true
    }

    pub fn set_route(&self, route: RouteDecision) -> bool {
        let mut state = self.record.state.lock().unwrap();
        if is_terminal_state(state.state) {
            return false;
        }
        state.route = Some(route);
        true
    }

    pub fn set_outbound(&self, name: String, outbound_type: OutboundType) -> bool {
        let mut state = self.record.state.lock().unwrap();
        if is_terminal_state(state.state) {
            return false;
        }
        state.outbound_name = Some(name);
        state.outbound_type = Some(outbound_type);
        true
    }

    /// Keeps the most complete route reported during chain construction. Once
    /// active, the path is frozen and registered with every generation in it.
    pub(crate) fn consider_link_path(&self, links: Vec<Arc<LinkGeneration>>) -> bool {
        let mut state = self.record.state.lock().unwrap();
        if matches!(
            state.state,
            ConnState::Active
                | ConnState::Closing
                | ConnState::Closed
                | ConnState::Failed
                | ConnState::Rejected
        ) {
            return false;
        }
        let mut current = self.record.link_dependencies.lock().unwrap();
        if links.len() <= current.len() {
            return false;
        }
        state.links = links.iter().map(|link| link.link_ref()).collect();
        *current = links;
        true
    }

    pub fn record_dns_lookup(&self, lookup: DnsLookupDetail) -> bool {
        let mut state = self.record.state.lock().unwrap();
        if is_terminal_state(state.state) {
            return false;
        }
        state.dns.total_lookups = state.dns.total_lookups.saturating_add(1);
        if self.record.metadata.conn_info.connection_type == NetworkType::Udp
            && state.dns.lookups.len() == 5
        {
            // Long-lived UDP sessions retain a bounded tail; TCP lookups are
            // naturally bounded by connection setup and remain complete.
            state.dns.lookups.remove(0);
        }
        state.dns.lookups.push(lookup);
        true
    }

    pub fn more_upload(&self, size: usize) {
        let size = size as u64;
        self.record.upload_bytes.fetch_add(size, Ordering::Relaxed);
        self.record.global_upload.fetch_add(size, Ordering::Relaxed);
        self.record
            .last_active_ms
            .store(now_ms(), Ordering::Relaxed);
    }

    pub fn more_download(&self, size: usize) {
        let size = size as u64;
        self.record
            .download_bytes
            .fetch_add(size, Ordering::Relaxed);
        self.record
            .global_download
            .fetch_add(size, Ordering::Relaxed);
        self.record
            .last_active_ms
            .store(now_ms(), Ordering::Relaxed);
    }

    /// Completes a record exactly once and immediately transfers index ownership
    /// from the active map to completion-ordered history.
    pub fn finish(
        &self,
        code: ConnResultCode,
        stage: Option<ConnStage>,
        detail: Option<String>,
    ) -> bool {
        let was_active = {
            let mut state = self.record.state.lock().unwrap();
            if is_terminal_state(state.state) {
                return false;
            }
            state.state = terminal_state_for(code);
            state.ended_at_ms = Some(now_ms());
            state.termination = Some(ConnTermination {
                code,
                stage,
                detail,
            });
            state.established_at_ms.is_some()
        };

        let traffic = was_active.then(|| {
            (
                self.record.upload_bytes.load(Ordering::Relaxed),
                self.record.download_bytes.load(Ordering::Relaxed),
                self.record.last_active_ms.load(Ordering::Relaxed),
            )
        });
        for dependency in self.record.link_dependencies.lock().unwrap().iter() {
            dependency.complete_connection(self.id(), traffic);
        }

        // Never hold the record-state lock while taking the manager index lock.
        // Snapshotting uses the opposite phases, so this rule avoids lock cycles.
        if let Some(index) = self.index.upgrade() {
            index.finish(self.record.clone());
        }
        true
    }

    pub fn done(&self) -> bool {
        is_terminal_state(self.state())
    }

    pub fn abort(&self) -> bool {
        self.set_state(ConnState::Closing);
        let reason = ConnTermination::new(ConnResultCode::UserStopped, ConnStage::Closing, None);
        let completed = self.finish(reason.code, reason.stage, reason.detail.clone());
        if completed {
            self.record.abort_handle.cancel(reason);
        }
        completed
    }

    pub(crate) fn finish_for_link(&self, result: ConnResultCode) -> bool {
        self.set_state(ConnState::Closing);
        let reason = ConnTermination::new(result, ConnStage::Closing, None);
        let completed = self.finish(reason.code, reason.stage, reason.detail.clone());
        self.record.abort_handle.cancel(reason);
        completed
    }
}

fn system_time_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn now_ms() -> u64 {
    system_time_ms(SystemTime::now())
}

pub(crate) fn bounded_error_detail(detail: &str) -> String {
    detail
        .chars()
        .filter_map(|character| {
            if character.is_control() {
                character.is_whitespace().then_some(' ')
            } else {
                Some(character)
            }
        })
        .take(256)
        .collect()
}

fn is_terminal_state(state: ConnState) -> bool {
    matches!(
        state,
        ConnState::Closed | ConnState::Failed | ConnState::Rejected
    )
}

fn terminal_state_for(code: ConnResultCode) -> ConnState {
    match code {
        ConnResultCode::RouteRejected | ConnResultCode::Blackholed => ConnState::Rejected,
        ConnResultCode::Completed
        | ConnResultCode::ClientClosed
        | ConnResultCode::RemoteClosed
        | ConnResultCode::UserStopped
        | ConnResultCode::LinkStopped
        | ConnResultCode::LinkReconfigured
        | ConnResultCode::LinkRemoved
        | ConnResultCode::LinkLost => ConnState::Closed,
        ConnResultCode::DnsTimeout
        | ConnResultCode::DnsError
        | ConnResultCode::ConnectTimeout
        | ConnResultCode::ConnectError
        | ConnResultCode::HandshakeError
        | ConnResultCode::TransferError
        | ConnResultCode::InternalError => ConnState::Failed,
    }
}

/// The packet as argument should be the first packet of the connection
pub fn check_tcp_protocol(packet: &[u8]) -> SessionProtocol {
    // TLS handshake
    if packet.len() > 5 && packet[0] == 22 && packet[1] == 3 {
        return match packet[2] {
            0..=4 => SessionProtocol::Tls,
            _ => SessionProtocol::Tcp, // unknown
        };
    }
    // HTTP request line
    if let Some(idx) = packet.iter().position(|&b| b == b'\r')
        && idx + 1 < packet.len()
        && packet[idx + 1] == b'\n'
    {
        // contains a request line
        let request_line = &packet[0..idx];
        if request_line.ends_with("HTTP/1.1".as_bytes()) {
            // we just ignore legacy versions
            return SessionProtocol::Http;
        }
    }
    // Unknown
    SessionProtocol::Tcp
}

/// The packet as argument should be the first packet of the connection
pub fn check_udp_protocol(packet: &[u8]) -> SessionProtocol {
    if packet.len() >= 16
        && (packet[0] & 0xf0 == 0xc0
            && packet[1] == 0
            && packet[2] == 0
            && packet[3] == 0
            && (packet[4] == 1 || packet[4] == 2))
    {
        // conservative idetification
        SessionProtocol::Quic
    } else {
        SessionProtocol::Udp
    }
}

pub struct ContextManager {
    index: Arc<ContextIndex>,
    global_upload: Arc<AtomicU64>,
    global_download: Arc<AtomicU64>,
    unique_id_cnt: AtomicU64,
}

#[derive(Debug)]
struct ContextIndex {
    inner: RwLock<ContextIndexInner>,
}

#[derive(Debug)]
struct ContextIndexInner {
    active: HashMap<u64, Arc<ConnRecord>>,
    terminal: VecDeque<Arc<ConnRecord>>,
    history_limit: u32,
}

impl ContextManager {
    pub fn new(history_limit: u32) -> Self {
        Self {
            index: Arc::new(ContextIndex {
                inner: RwLock::new(ContextIndexInner {
                    active: HashMap::new(),
                    terminal: VecDeque::new(),
                    history_limit,
                }),
            }),
            global_upload: Arc::new(Default::default()),
            global_download: Arc::new(Default::default()),
            unique_id_cnt: Default::default(),
        }
    }

    /// Registers a connection before any fallible inspection or routing work.
    pub fn begin(
        &self,
        conn_info: ConnInfo,
        accepted_target: NetworkAddr,
        parsed_session_proto: Option<SessionProtocol>,
        abort_handle: ConnAbortHandle,
    ) -> ConnHandle {
        let id = self.unique_id_cnt.fetch_add(1, Ordering::Relaxed);
        let start_time = SystemTime::now();
        let session_protocol = parsed_session_proto.unwrap_or(match conn_info.connection_type {
            NetworkType::Tcp => SessionProtocol::Tcp,
            NetworkType::Udp => SessionProtocol::Udp,
        });
        let flow = ConnFlow {
            inbound: conn_info.inbound.to_string(),
            source: conn_info.src,
            accepted: accepted_target,
            identified: None,
            resolution: match (conn_info.resolved_dst, &conn_info.dst) {
                (Some(address), _) => DestinationResolution::Resolved { address },
                (None, NetworkAddr::Socket { .. }) => DestinationResolution::NotRequired,
                (None, NetworkAddr::Domain { .. }) => DestinationResolution::NotStarted,
            },
        };
        let record = Arc::new(ConnRecord {
            metadata: ConnMetadata {
                id,
                started_at_ms: system_time_ms(start_time),
                start_time,
                conn_info,
            },
            state: Mutex::new(ConnRecordState {
                state: ConnState::Accepted,
                session_protocol,
                outbound_name: None,
                outbound_type: None,
                established_at_ms: None,
                ended_at_ms: None,
                flow,
                route: None,
                dns: ConnDnsActivity {
                    total_lookups: 0,
                    lookups: Vec::new(),
                },
                links: Vec::new(),
                termination: None,
            }),
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
            last_active_ms: AtomicU64::new(system_time_ms(start_time)),
            global_upload: self.global_upload.clone(),
            global_download: self.global_download.clone(),
            abort_handle,
            link_dependencies: Mutex::new(Vec::new()),
            activation_owner: Mutex::new(None),
        });
        self.index
            .inner
            .write()
            .unwrap()
            .active
            .insert(id, record.clone());
        ConnHandle::new(record, &self.index)
    }

    pub fn get_upload(&self) -> Arc<AtomicU64> {
        self.global_upload.clone()
    }

    pub fn get_download(&self) -> Arc<AtomicU64> {
        self.global_download.clone()
    }

    pub fn get_conn_history_limit(&self) -> u32 {
        self.index.inner.read().unwrap().history_limit
    }

    pub fn set_conn_history_limit(&self, limit: u32) {
        let mut inner = self.index.inner.write().unwrap();
        inner.history_limit = limit;
        inner.evict_terminal_history();
    }

    /// Clones record handles while holding the index lock. Callers can then
    /// snapshot cold record state without blocking new begin/finish operations.
    pub fn active_records(&self) -> Vec<ConnHandle> {
        let mut records: Vec<_> = self
            .index
            .inner
            .read()
            .unwrap()
            .active
            .values()
            .cloned()
            .collect();
        records.sort_unstable_by_key(|record| record.metadata.id);
        records
            .into_iter()
            .map(|record| ConnHandle::new(record, &self.index))
            .collect()
    }

    pub fn terminal_records(&self) -> Vec<ConnHandle> {
        self.index
            .inner
            .read()
            .unwrap()
            .terminal
            .iter()
            .cloned()
            .map(|record| ConnHandle::new(record, &self.index))
            .collect()
    }

    pub async fn get_nth(&self, id: u64) -> Option<ConnHandle> {
        self.get(id)
    }

    pub fn get(&self, id: u64) -> Option<ConnHandle> {
        let inner = self.index.inner.read().unwrap();
        inner
            .active
            .get(&id)
            .or_else(|| {
                inner
                    .terminal
                    .iter()
                    .find(|record| record.metadata.id == id)
            })
            .cloned()
            .map(|record| ConnHandle::new(record, &self.index))
    }

    /// Stops only live records. A completion racing this call wins according to
    /// the same first-terminal-result rule as every other terminal path.
    pub fn stop(&self, id: u64) -> bool {
        let record = self.index.inner.read().unwrap().active.get(&id).cloned();
        record
            .map(|record| ConnHandle::new(record, &self.index).abort())
            .unwrap_or(false)
    }

    /// Returns only currently active connections whose frozen dependency path
    /// contains the named link. Terminal history is intentionally excluded.
    pub(crate) fn get_active_for_link(&self, name: &str) -> Vec<ConnHandle> {
        let records: Vec<_> = self
            .index
            .inner
            .read()
            .unwrap()
            .active
            .values()
            .cloned()
            .collect();
        let mut matching: Vec<_> = records
            .into_iter()
            .filter(|record| {
                let state = record.state.lock().unwrap();
                state.state == ConnState::Active && state.links.iter().any(|link| link.name == name)
            })
            .map(|record| ConnHandle::new(record, &self.index))
            .collect();
        matching.sort_unstable_by_key(ConnHandle::id);
        matching
    }
}

impl ContextIndex {
    fn finish(&self, record: Arc<ConnRecord>) {
        let mut inner = self.inner.write().unwrap();
        let id = record.metadata.id;
        let owns_active_entry = inner
            .active
            .get(&id)
            .is_some_and(|active| Arc::ptr_eq(active, &record));
        if !owns_active_entry {
            return;
        }
        inner.active.remove(&id);
        if inner.history_limit != 0 {
            // Records are appended only after their terminal state is committed,
            // making deque order completion order rather than start order.
            inner.terminal.push_back(record);
            inner.evict_terminal_history();
        }
    }
}

impl ContextIndexInner {
    fn evict_terminal_history(&mut self) {
        let limit = self.history_limit as usize;
        while self.terminal.len() > limit {
            self.terminal.pop_front();
        }
    }
}

#[cfg(test)]
mod connection_record_tests {
    use super::*;
    use crate::dispatch::InboundInfo;
    use std::net::SocketAddr;
    use std::sync::Barrier;

    fn begin_test_connection(manager: &ContextManager, port: u16) -> ConnHandle {
        manager.begin(
            ConnInfo {
                src: SocketAddr::from(([127, 0, 0, 1], port)),
                dst: NetworkAddr::from(SocketAddr::from(([127, 0, 0, 1], 443))),
                local_ip: None,
                inbound: InboundInfo::Tun,
                resolved_dst: None,
                connection_type: NetworkType::Tcp,
                process_info: None,
            },
            NetworkAddr::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            None,
            ConnAbortHandle::placeholder(),
        )
    }

    #[test]
    fn ids_are_monotonic_and_active_snapshots_are_stable() {
        let manager = ContextManager::new(10);
        let first = begin_test_connection(&manager, 10_001);
        let second = begin_test_connection(&manager, 10_002);
        let third = begin_test_connection(&manager, 10_003);

        assert_eq!((first.id(), second.id(), third.id()), (0, 1, 2));
        assert_eq!(
            manager
                .active_records()
                .iter()
                .map(ConnHandle::id)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn transitions_cannot_bypass_or_leave_a_terminal_state() {
        let manager = ContextManager::new(10);
        let handle = begin_test_connection(&manager, 10_001);

        assert!(handle.set_state(ConnState::Inspecting));
        assert!(handle.set_state(ConnState::Active));
        assert!(!handle.set_state(ConnState::Closed));
        assert_eq!(handle.state(), ConnState::Active);
        assert!(handle.finish(ConnResultCode::Completed, None, None));
        assert!(!handle.set_state(ConnState::Closing));
        assert!(!handle.finish(
            ConnResultCode::TransferError,
            Some(ConnStage::Transferring),
            None,
        ));

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.state.state, ConnState::Closed);
        assert_eq!(
            snapshot.state.termination.unwrap().code,
            ConnResultCode::Completed
        );
    }

    #[test]
    fn flow_keeps_accepted_and_identified_targets_distinct() {
        let manager = ContextManager::new(10);
        let accepted = NetworkAddr::from(SocketAddr::from(([198, 18, 0, 7], 443)));
        let identified = NetworkAddr::Domain {
            name: "example.com".to_string(),
            port: 443,
        };
        let handle = manager.begin(
            ConnInfo {
                src: SocketAddr::from(([127, 0, 0, 1], 10_001)),
                dst: identified.clone(),
                local_ip: None,
                inbound: InboundInfo::Tun,
                resolved_dst: None,
                connection_type: NetworkType::Tcp,
                process_info: None,
            },
            accepted.clone(),
            None,
            ConnAbortHandle::placeholder(),
        );
        assert!(
            handle.set_identified_target(identified.clone(), IdentificationSource::FakeIpMapping,)
        );

        let flow = handle.snapshot().state.flow;
        assert_eq!(flow.accepted, accepted);
        let observed = flow.identified.unwrap();
        assert_eq!(observed.target, identified);
        assert_eq!(observed.source, IdentificationSource::FakeIpMapping);
    }

    #[test]
    fn finish_moves_records_immediately_in_completion_order() {
        let manager = ContextManager::new(10);
        let first = begin_test_connection(&manager, 10_001);
        let second = begin_test_connection(&manager, 10_002);

        assert!(second.finish(ConnResultCode::Completed, None, None));
        assert!(first.finish(ConnResultCode::Completed, None, None));
        assert!(manager.active_records().is_empty());
        assert_eq!(
            manager
                .terminal_records()
                .iter()
                .map(ConnHandle::id)
                .collect::<Vec<_>>(),
            vec![1, 0]
        );
    }

    #[test]
    fn history_limit_changes_evict_oldest_records_immediately() {
        let manager = ContextManager::new(3);
        for port in 10_001..=10_003 {
            assert!(begin_test_connection(&manager, port).finish(
                ConnResultCode::Completed,
                None,
                None,
            ));
        }

        manager.set_conn_history_limit(2);
        assert_eq!(
            manager
                .terminal_records()
                .iter()
                .map(ConnHandle::id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        manager.set_conn_history_limit(0);
        assert!(manager.terminal_records().is_empty());
    }

    #[test]
    fn zero_history_never_removes_active_records() {
        let manager = ContextManager::new(0);
        let completed = begin_test_connection(&manager, 10_001);
        let active = begin_test_connection(&manager, 10_002);

        assert!(completed.finish(ConnResultCode::Completed, None, None));
        assert!(manager.terminal_records().is_empty());
        assert_eq!(manager.active_records()[0].id(), active.id());
    }

    #[test]
    fn concurrent_completion_has_exactly_one_winner() {
        let manager = ContextManager::new(10);
        let handle = begin_test_connection(&manager, 10_001);
        let barrier = Arc::new(Barrier::new(3));

        let wins = std::thread::scope(|scope| {
            let first_handle = handle.clone();
            let first_barrier = barrier.clone();
            let first = scope.spawn(move || {
                first_barrier.wait();
                first_handle.finish(ConnResultCode::Completed, None, None)
            });
            let second_handle = handle.clone();
            let second_barrier = barrier.clone();
            let second = scope.spawn(move || {
                second_barrier.wait();
                second_handle.finish(
                    ConnResultCode::TransferError,
                    Some(ConnStage::Transferring),
                    None,
                )
            });
            barrier.wait();
            usize::from(first.join().unwrap()) + usize::from(second.join().unwrap())
        });

        assert_eq!(wins, 1);
        assert!(manager.active_records().is_empty());
        assert_eq!(manager.terminal_records().len(), 1);
        assert!(matches!(
            handle.snapshot().state.termination.unwrap().code,
            ConnResultCode::Completed | ConnResultCode::TransferError
        ));
    }

    #[test]
    fn stop_only_succeeds_for_a_live_record() {
        let manager = ContextManager::new(10);
        let handle = begin_test_connection(&manager, 10_001);

        assert!(manager.stop(handle.id()));
        assert!(!manager.stop(handle.id()));
        assert!(!manager.stop(u64::MAX));
        assert_eq!(
            manager
                .get(handle.id())
                .unwrap()
                .snapshot()
                .state
                .termination
                .unwrap()
                .code,
            ConnResultCode::UserStopped
        );
    }

    fn test_dns_lookup(name: &str) -> DnsLookupDetail {
        DnsLookupDetail {
            purpose: boltapi::DnsLookupPurpose::Destination,
            name: name.to_string(),
            selection: boltapi::DnsSelection::Hosts,
            cache: boltapi::DnsCacheStatus::NotApplicable,
            attempts: Vec::new(),
            answers: Vec::new(),
            result: boltapi::DnsOutcome::Answered {
                response: boltapi::DnsResponseKind::NoData,
            },
            duration_ms: 0,
        }
    }

    #[test]
    fn udp_dns_evidence_keeps_latest_five_and_preserves_total() {
        let manager = ContextManager::new(10);
        let target = NetworkAddr::from(SocketAddr::from(([127, 0, 0, 1], 443)));
        let udp = manager.begin(
            ConnInfo {
                src: SocketAddr::from(([127, 0, 0, 1], 10_001)),
                dst: target.clone(),
                local_ip: None,
                inbound: InboundInfo::Tun,
                resolved_dst: None,
                connection_type: NetworkType::Udp,
                process_info: None,
            },
            target,
            None,
            ConnAbortHandle::placeholder(),
        );
        for index in 0..7 {
            assert!(udp.record_dns_lookup(test_dns_lookup(&format!("name-{index}"))));
        }

        let activity = udp.snapshot().state.dns;
        assert_eq!(activity.total_lookups, 7);
        assert_eq!(activity.lookups.len(), 5);
        assert_eq!(activity.lookups[0].name, "name-2");
        assert_eq!(activity.lookups[4].name, "name-6");
    }

    #[test]
    fn tcp_dns_evidence_retains_every_lookup() {
        let manager = ContextManager::new(10);
        let tcp = begin_test_connection(&manager, 10_001);
        for index in 0..7 {
            assert!(tcp.record_dns_lookup(test_dns_lookup(&format!("name-{index}"))));
        }

        let activity = tcp.snapshot().state.dns;
        assert_eq!(activity.total_lookups, 7);
        assert_eq!(activity.lookups.len(), 7);
    }
}

#[derive(Clone, Debug)]
pub enum CapturedBody {
    FullCapture(hyper::body::Bytes),
    ExceedLimit(String),
    NoCapture,
}

impl CapturedBody {
    pub fn to_captured_schema(&self) -> CapturedBodySchema {
        match self {
            CapturedBody::FullCapture(bytes) => CapturedBodySchema::Body {
                content: bytes.to_vec(),
            },
            CapturedBody::ExceedLimit(s) => CapturedBodySchema::Warning { content: s.clone() },
            CapturedBody::NoCapture => CapturedBodySchema::Empty,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DumpedRequest {
    pub uri: http::Uri,
    pub method: http::Method,
    pub version: http::Version,
    pub headers: http::HeaderMap<http::HeaderValue>,
    pub body: CapturedBody,
    pub time: SystemTime,
}

impl DumpedRequest {
    pub fn from_parts(parts: &http::request::Parts, body: CapturedBody) -> Self {
        Self {
            uri: parts.uri.clone(),
            method: parts.method.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
            body,
            time: SystemTime::now(),
        }
    }

    pub fn collect_headers(&self) -> Vec<String> {
        self.headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("INVALID NON-ASCII DATA")))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct DumpedResponse {
    pub status: http::StatusCode,
    pub version: http::Version,
    pub headers: http::HeaderMap<http::HeaderValue>,
    pub body: CapturedBody,
    pub time: SystemTime,
}

impl DumpedResponse {
    pub fn from_parts(parts: &http::response::Parts, body: CapturedBody) -> Self {
        Self {
            status: parts.status,
            version: parts.version,
            headers: parts.headers.clone(),
            body,
            time: SystemTime::now(),
        }
    }

    pub fn collect_headers(&self) -> Vec<String> {
        self.headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("INVALID NON-ASCII DATA")))
            .collect()
    }

    pub fn body_len(&self) -> Option<u64> {
        match &self.body {
            CapturedBody::FullCapture(b) => Some(b.len() as u64),
            CapturedBody::ExceedLimit(_) | CapturedBody::NoCapture => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpInterceptData {
    pub host: String,
    pub process_info: Option<ProcessInfo>,
    pub req: DumpedRequest,
    pub resp: DumpedResponse,
}

impl HttpInterceptData {
    pub fn new(
        host: String,
        process_info: Option<ProcessInfo>,
        req: DumpedRequest,
        resp: DumpedResponse,
    ) -> Self {
        Self {
            host,
            process_info,
            req,
            resp,
        }
    }

    pub fn get_full_uri(&self) -> String {
        let s = self.req.uri.to_string();
        if s.starts_with("https://") || s.starts_with("http://") {
            // http2
            s
        } else {
            // http1.1, with no host in uri field
            self.host.clone() + s.as_str()
        }
    }
}

pub struct HttpCapturer {
    inner: Mutex<HttpCapturerInner>,
}

struct HttpCapturerInner {
    /// how many elements are allowed to return to caller
    keep_count: usize,
    // how many extra elements are allowed to reside in memory before eviction.
    grace_threshold: usize,
    contents: EvictableVec<HttpInterceptData>,
}

impl HttpCapturer {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HttpCapturerInner {
                keep_count: 20,
                grace_threshold: 3,
                contents: EvictableVec::new(),
            }),
        }
    }

    pub fn push(
        &self,
        pair: (DumpedRequest, DumpedResponse),
        host: String,
        client: Option<ProcessInfo>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.evict();
        inner
            .contents
            .push(HttpInterceptData::new(host, client, pair.0, pair.1))
    }

    pub fn get_copy(&self) -> (Vec<HttpInterceptData>, usize) {
        let inner = self.inner.lock().unwrap();
        (
            inner.get_allowed_elements(),
            minimum_start(inner.contents.logical_len(), inner.keep_count),
        )
    }

    #[allow(clippy::type_complexity)]
    pub fn get_range_copy(
        &self,
        start: usize,
        end: Option<usize>,
    ) -> Option<(Vec<HttpInterceptData>, usize)> {
        let inner = self.inner.lock().unwrap();
        let allowed_start = minimum_start(inner.contents.logical_len(), inner.keep_count);

        let start = if start >= allowed_start {
            start
        } else {
            allowed_start
        };
        // check if the range is valid logically
        if start >= inner.contents.logical_len()
            || (end.is_some()
                && (end.unwrap() > inner.contents.logical_len() || start >= end.unwrap()))
        {
            return None;
        }
        Some((
            inner.contents.logical_slice(start, end).to_vec(),
            allowed_start,
        ))
    }
}

impl HttpCapturerInner {
    fn get_allowed_elements(&self) -> Vec<HttpInterceptData> {
        self.contents.get_last_n(self.keep_count)
    }

    fn evict(&mut self) {
        if self.contents.real_len() > self.keep_count + self.grace_threshold {
            self.contents.evict_with(self.keep_count, |_| {})
        }
    }
}

fn minimum_start(logical_len: usize, limit: usize) -> usize {
    logical_len.saturating_sub(limit)
}
