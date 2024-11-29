use crate::adapter::OutboundType;
use crate::common::evictable_vec::EvictableVec;
use crate::config::RawServerAddr;
use crate::dispatch::InboundInfo;
use crate::external::DatabaseHandle;
use crate::platform::process::{NetworkType, ProcessInfo};
use arc_swap::ArcSwap;
use boltapi::CapturedBodySchema;
use fast_socks5::util::target_addr::TargetAddr;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime};
use tokio::task::JoinHandle;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProtocol {
    Tcp,
    Udp,
    Http,
    Tls(TlsVersion),
    Quic(u8),
}

impl Display for SessionProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionProtocol::Tcp => f.write_str("tcp"),
            SessionProtocol::Udp => f.write_str("udp"),
            SessionProtocol::Http => f.write_str("http"),
            SessionProtocol::Tls(_) => f.write_str("tls"),
            SessionProtocol::Quic(_) => f.write_str("quic"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Ssl30,
    Tls,
}

/// Domain name with port or pure socket address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkAddr {
    Raw(SocketAddr),
    DomainName { domain_name: String, port: u16 },
}

impl Display for NetworkAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkAddr::Raw(addr) => f.write_str(format!("{}", addr).as_str()),
            NetworkAddr::DomainName { domain_name, port } => {
                f.write_str(format!("{}:{}", domain_name, port).as_str())
            }
        }
    }
}

impl From<NetworkAddr> for TargetAddr {
    fn from(value: NetworkAddr) -> Self {
        match value {
            NetworkAddr::Raw(s) => TargetAddr::Ip(s),
            NetworkAddr::DomainName { domain_name, port } => TargetAddr::Domain(domain_name, port),
        }
    }
}

impl From<TargetAddr> for NetworkAddr {
    fn from(value: TargetAddr) -> Self {
        match value {
            TargetAddr::Ip(s) => NetworkAddr::Raw(s),
            TargetAddr::Domain(domain_name, port) => NetworkAddr::DomainName { domain_name, port },
        }
    }
}

impl NetworkAddr {
    pub fn port(&self) -> u16 {
        match self {
            NetworkAddr::Raw(ad) => ad.port(),
            NetworkAddr::DomainName {
                domain_name: _,
                port,
            } => *port,
        }
    }

    pub fn definitely_not_equal(&self, rhs: &NetworkAddr) -> bool {
        match &self {
            NetworkAddr::Raw(s1) => match rhs {
                NetworkAddr::Raw(s2) => s1 != s2,
                NetworkAddr::DomainName {
                    domain_name: _,
                    port,
                } => s1.port() != *port,
            },
            NetworkAddr::DomainName { domain_name, port } => match rhs {
                NetworkAddr::Raw(s) => s.port() != *port,
                NetworkAddr::DomainName {
                    domain_name: d2,
                    port: p2,
                } => domain_name != d2 || *port != *p2,
            },
        }
    }

    pub fn from(addr: &RawServerAddr, port: u16) -> Self {
        match addr {
            RawServerAddr::IpAddr(ip) => Self::Raw(SocketAddr::new(*ip, port)),
            RawServerAddr::DomainName(dn) => Self::DomainName {
                domain_name: dn.clone(),
                port,
            },
        }
    }
}

impl FromStr for NetworkAddr {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (left, right) = s.split_once(':').ok_or(())?;
        let port = right.parse::<u16>().map_err(|_| ())?;
        if let Ok(addr) = left.parse::<IpAddr>() {
            Ok(NetworkAddr::Raw(SocketAddr::new(addr, port)))
        } else {
            Ok(NetworkAddr::DomainName {
                domain_name: left.to_string(),
                port,
            })
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
        }))
    }

    pub fn placeholder() -> Self {
        Self(Arc::new(AbortHandle {
            handles: ArcSwap::new(Arc::new(vec![])),
            state: AtomicU8::new(READY),
        }))
    }

    pub fn cancel(&self) {
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

// Info about one connection
#[derive(Debug)]
pub struct ConnContext {
    pub id: u64,
    pub start_time: SystemTime,
    pub dest: NetworkAddr,
    pub process_info: Option<ProcessInfo>,
    pub inbound_info: InboundInfo,

    // Will change
    pub session_proto: RwLock<SessionProtocol>,
    pub outbound_name: String,
    pub outbound_type: OutboundType,
    pub upload_traffic: AtomicU64,
    pub download_traffic: AtomicU64,
    pub done: AtomicBool,
    global_upload: Arc<AtomicU64>,
    global_download: Arc<AtomicU64>,
    abort_handle: ConnAbortHandle,
    notify_handle: Arc<AtomicBool>,
}

impl ConnContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        // static info
        id: u64,
        dst: NetworkAddr,
        process_info: Option<ProcessInfo>,
        inbound_info: InboundInfo,
        outbound_name: String,
        outbound_type: OutboundType,
        network_type: NetworkType,
        // runtime handle
        abort_handle: ConnAbortHandle,
        global_upload: Arc<AtomicU64>,
        global_download: Arc<AtomicU64>,
        notify_handle: Arc<AtomicBool>,
    ) -> Self {
        Self {
            id,
            start_time: SystemTime::now(),
            dest: dst,
            inbound_info,
            process_info,
            session_proto: std::sync::RwLock::new(match network_type {
                NetworkType::Tcp => SessionProtocol::Tcp,
                NetworkType::Udp => SessionProtocol::Udp,
            }),
            outbound_name,
            outbound_type,
            upload_traffic: AtomicU64::new(0),
            download_traffic: AtomicU64::new(0),
            done: AtomicBool::new(false),
            global_upload,
            global_download,
            abort_handle,
            notify_handle,
        }
    }

    pub fn update_proto(&self, packet: &[u8]) {
        let mut lock = self.session_proto.write().unwrap();
        if *lock == SessionProtocol::Tcp {
            *lock = check_tcp_protocol(packet);
        } else if *lock == SessionProtocol::Udp {
            *lock = check_udp_protocol(packet)
        }
    }

    pub fn more_upload(&self, size: usize) {
        self.upload_traffic
            .fetch_add(size as u64, Ordering::Relaxed);
        self.global_upload.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn more_download(&self, size: usize) {
        self.download_traffic
            .fetch_add(size as u64, Ordering::Relaxed);
        self.global_download
            .fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn mark_fin(&self) {
        self.done.store(true, Ordering::Relaxed);
        self.notify_handle.store(true, Ordering::Relaxed);
    }

    pub fn abort(&self) {
        self.abort_handle.cancel();
        self.mark_fin();
    }
}

/// The packet as argument should be the first packet of the connection
pub fn check_tcp_protocol(packet: &[u8]) -> SessionProtocol {
    // TLS handshake
    if packet.len() > 5 && packet[0] == 22 && packet[1] == 3 {
        return match packet[2] {
            1..=4 => SessionProtocol::Tls(TlsVersion::Tls),
            0 => SessionProtocol::Tls(TlsVersion::Ssl30),
            _ => SessionProtocol::Tcp, // unknown
        };
    }
    // HTTP request line
    if let Some(idx) = packet.iter().position(|&b| b == b'\r') {
        if idx + 1 < packet.len() && packet[idx + 1] == b'\n' {
            // contains a request line
            let request_line = &packet[0..idx];
            if request_line.ends_with("HTTP/1.1".as_bytes()) {
                // we just ignore legacy versions
                return SessionProtocol::Http;
            }
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
        SessionProtocol::Quic(packet[4])
    } else {
        SessionProtocol::Udp
    }
}

pub struct ContextManager {
    inner: RwLock<ContextManagerInner>,
    global_upload: Arc<AtomicU64>,
    global_download: Arc<AtomicU64>,
    notify_handle: Arc<AtomicBool>,
    unique_id_cnt: AtomicU64,
}

struct ContextManagerInner {
    active_ctx: HashMap<u64, Arc<ConnContext>>,
    inactive_ctx: EvictableVec<Arc<ConnContext>>,
    log_limit: u32,
    grace_threshold: usize,
    db_handle: Option<DatabaseHandle>,
}

impl ContextManager {
    pub fn new(db_handle: Option<DatabaseHandle>, log_limit: u32) -> Self {
        Self {
            inner: RwLock::new(ContextManagerInner {
                active_ctx: Default::default(),
                inactive_ctx: EvictableVec::new(),
                log_limit,
                grace_threshold: 5,
                db_handle,
            }),
            global_upload: Arc::new(Default::default()),
            global_download: Arc::new(Default::default()),
            notify_handle: Arc::new(AtomicBool::new(false)),
            unique_id_cnt: Default::default(),
        }
    }

    pub fn alloc_unique_id(&self) -> u64 {
        self.unique_id_cnt.fetch_add(1, Ordering::Relaxed)
    }

    pub fn get_upload(&self) -> Arc<AtomicU64> {
        self.global_upload.clone()
    }

    pub fn get_download(&self) -> Arc<AtomicU64> {
        self.global_download.clone()
    }

    pub fn get_notify_handle(&self) -> Arc<AtomicBool> {
        self.notify_handle.clone()
    }

    pub fn get_conn_log_limit(&self) -> u32 {
        self.inner.read().unwrap().log_limit
    }

    pub fn set_conn_log_limit(&self, limit: u32) {
        self.inner.write().unwrap().log_limit = limit;
    }

    pub fn push(&self, info: Arc<ConnContext>) {
        let mut inner = self.inner.write().unwrap();
        inner.active_ctx.insert(info.id, info);
        let process_active = self.notify_handle.swap(false, Ordering::Relaxed);
        inner.evict(process_active);
    }

    pub fn get_active_copy(&self) -> Vec<Arc<ConnContext>> {
        self.inner
            .read()
            .unwrap()
            .active_ctx
            .values()
            .cloned()
            .collect()
    }

    pub fn get_inactive_copy(&self) -> Vec<Arc<ConnContext>> {
        self.inner.read().unwrap().inactive_ctx.as_vec()
    }

    pub async fn get_nth(&self, idx: u64) -> Option<Arc<ConnContext>> {
        self.inner.read().unwrap().active_ctx.get(&idx).cloned()
    }
}

impl ContextManagerInner {
    fn evict(&mut self, process_active: bool) {
        let log_limit = self.log_limit as usize;
        if process_active {
            let mut to_remove = vec![];
            for (id, ctx) in self.active_ctx.iter() {
                if ctx.done.load(Ordering::Relaxed) {
                    to_remove.push(*id);
                    self.inactive_ctx.push(ctx.clone());
                }
            }
            self.active_ctx.retain(|k, _| !to_remove.contains(k));
        }
        if self.inactive_ctx.real_len() > log_limit + self.grace_threshold {
            self.inactive_ctx.evict_until(
                |_c, left| -> bool { left > log_limit },
                |data| {
                    if let Some(handle) = &mut self.db_handle {
                        handle.add_connections(data)
                    }
                },
            );
        }
    }
}

impl Drop for ContextManagerInner {
    fn drop(&mut self) {
        let active_list: Vec<_> = self.active_ctx.values().cloned().collect();
        if let Some(handle) = &mut self.db_handle {
            handle.add_connections(active_list)
        }
        self.inactive_ctx.evict_with(0, |data| {
            if let Some(handle) = &mut self.db_handle {
                handle.add_connections(data)
            }
        })
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
    pub time: Instant,
}

impl DumpedRequest {
    pub fn from_parts(parts: &http::request::Parts, body: CapturedBody) -> Self {
        Self {
            uri: parts.uri.clone(),
            method: parts.method.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
            body,
            time: Instant::now(),
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
    pub time: Instant,
}

impl DumpedResponse {
    pub fn from_parts(parts: &http::response::Parts, body: CapturedBody) -> Self {
        Self {
            status: parts.status,
            version: parts.version,
            headers: parts.headers.clone(),
            body,
            time: Instant::now(),
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
    // how many extra elements are allowed to reside in memory, in order to reduce database operation times.
    grace_threshold: usize,
    contents: EvictableVec<HttpInterceptData>,
    db_handle: Option<DatabaseHandle>,
}

impl HttpCapturer {
    pub fn new(db_handle: Option<DatabaseHandle>) -> Self {
        Self {
            inner: Mutex::new(HttpCapturerInner {
                keep_count: 20,
                grace_threshold: 3,
                contents: EvictableVec::new(),
                db_handle,
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
            self.contents.evict_with(self.keep_count, |data| {
                if let Some(handle) = &mut self.db_handle {
                    handle.add_interceptions(data)
                }
            })
        }
    }
}

impl Drop for HttpCapturerInner {
    fn drop(&mut self) {
        self.contents.evict_with(0, |data| {
            if let Some(handle) = &mut self.db_handle {
                handle.add_interceptions(data)
            }
        })
    }
}

fn minimum_start(logical_len: usize, limit: usize) -> usize {
    logical_len.saturating_sub(limit)
}
