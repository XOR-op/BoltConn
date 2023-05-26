use crate::adapter::OutboundType;
use crate::common::evictable_vec::EvictableVec;
use crate::config::RawServerAddr;
use crate::external::DatabaseHandle;
use crate::platform::process::{NetworkType, ProcessInfo};
use fast_socks5::util::target_addr::TargetAddr;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProtocol {
    Tcp,
    Udp,
    Http,
    Tls(TlsVersion),
}

impl Display for SessionProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionProtocol::Tcp => f.write_str("tcp"),
            SessionProtocol::Udp => f.write_str("udp"),
            SessionProtocol::Http => f.write_str("http"),
            SessionProtocol::Tls(_) => f.write_str("tls"),
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
pub struct ConnAbortHandle(Arc<tokio::sync::RwLock<AbortHandle>>);

#[derive(Copy, Clone, PartialEq, Debug)]
enum CancelState {
    NotReady,
    Ready,
    Cancelled,
}

#[derive(Debug)]
struct AbortHandle {
    handles: Vec<JoinHandle<()>>,
    state: CancelState,
}

impl ConnAbortHandle {
    pub fn new() -> Self {
        Self(Arc::new(tokio::sync::RwLock::new(AbortHandle {
            handles: vec![],
            state: CancelState::NotReady,
        })))
    }

    pub async fn cancel(&self) {
        let mut timer = tokio::time::interval(Duration::from_micros(100));
        loop {
            let mut got = self.0.write().await;
            match got.state {
                CancelState::NotReady => {
                    drop(got);
                    timer.tick().await;
                    continue;
                }
                CancelState::Ready => {
                    got.state = CancelState::Cancelled;
                    for h in &got.handles {
                        h.abort();
                    }
                    got.handles.clear();
                    return;
                }
                CancelState::Cancelled => return,
            }
        }
    }

    pub async fn fulfill(&self, handles: Vec<JoinHandle<()>>) {
        let mut got = self.0.write().await;
        if got.state != CancelState::NotReady {
            tracing::warn!("Fulfill a cancel handle twice");
        }
        got.handles = handles;
        got.state = CancelState::Ready;
    }
}

// Info about one connection
#[derive(Debug)]
pub struct ConnContext {
    pub start_time: SystemTime,
    pub dest: NetworkAddr,
    pub process_info: Option<ProcessInfo>,
    pub session_proto: SessionProtocol,
    pub rule: OutboundType,
    pub upload_traffic: u64,
    pub download_traffic: u64,
    pub done: bool,
    global_upload: Arc<AtomicU64>,
    global_download: Arc<AtomicU64>,
    abort_handle: ConnAbortHandle,
}

impl ConnContext {
    pub fn new(
        dst: NetworkAddr,
        process_info: Option<ProcessInfo>,
        rule: OutboundType,
        network_type: NetworkType,
        abort_handle: ConnAbortHandle,
        global_upload: Arc<AtomicU64>,
        global_download: Arc<AtomicU64>,
    ) -> Self {
        Self {
            start_time: SystemTime::now(),
            dest: dst,
            process_info,
            session_proto: match network_type {
                NetworkType::Tcp => SessionProtocol::Tcp,
                NetworkType::Udp => SessionProtocol::Udp,
            },
            rule,
            upload_traffic: 0,
            download_traffic: 0,
            done: false,
            global_upload,
            global_download,
            abort_handle,
        }
    }

    pub fn update_proto(&mut self, packet: &[u8]) {
        if self.session_proto == SessionProtocol::Tcp {
            self.session_proto = check_tcp_protocol(packet);
        }
    }

    pub fn more_upload(&mut self, size: usize) {
        self.upload_traffic += size as u64;
        self.global_upload.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn more_download(&mut self, size: usize) {
        self.download_traffic += size as u64;
        self.global_download
            .fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn mark_fin(&mut self) {
        self.done = true;
    }

    pub async fn abort(&mut self) {
        self.abort_handle.cancel().await;
        self.mark_fin();
    }
}

/// The packet as argument should be the first packet of the connection
pub fn check_tcp_protocol(packet: &[u8]) -> SessionProtocol {
    // TLS handshake
    if packet.len() > 5 && packet[0] == 22 && packet[1] == 3 {
        return match packet[2] {
            1 | 2 | 3 | 4 => SessionProtocol::Tls(TlsVersion::Tls),
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

pub struct ContextManager {
    content: RwLock<EvictableVec<Arc<RwLock<ConnContext>>>>,
    keep_count: usize,
    grace_threshold: usize,
    db_handle: Mutex<DatabaseHandle>,
    global_upload: Arc<AtomicU64>,
    global_download: Arc<AtomicU64>,
}

impl ContextManager {
    pub fn new(db_handle: DatabaseHandle, keep_count: usize, grace_threshold: usize) -> Self {
        Self {
            content: RwLock::new(EvictableVec::new()),
            db_handle: Mutex::new(db_handle),
            global_upload: Arc::new(Default::default()),
            global_download: Arc::new(Default::default()),
        }
    }

    pub fn get_upload(&self) -> Arc<AtomicU64> {
        self.global_upload.clone()
    }

    pub fn get_download(&self) -> Arc<AtomicU64> {
        self.global_download.clone()
    }

    pub async fn push(&self, info: Arc<RwLock<ConnContext>>) {
        self.content.write().await.push(info);
    }

    pub async fn get_copy(&self) -> Vec<Arc<RwLock<ConnContext>>> {
        let vec = self.content.read().await;
        vec.get_last_n(vec.real_len())
    }

    pub async fn get_nth(&self, idx: usize) -> Option<Arc<RwLock<ConnContext>>> {
        self.content.read().await.get(idx).cloned()
    }

    async fn evict(&self) {
        let mut write_vec = self.content.write().await;
        let mut handle = self.db_handle.lock().unwrap();
        if write_vec.real_len() > self.keep_count + self.grace_threshold {
            write_vec.evict_with(self.keep_count, |data| {
                if let Err(err) = handle.add_interceptions(data) {
                    tracing::warn!("Write connection data failed: {}", err)
                }
            })
        }
    }
}

impl Drop for ContextManager {
    fn drop(&mut self) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct DumpedRequest {
    pub uri: http::Uri,
    pub method: http::Method,
    pub version: http::Version,
    pub headers: http::HeaderMap<http::HeaderValue>,
    pub body: hyper::body::Bytes,
    pub time: Instant,
}

impl DumpedRequest {
    pub fn from_parts(parts: &http::request::Parts, body: &hyper::body::Bytes) -> Self {
        Self {
            uri: parts.uri.clone(),
            method: parts.method.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
            body: body.clone(),
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
    pub body: hyper::body::Bytes,
    pub time: Instant,
}

impl DumpedResponse {
    pub fn from_parts(parts: &http::response::Parts, body: &hyper::body::Bytes) -> Self {
        Self {
            status: parts.status,
            version: parts.version,
            headers: parts.headers.clone(),
            body: body.clone(),
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
    db_handle: DatabaseHandle,
}

impl HttpCapturer {
    pub fn new(db_handle: DatabaseHandle) -> Self {
        Self {
            inner: Mutex::new(HttpCapturerInner {
                keep_count: 50,
                grace_threshold: 10,
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
        self.inner
            .lock()
            .unwrap()
            .contents
            .push(HttpInterceptData::new(host, client, pair.0, pair.1))
    }

    pub fn get_copy(&self) -> Vec<HttpInterceptData> {
        let result = self.inner.lock().unwrap().get_allowed_elements();
        // GC
        self.inner.lock().unwrap().evict();
        result
    }

    #[allow(clippy::type_complexity)]
    pub fn get_range_copy(
        &self,
        start: usize,
        end: Option<usize>,
    ) -> Option<Vec<HttpInterceptData>> {
        let inner = self.inner.lock().unwrap();

        let start = if start >= inner.contents.current_offset() {
            start
        } else {
            inner.contents.current_offset()
        };
        // check if the range is valid logically
        if start >= inner.contents.logical_len()
            || (end.is_some()
                && (end.unwrap() > inner.contents.logical_len() || start >= end.unwrap()))
        {
            return None;
        }
        Some(inner.contents.logical_slice(start, end).to_vec())
    }
}

impl HttpCapturerInner {
    fn get_allowed_elements(&self) -> Vec<HttpInterceptData> {
        self.contents.get_last_n(self.keep_count)
    }

    fn evict(&mut self) {
        if self.contents.real_len() > self.keep_count + self.grace_threshold {
            self.contents.evict_with(self.keep_count, |data| {
                if let Err(err) = self.db_handle.add_interceptions(data) {
                    tracing::warn!("Write intercepted http data failed: {}", err)
                }
            })
        }
    }
}

impl Drop for HttpCapturerInner {
    fn drop(&mut self) {
        self.contents.evict_with(0, |data| {
            let _ = self.db_handle.add_interceptions(data);
        })
    }
}
