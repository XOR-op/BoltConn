use crate::adapter::OutboundType;
use crate::config::RawServerAddr;
use crate::platform::process::{NetworkType, ProcessInfo};
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionProtocol {
    TCP,
    UDP,
    HTTP,
    TLS(TlsVersion),
}

impl Display for SessionProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionProtocol::TCP => f.write_str("tcp"),
            SessionProtocol::UDP => f.write_str("udp"),
            SessionProtocol::HTTP => f.write_str("http"),
            SessionProtocol::TLS(_) => f.write_str("tls"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    SSL30,
    TLS,
}

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

impl NetworkAddr {
    pub fn port(&self) -> u16 {
        match self {
            NetworkAddr::Raw(ad) => ad.port(),
            NetworkAddr::DomainName {
                domain_name: _,
                port,
            } => port.clone(),
        }
    }

    pub fn from(addr: &RawServerAddr, port: u16) -> Self {
        match addr {
            RawServerAddr::IpAddr(ip) => Self::Raw(SocketAddr::new(ip.clone(), port)),
            RawServerAddr::DomainName(dn) => Self::DomainName {
                domain_name: dn.clone(),
                port,
            },
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
        got.handles = handles;
        got.state = CancelState::Ready;
    }
}

// Info about one connection
#[derive(Debug)]
pub struct ConnAgent {
    pub start_time: Instant,
    pub dest: NetworkAddr,
    pub process_info: Option<ProcessInfo>,
    pub session_proto: SessionProtocol,
    pub rule: OutboundType,
    pub upload_traffic: usize,
    pub download_traffic: usize,
    pub done: bool,
    abort_handle: ConnAbortHandle,
}

impl ConnAgent {
    pub fn new(
        dst: NetworkAddr,
        process_info: Option<ProcessInfo>,
        rule: OutboundType,
        network_type: NetworkType,
        abort_handle: ConnAbortHandle,
    ) -> Self {
        Self {
            start_time: Instant::now(),
            dest: dst,
            process_info,
            session_proto: match network_type {
                NetworkType::TCP => SessionProtocol::TCP,
                NetworkType::UDP => SessionProtocol::UDP,
            },
            rule,
            upload_traffic: 0,
            download_traffic: 0,
            done: false,
            abort_handle,
        }
    }

    pub fn update_proto(&mut self, packet: &[u8]) {
        if self.session_proto == SessionProtocol::TCP {
            self.session_proto = check_tcp_protocol(packet);
        }
    }

    pub fn more_upload(&mut self, size: usize) {
        self.upload_traffic += size
    }

    pub fn more_download(&mut self, size: usize) {
        self.download_traffic += size
    }

    pub fn mark_fin(&mut self) {
        self.done = true;
    }

    // todo: abort udp may not work properly
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
            1 | 2 | 3 | 4 => SessionProtocol::TLS(TlsVersion::TLS),
            0 => SessionProtocol::TLS(TlsVersion::SSL30),
            _ => SessionProtocol::TCP, // unknown
        };
    }
    // HTTP request line
    if let Some(idx) = packet.iter().position(|&b| b == b'\r') {
        if idx + 1 < packet.len() && packet[idx + 1] == b'\n' {
            // contains a request line
            let request_line = &packet[0..idx];
            if request_line.ends_with("HTTP/1.1".as_bytes()) {
                // we just ignore legacy versions
                return SessionProtocol::HTTP;
            }
        }
    }
    // Unknown
    SessionProtocol::TCP
}

pub struct AgentCenter {
    content: RwLock<Vec<Arc<RwLock<ConnAgent>>>>,
}

impl AgentCenter {
    pub fn new() -> Self {
        Self {
            content: RwLock::new(Vec::new()),
        }
    }

    pub async fn push(&self, info: Arc<RwLock<ConnAgent>>) {
        self.content.write().await.push(info);
    }

    pub async fn get_copy(&self) -> Vec<Arc<RwLock<ConnAgent>>> {
        self.content.read().await.clone()
    }

    pub async fn get_nth(&self, idx: usize) -> Option<Arc<RwLock<ConnAgent>>> {
        self.content.read().await.get(idx).map(|e| e.clone())
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

#[derive(Clone, Debug)]
pub struct DumpedResponse {
    pub status: http::StatusCode,
    pub version: http::Version,
    pub headers: http::HeaderMap<http::HeaderValue>,
    pub body: hyper::body::Bytes,
    pub time: Instant,
}

pub struct HttpCapturer {
    contents: Mutex<Vec<(String, Option<ProcessInfo>, DumpedRequest, DumpedResponse)>>,
}

impl HttpCapturer {
    pub fn new() -> Self {
        Self {
            contents: Mutex::new(Vec::new()),
        }
    }

    pub fn push(
        &self,
        pair: (DumpedRequest, DumpedResponse),
        host: String,
        client: Option<ProcessInfo>,
    ) {
        self.contents
            .lock()
            .unwrap()
            .push((host, client, pair.0, pair.1))
    }

    pub fn get_copy(&self) -> Vec<(String, Option<ProcessInfo>, DumpedRequest, DumpedResponse)> {
        self.contents.lock().unwrap().clone()
    }
    pub fn get_range_copy(
        &self,
        start: usize,
        end: Option<usize>,
    ) -> Option<Vec<(String, Option<ProcessInfo>, DumpedRequest, DumpedResponse)>> {
        let arr = self.contents.lock().unwrap();
        if start >= arr.len() || (end.is_some() && end.unwrap() > arr.len()) {
            return None;
        }
        Some(if let Some(end) = end {
            arr.as_slice()[start..end]
                .iter()
                .map(|e| e.clone())
                .collect()
        } else {
            arr.as_slice()[start..].iter().map(|e| e.clone()).collect()
        })
    }
}
