use crate::adapter::OutboundType;
use crate::config::RawServerAddr;
use crate::platform::process::ProcessInfo;
use http::{Request, Response};
use hyper::Body;
use std::fmt::{Display, Formatter, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionProtocol {
    TCP,
    HTTP,
    TLS(TlsVersion),
}

impl Display for SessionProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionProtocol::TCP => f.write_str("tcp"),
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

#[derive(Debug, Clone)]
pub struct StatisticsInfo {
    pub start_time: Instant,
    pub dest: NetworkAddr,
    pub process_info: Option<ProcessInfo>,
    pub session_proto: SessionProtocol,
    pub rule: OutboundType,
    pub upload_traffic: usize,
    pub download_traffic: usize,
    pub done: bool,
}

impl StatisticsInfo {
    pub fn new(dst: NetworkAddr, process_info: Option<ProcessInfo>, rule: OutboundType) -> Self {
        Self {
            start_time: Instant::now(),
            dest: dst,
            process_info,
            session_proto: SessionProtocol::TCP,
            rule,
            upload_traffic: 0,
            download_traffic: 0,
            done: false,
        }
    }

    pub fn update_proto(&mut self, packet: &[u8]) {
        self.session_proto = check_tcp_protocol(packet);
        if self.session_proto != SessionProtocol::TCP {
            tracing::trace!(
                "Update info: dst={:?}, proto={:?}, rule={:?}",
                self.dest,
                self.session_proto,
                self.rule
            );
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

pub struct StatCenter {
    content: RwLock<Vec<Arc<RwLock<StatisticsInfo>>>>,
}

impl StatCenter {
    pub fn new() -> Self {
        Self {
            content: RwLock::new(Vec::new()),
        }
    }

    pub fn push(&self, info: Arc<RwLock<StatisticsInfo>>) {
        self.content.write().unwrap().push(info);
    }

    pub fn get_copy(&self) -> Vec<Arc<RwLock<StatisticsInfo>>> {
        self.content.read().unwrap().clone()
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
        range: (usize, usize),
    ) -> Vec<(String, Option<ProcessInfo>, DumpedRequest, DumpedResponse)> {
        let arr = self.contents.lock().unwrap();
        arr.as_slice()[range.0..range.1]
            .iter()
            .map(|e| e.clone())
            .collect()
    }
}
