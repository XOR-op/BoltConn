use crate::adapter::OutboundType;
use crate::config::RawServerAddr;
use std::net::{ SocketAddr};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionProtocol {
    TCP,
    HTTP,
    TLS(TlsVersion),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    SSL30,
    TLS,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkAddr {
    Raw(SocketAddr),
    DomainName { domain_name: String, port: u16 },
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
pub struct SessionInfo {
    pub start_time: Instant,
    pub dest: NetworkAddr,
    pub session_proto: SessionProtocol,
    pub rule: OutboundType,
    pub upload_traffic: u64,
    pub download_traffic: u64,
}

impl SessionInfo {
    pub fn new(dst: NetworkAddr, rule: OutboundType) -> Self {
        Self {
            start_time: Instant::now(),
            dest: dst,
            session_proto: SessionProtocol::TCP,
            rule,
            upload_traffic: 0,
            download_traffic: 0,
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

    pub fn more_upload(&mut self, size: u64) {
        self.upload_traffic += size
    }

    pub fn more_download(&mut self, size: u64) {
        self.download_traffic += size
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
