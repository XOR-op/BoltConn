use std::net::{IpAddr, SocketAddr};
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
    TLS10,
    TLS11,
    TLS12,
    TLS13,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkAddr {
    Raw(SocketAddr),
    DomainName { domain_name: String, port: u16 },
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub start_time: Instant,
    pub dest: NetworkAddr,
    pub session_proto: SessionProtocol,
    pub rule: String,
}

impl SessionInfo {
    pub fn new(dst: NetworkAddr, rule: &str) -> Self {
        Self {
            start_time: Instant::now(),
            dest: dst,
            session_proto: SessionProtocol::TCP,
            rule: rule.to_string(),
        }
    }

    pub fn update_proto(&mut self, packet: &[u8]) {
        self.session_proto = check_tcp_protocol(packet);
        if self.session_proto != SessionProtocol::TCP {
            tracing::trace!("Update info: {:?}", self);
        }
    }
}

/// The packet as argument should be the first packet of the connection
pub fn check_tcp_protocol(packet: &[u8]) -> SessionProtocol {
    // TLS handshake
    if packet.len() > 5 && packet[0] == 22 && packet[1] == 3 {
        return match packet[2] {
            3 => SessionProtocol::TLS(TlsVersion::TLS12),
            4 => SessionProtocol::TLS(TlsVersion::TLS13),
            2 => SessionProtocol::TLS(TlsVersion::TLS11),
            1 => SessionProtocol::TLS(TlsVersion::TLS10),
            0 => SessionProtocol::TLS(TlsVersion::SSL30),
            _ => SessionProtocol::TCP // unknown
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
