use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone, Copy)]
pub enum SessionProtocol {
    TCP,
    HTTP,
    TLS(TlsVersion),
}

#[derive(Debug, Clone, Copy)]
pub enum TlsVersion {
    TLS12,
    TLS13,
    LEGACY,
}

#[derive(Debug, Clone)]
pub enum NetworkAddr {
    IP(SocketAddr),
    DomainName { domain_name: String, port: u16 },
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub start_time: Instant,
    pub dest: NetworkAddr,
    pub session_proto: SessionProtocol,
    pub rule: String,
}

/// The packet as argument should be the first packet of the connection
pub fn check_tcp_protocol(packet: &[u8]) -> SessionProtocol {
    // TLS handshake
    if packet.len() > 5 && packet[0] == 22 && packet[1] == 3 {
        match packet[2] {
            3 => return SessionProtocol::TLS(TlsVersion::TLS12),
            4 => return SessionProtocol::TLS(TlsVersion::TLS13),
            0 | 1 | 2 => return SessionProtocol::TLS(TlsVersion::LEGACY),
            _ => {}
        }
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