use super::session::{TcpSessionCtl, UdpSessionCtl};
use dashmap::DashMap;
use io::Result;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct SessionManager {
    tcp_records: DashMap<u16, TcpSessionCtl>,
    udp_records: DashMap<u16, UdpSessionCtl>,
    stale_time: Duration,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            tcp_records: DashMap::new(),
            udp_records: DashMap::new(),
            // 2MSL
            stale_time: Duration::from_secs(120),
        }
    }

    pub fn query_tcp_by_addr(&self, src_addr: SocketAddr, dst_addr: SocketAddr) -> u16 {
        let entry = self.tcp_records.entry(src_addr.port());
        let mut pair = entry.or_insert(TcpSessionCtl::new(src_addr, dst_addr));
        // If original connection silently expired
        if pair.dest_addr != dst_addr {
            tracing::debug!("[Session] Recreate record {}", src_addr.port());
            *pair.value_mut() = TcpSessionCtl::new(src_addr, dst_addr);
        }
        pair.value_mut().update_time();
        pair.key().clone()
    }

    pub fn query_tcp_by_token(&self, port: u16) -> Result<(SocketAddr, SocketAddr, Arc<AtomicU8>)> {
        match self.tcp_records.get(&port) {
            Some(s) => {
                tracing::trace!(
                    "[Session] success = ({})=>({},{})",
                    port,
                    s.source_addr,
                    s.dest_addr
                );
                Ok((s.source_addr, s.dest_addr, s.available.clone()))
            }
            None => {
                tracing::debug!(
                    "[Session] token {} not found; tcp_records = {:?}",
                    port,
                    self.tcp_records
                );
                Err(io::Error::new(
                    ErrorKind::AddrNotAvailable,
                    format!("No record found"),
                ))
            }
        }
    }
}
