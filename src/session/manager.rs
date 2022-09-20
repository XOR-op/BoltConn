use super::session::{TcpSessionCtl, UdpSessionCtl};
use dashmap::DashMap;
use io::Result;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

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
        entry.or_insert(TcpSessionCtl::new(src_addr, dst_addr));
        entry.and_modify(|mut se| {
            // If original connection silently expired
            if se.dest_addr != dst_addr {
                *se = TcpSessionCtl::new(src_addr, dst_addr);
            }
            se.update_time();
        });
        entry.key().clone()
    }

    pub fn query_tcp_by_token(
        &self,
        port: u16,
    ) -> Result<(SocketAddr, SocketAddr, Arc<AtomicBool>)> {
        match self.tcp_records.get(&port) {
            Some(s) => Ok((s.source_addr, s.dest_addr, s.available.clone())),
            None => Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                format!("No record found"),
            )),
        }
    }
}
