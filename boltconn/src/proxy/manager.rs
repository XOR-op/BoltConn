use super::session_ctl::{TcpSessionCtl, UdpSessionCtl};
use dashmap::mapref::entry::Entry;
use dashmap::{DashMap, DashSet};
use io::Result;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

pub struct SessionManager {
    tcp_records: Arc<DashMap<u16, TcpSessionCtl>>,
    // ipv4 as key
    udp_records: Arc<DashMap<u16, UdpSessionCtl>>,
    occupied_key: Arc<DashSet<u32>>,
    tcp_stale_time: Duration,
    udp_stale_time: Duration,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            tcp_records: Default::default(),
            udp_records: Default::default(),
            occupied_key: Default::default(),
            // 2MSL
            tcp_stale_time: Duration::from_secs(120),
            udp_stale_time: Duration::from_secs(45),
        }
    }

    /// inbound->outbound, return inbound.port
    pub fn register_tcp_session(&self, src_addr: SocketAddr, dst_addr: SocketAddr) -> u16 {
        let entry = self.tcp_records.entry(src_addr.port());
        let mut pair = entry.or_insert(TcpSessionCtl::new(src_addr, dst_addr));
        // If original connection silently expired
        if pair.dest_addr != dst_addr {
            tracing::warn!(
                "[Session] Recreate TCP record {}: src={}, old={}, new={}",
                src_addr.port(),
                src_addr,
                pair.dest_addr,
                dst_addr
            );
            *pair.value_mut() = TcpSessionCtl::new(src_addr, dst_addr);
        }
        pair.value_mut().update_time();
        *pair.key()
    }

    /// Use inbound.port to query session
    pub fn lookup_tcp_session(
        &self,
        inbound_port: u16,
    ) -> Result<(SocketAddr, SocketAddr, Arc<AtomicU8>)> {
        match self.tcp_records.get(&inbound_port) {
            Some(s) => Ok((s.source_addr, s.dest_addr, s.available.clone())),
            None => Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                "No record found".to_string(),
            )),
        }
    }

    /// Evict all expired sessions.
    /// TCP session expires when closed; UDP session expires when timeout.
    pub fn flush(&self) {
        self.tcp_records
            .retain(|_, v| v.available.load(Ordering::Relaxed) > 0);
        self.udp_records.retain(|_, record| -> bool {
            if record.is_expired(self.udp_stale_time) {
                record.invalidate();
                return false;
            }
            true
        });
    }

    pub fn flush_with_interval(&self, dura: Duration) -> JoinHandle<()> {
        let shallow_copy = Self {
            tcp_records: self.tcp_records.clone(),
            udp_records: self.udp_records.clone(),
            occupied_key: self.occupied_key.clone(),
            tcp_stale_time: self.tcp_stale_time,
            udp_stale_time: self.udp_stale_time,
        };
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(dura);
            loop {
                interval.tick().await;
                shallow_copy.flush();
            }
        })
    }

    pub fn get_all_tcp_sessions(&self) -> Vec<TcpSessionCtl> {
        self.tcp_records.iter().map(|p| p.value().clone()).collect()
    }
    pub fn get_all_udp_sessions(&self) -> Vec<UdpSessionCtl> {
        self.udp_records.iter().map(|p| p.value().clone()).collect()
    }

    pub fn get_udp_probe(&self, src: SocketAddr) -> Arc<AtomicBool> {
        match self.udp_records.entry(src.port()) {
            Entry::Occupied(s) => s.get().available.clone(),
            Entry::Vacant(entry) => {
                let ctl = UdpSessionCtl::new(src);
                let probe = ctl.available.clone();
                entry.insert(ctl);
                probe
            }
        }
    }
}
