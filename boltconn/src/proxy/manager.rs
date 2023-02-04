use super::session_ctl::{TcpSessionCtl, UdpSessionCtl};
use dashmap::mapref::entry::Entry;
use dashmap::{DashMap, DashSet};
use io::Result;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

pub struct SessionManager {
    tcp_records: Arc<DashMap<u16, TcpSessionCtl>>,
    // ipv4 as key
    udp_records: Arc<DashMap<u32, UdpSessionCtl>>,
    // map (src,dst) to session key
    udp_session_mapping: Arc<DashMap<(SocketAddr, SocketAddr), u32>>,
    occupied_key: Arc<DashSet<u32>>,
    tcp_stale_time: Duration,
    udp_stale_time: Duration,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            tcp_records: Default::default(),
            udp_records: Default::default(),
            udp_session_mapping: Default::default(),
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
            tracing::debug!("[Session] Recreate record {}", src_addr.port());
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
        self.udp_session_mapping.retain(|_, id| -> bool {
            let Entry::Occupied(record) = self.udp_records.entry(*id)else { return false; };
            if record.get().is_expired(self.udp_stale_time) {
                self.occupied_key.remove(id);
                record.remove();
                return false;
            }
            true
        });
    }

    pub fn flush_with_interval(&self, dura: Duration) -> JoinHandle<()> {
        let shallow_copy = Self {
            tcp_records: self.tcp_records.clone(),
            udp_records: self.udp_records.clone(),
            udp_session_mapping: self.udp_session_mapping.clone(),
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

    pub async fn lookup_udp_token(&self, src: SocketAddr, dst: SocketAddr) -> Option<IpAddr> {
        match self.udp_session_mapping.entry((src, dst)) {
            Entry::Occupied(v) => {
                let key = *v.get();
                if let Some(mut p) = self.udp_records.get_mut(&key) {
                    p.update_time()
                }
                Some(match src {
                    SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(key)),
                    SocketAddr::V6(_) => IpAddr::V6(Ipv4Addr::from(key).to_ipv6_mapped()),
                })
            }
            _ => None,
        }
    }

    pub async fn register_udp_session(&self, src: SocketAddr, dst: SocketAddr) -> IpAddr {
        match self.udp_session_mapping.entry((src, dst)) {
            Entry::Occupied(v) => {
                let key = *v.get();
                if let Some(mut p) = self.udp_records.get_mut(&key) {
                    p.update_time()
                }
                match src {
                    SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(key)),
                    SocketAddr::V6(_) => IpAddr::V6(Ipv4Addr::from(key).to_ipv6_mapped()),
                }
            }
            Entry::Vacant(en) => {
                let key = {
                    loop {
                        let ip = Ipv4Addr::new(
                            99,
                            fastrand::u8(0..=255),
                            fastrand::u8(0..=255),
                            fastrand::u8(0..=255),
                        );
                        let key = ip.into();
                        if self.occupied_key.insert(key) {
                            break key;
                        }
                    }
                };
                en.insert(key);
                self.udp_records.insert(key, UdpSessionCtl::new(src, dst));
                match src {
                    SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(key)),
                    SocketAddr::V6(_) => IpAddr::V6(Ipv4Addr::from(key).to_ipv6_mapped()),
                }
            }
        }
    }

    pub fn lookup_udp_session(
        &self,
        token: IpAddr,
    ) -> Result<(SocketAddr, SocketAddr, Arc<AtomicBool>)> {
        let key: u32 = match token {
            IpAddr::V4(v4) => v4.into(),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                None => {
                    return Err(io::Error::new(
                        ErrorKind::AddrNotAvailable,
                        "Invalid key".to_string(),
                    ));
                }
                Some(v4) => v4.into(),
            },
        };
        match self.udp_records.get_mut(&key) {
            Some(mut s) => {
                s.update_time();
                Ok((s.source_addr, s.dest_addr, s.available.clone()))
            }
            None => Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                "No record found".to_string(),
            )),
        }
    }
}
