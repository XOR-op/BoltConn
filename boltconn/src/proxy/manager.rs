use super::session_ctl::{TcpSessionCtl, UdpSessionCtl};
use dashmap::mapref::entry::Entry;
use dashmap::{DashMap, DashSet};
use io::Result;
use std::collections::HashSet;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct SessionManager {
    tcp_records: DashMap<u16, TcpSessionCtl>,
    // ipv4 as key
    udp_records: DashMap<u32, UdpSessionCtl>,
    // map (src,dst) to session key
    udp_session_mapping: DashMap<(SocketAddr, SocketAddr), u32>,
    occupied_key: DashSet<u32>,
    stale_time: Duration,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            tcp_records: DashMap::new(),
            udp_records: DashMap::new(),
            udp_session_mapping: DashMap::new(),
            occupied_key: DashSet::new(),
            // 2MSL
            stale_time: Duration::from_secs(120),
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
        pair.key().clone()
    }

    /// Use inbound.port to query session
    pub fn lookup_tcp_session(
        &self,
        inbound_port: u16,
    ) -> Result<(SocketAddr, SocketAddr, Arc<AtomicU8>)> {
        match self.tcp_records.get(&inbound_port) {
            Some(s) => {
                // tracing::trace!(
                //     "[Session] success = ({})=>({},{})",
                //     port,
                //     s.source_addr,
                //     s.dest_addr
                // );
                Ok((s.source_addr, s.dest_addr, s.available.clone()))
            }
            None => {
                // tracing::debug!(
                //     "[Session] token {} not found; tcp_records = {:?}",
                //     port,
                //     self.tcp_records
                // );
                Err(io::Error::new(
                    ErrorKind::AddrNotAvailable,
                    format!("No record found"),
                ))
            }
        }
    }

    /// Evict all expired sessions.
    /// TCP session expires when closed; UDP session expires when timeout.
    pub fn flush(&self) {
        self.tcp_records
            .retain(|_, v| v.available.load(Ordering::Relaxed) > 0);
        // todo: need fix
        self.udp_records
            .retain(|_, v| v.is_expired(self.stale_time));
    }

    pub fn get_all_tcp_sessions(&self) -> Vec<TcpSessionCtl> {
        self.tcp_records.iter().map(|p| p.value().clone()).collect()
    }
    pub fn get_all_udp_sessions(&self) -> Vec<UdpSessionCtl> {
        self.udp_records.iter().map(|p| p.value().clone()).collect()
    }

    pub async fn lookup_udp_token(&self, src: SocketAddr, dst: SocketAddr) -> Option<IpAddr> {
        match self.udp_session_mapping.entry((src.clone(), dst)) {
            Entry::Occupied(v) => {
                let key = v.get().clone();
                self.udp_records.get_mut(&key).map(|mut p| p.update_time());
                Some(match src {
                    SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(key)),
                    SocketAddr::V6(_) => IpAddr::V6(Ipv4Addr::from(key).to_ipv6_mapped()),
                })
            }
            _ => None,
        }
    }

    pub async fn register_udp_session(&self, src: SocketAddr, dst: SocketAddr) -> IpAddr {
        match self.udp_session_mapping.entry((src.clone(), dst)) {
            Entry::Occupied(v) => {
                let key = v.get().clone();
                self.udp_records.get_mut(&key).map(|mut p| p.update_time());
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
                        format!("Invalid key"),
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
                format!("No record found"),
            )),
        }
    }
}
