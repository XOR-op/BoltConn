mod dns;
mod dns_table;

use crate::platform::{add_route_entry, add_route_entry_via_gateway, delete_route_entry};
pub use dns::Dns;
use ipnet::IpNet;
use std::io::Result;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug)]
pub struct DnsRoutingHandle(Vec<DnsConfig>);

impl DnsRoutingHandle {
    pub fn new(gw: IpAddr, iface: &str, config: &Vec<IpAddr>) -> Result<Self> {
        let mut arr = Vec::new();
        for e in config.clone() {
            add_route_entry_via_gateway(e, gw, iface)?;
            arr.push(DnsConfig::new_udp(e))
        }
        Ok(Self { 0: arr })
    }
}

impl Drop for DnsRoutingHandle {
    fn drop(&mut self) {
        for e in &self.0 {
            let _ = delete_route_entry(e.ip());
        }
    }
}

#[derive(Clone, Debug)]
enum DnsType {
    Udp(IpAddr),
    Tcp(IpAddr),
    // todo: domain name alternative
    DoT(IpAddr),
}

#[derive(Clone, Debug)]
pub struct DnsConfig {
    dns_type: DnsType,
}

impl DnsConfig {
    pub fn new_udp(ip: IpAddr) -> Self {
        Self {
            dns_type: DnsType::Udp(ip),
        }
    }

    pub fn ip(&self) -> IpAddr {
        match self.dns_type {
            DnsType::Udp(ip) => ip,
            DnsType::Tcp(ip) => ip,
            DnsType::DoT(ip) => ip,
        }
    }
}
