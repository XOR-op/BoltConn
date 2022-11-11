mod dns;
mod dns_table;

use crate::config::RawDnsCfg;
use crate::platform::{add_route_entry, add_route_entry_via_gateway, delete_route_entry};
pub use dns::Dns;
use ipnet::IpNet;
use std::io::Result;
use std::net::IpAddr;

pub struct DnsRoutingHandle(RawDnsCfg);

impl DnsRoutingHandle {
    pub fn new(gw: IpAddr, iface: &str, config: RawDnsCfg) -> Result<Self> {
        for e in &config.list {
            add_route_entry_via_gateway(e.ip(), gw, iface)?;
        }
        Ok(Self { 0: config })
    }
}

impl Drop for DnsRoutingHandle {
    fn drop(&mut self) {
        for e in &self.0.list {
            let _ = delete_route_entry(e.ip());
        }
    }
}
