mod dns;
mod dns_table;

pub use dns::Dns;
use crate::config::DnsConfig;
use crate::platform::{add_route_entry, delete_route_entry};
use std::io::Result;
use ipnet::IpNet;

pub struct DnsRoutingHandle(DnsConfig);

impl DnsRoutingHandle {
    pub fn new(gw: &str, config: DnsConfig) -> Result<Self> {
        for e in &config.list {
            add_route_entry(IpNet::from(e.ip()), gw)?;
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
