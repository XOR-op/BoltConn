use crate::platform;
use crate::platform::route::{ipv4_relay_addresses, setup_ipv4_routing_table};
use crate::platform::SystemDnsHandle;
use ipnet::IpNet;
use std::io;
use std::net::Ipv4Addr;

pub struct TunConfigure {
    dns_addr: Ipv4Addr,
    device_name: String,
    outbound_name: String,
    dns_handle: Option<SystemDnsHandle>,
    routing_table_flag: bool,
}

impl TunConfigure {
    pub fn new(dns_addr: Ipv4Addr, device_name: &str, outbound_name: &str) -> Self {
        Self {
            dns_addr,
            device_name: device_name.to_string(),
            outbound_name: outbound_name.to_string(),
            dns_handle: None,
            routing_table_flag: false,
        }
    }

    pub fn enable(&mut self) -> io::Result<()> {
        self.enable_dns()?;
        if let Err(e) = self.enable_routing_table() {
            self.disable_dns();
            return Err(e);
        }
        tracing::info!("Tun mode has been enabled");
        Ok(())
    }

    pub fn disable(&mut self, show_log: bool) {
        self.disable_routing_table();
        self.disable_dns();
        if show_log {
            tracing::info!("Tun mode has been disabled");
        }
    }

    pub fn get_status(&self) -> bool {
        self.dns_handle.is_some() && self.routing_table_flag
    }

    fn enable_dns(&mut self) -> io::Result<()> {
        if self.dns_handle.is_none() {
            self.dns_handle = Some(SystemDnsHandle::new(
                self.dns_addr,
                &self.device_name,
                &self.outbound_name,
            )?)
        }
        Ok(())
    }

    fn enable_routing_table(&mut self) -> io::Result<()> {
        if !self.routing_table_flag {
            setup_ipv4_routing_table(self.device_name.as_str())?;
            self.routing_table_flag = true;
        }
        Ok(())
    }

    fn disable_dns(&mut self) {
        self.dns_handle = None
    }

    fn disable_routing_table(&mut self) {
        if self.routing_table_flag {
            for item in ipv4_relay_addresses() {
                let _ = platform::delete_route_entry(IpNet::V4(item));
            }
            self.routing_table_flag = false
        }
    }
}

impl Drop for TunConfigure {
    fn drop(&mut self) {
        self.disable(false)
    }
}
