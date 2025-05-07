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
    rootless: bool,
}

macro_rules! check_rootless {
    ($self:ident, $ret:expr) => {
        if $self.rootless {
            tracing::warn!(
                "TUN mode is disabled in rootless mode; no configuration will be applied"
            );
            #[allow(clippy::unused_unit)]
            return $ret;
        }
    };
}

impl TunConfigure {
    pub fn new(dns_addr: Ipv4Addr, device_name: &str, outbound_name: &str, rootless: bool) -> Self {
        Self {
            dns_addr,
            device_name: device_name.to_string(),
            outbound_name: outbound_name.to_string(),
            dns_handle: None,
            routing_table_flag: false,
            rootless,
        }
    }

    pub fn enable(&mut self) -> io::Result<()> {
        check_rootless!(self, Ok(()));
        self.enable_dns()?;
        if let Err(e) = self.enable_routing_table() {
            self.disable_dns();
            return Err(e);
        }
        tracing::info!("Tun mode has been enabled");
        Ok(())
    }

    pub fn disable(&mut self, show_log: bool) {
        if self.rootless {
            if show_log {
                tracing::warn!(
                    "TUN mode is disabled in rootless mode; no configuration will be applied"
                );
            }
            return;
        }
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
        check_rootless!(self, Ok(()));
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
        check_rootless!(self, Ok(()));
        if !self.routing_table_flag {
            setup_ipv4_routing_table(self.device_name.as_str())?;
            self.routing_table_flag = true;
        }
        Ok(())
    }

    fn disable_dns(&mut self) {
        check_rootless!(self, ());
        self.dns_handle = None
    }

    fn disable_routing_table(&mut self) {
        check_rootless!(self, ());
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
