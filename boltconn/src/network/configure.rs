use crate::platform;
use crate::platform::SystemDnsHandle;
use crate::platform::route::{ipv4_relay_addresses, setup_ipv4_routing_table};
use ipnet::IpNet;
use std::io;
use std::net::Ipv4Addr;

use crate::config::RawFirewallConfig;
#[cfg(target_os = "linux")]
use crate::external::firewall::DockerMasqueradeGuard;
use crate::external::firewall::KillSwitchGuard;

pub struct TunConfigure {
    dns_addr: Ipv4Addr,
    device_name: String,
    outbound_name: String,
    dns_handle: Option<SystemDnsHandle>,
    routing_table_flag: bool,
    rootless: bool,
    firewall_config: RawFirewallConfig,
    kill_switch_guard: Option<KillSwitchGuard>,
    #[cfg(target_os = "linux")]
    docker_masquerade_guard: Option<DockerMasqueradeGuard>,
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
    pub fn new(
        dns_addr: Ipv4Addr,
        device_name: &str,
        outbound_name: &str,
        rootless: bool,
        firewall_config: RawFirewallConfig,
    ) -> Self {
        Self {
            dns_addr,
            device_name: device_name.to_string(),
            outbound_name: outbound_name.to_string(),
            dns_handle: None,
            routing_table_flag: false,
            rootless,
            firewall_config,
            kill_switch_guard: None,
            #[cfg(target_os = "linux")]
            docker_masquerade_guard: None,
        }
    }

    pub fn enable(&mut self) -> io::Result<()> {
        check_rootless!(self, Ok(()));

        if self.firewall_config.kill_switch && self.kill_switch_guard.is_none() {
            self.kill_switch_guard = Some(KillSwitchGuard::setup(&self.device_name)?);
        }

        if let Err(error) = self.enable_dns() {
            return Err(self.rollback_kill_switch(error));
        }
        if let Err(e) = self.enable_routing_table() {
            self.disable_dns();
            return Err(self.rollback_kill_switch(e));
        }
        #[cfg(target_os = "linux")]
        {
            if self.docker_masquerade_guard.is_none() {
                self.docker_masquerade_guard = DockerMasqueradeGuard::setup(
                    &self.device_name,
                    &self.firewall_config.docker_masquerade,
                );
            }
        }
        tracing::info!("Tun mode has been enabled");
        Ok(())
    }

    pub fn disable(&mut self, show_log: bool) -> io::Result<()> {
        if self.rootless {
            if show_log {
                tracing::warn!(
                    "TUN mode is disabled in rootless mode; no configuration will be applied"
                );
            }
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            self.docker_masquerade_guard.take();
        }

        let route_result = self.disable_routing_table();
        self.disable_dns();
        // If route cleanup failed, retain the kill switch. Removing it while a partially
        // configured routing table remains would turn a cleanup failure into a traffic leak.
        let kill_switch_result = if route_result.is_ok() {
            self.disable_kill_switch()
        } else {
            Ok(())
        };
        let result = combine_results(route_result, kill_switch_result);
        if show_log {
            match &result {
                Ok(()) => tracing::info!("Tun mode has been disabled"),
                Err(error) => tracing::error!(%error, "failed to disable TUN mode"),
            }
        }
        result
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

    fn disable_routing_table(&mut self) -> io::Result<()> {
        check_rootless!(self, Ok(()));
        let mut first_error = None;
        if self.routing_table_flag {
            for item in ipv4_relay_addresses() {
                if let Err(error) = platform::delete_route_entry(IpNet::V4(item))
                    && first_error.is_none()
                {
                    first_error = Some(error);
                }
            }
            if first_error.is_none() {
                self.routing_table_flag = false;
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn disable_kill_switch(&mut self) -> io::Result<()> {
        let Some(mut guard) = self.kill_switch_guard.take() else {
            return Ok(());
        };
        if let Err(error) = guard.teardown() {
            self.kill_switch_guard = Some(guard);
            Err(error)
        } else {
            Ok(())
        }
    }

    fn rollback_kill_switch(&mut self, original: io::Error) -> io::Error {
        match self.disable_kill_switch() {
            Ok(()) => original,
            Err(rollback) => io::Error::other(format!(
                "TUN setup failed ({original}); kill-switch rollback failed ({rollback})"
            )),
        }
    }
}

impl Drop for TunConfigure {
    fn drop(&mut self) {
        if let Err(error) = self.disable(false) {
            tracing::error!(%error, "failed to clean up TUN configuration");
        }
    }
}

fn combine_results(first: io::Result<()>, second: io::Result<()>) -> io::Result<()> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(io::Error::other(format!(
            "route cleanup failed ({first}); kill-switch cleanup failed ({second})"
        ))),
    }
}
