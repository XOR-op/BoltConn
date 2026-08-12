mod bootstrap;
#[allow(clippy::module_inception)]
mod dns;
mod dns_table;
mod hijack_ctrl;
mod hosts;
mod ns_policy;
mod provider;

use crate::config::DnsConfigError;
use crate::proxy::error::DnsError;
pub use bootstrap::BootstrapResolver;
pub use dns::{Dns, GenericDns};
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    CLOUDFLARE, ConnectionConfig, GOOGLE, NameServerConfig, QUAD9, ResolverConfig, ResolverOpts,
};
pub use hijack_ctrl::DnsHijackController;
pub use ns_policy::NameserverPolicies;
use provider::IfaceProvider;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub enum NameServerConfigEnum {
    Normal(Vec<NameServerConfig>),
    Dhcp(String),
}

fn encrypted_server_configs(ips: &[IpAddr], connection: ConnectionConfig) -> Vec<NameServerConfig> {
    ips.iter()
        .map(|ip| NameServerConfig::new(*ip, false, vec![connection.clone()]))
        .collect()
}

async fn resolve_dns(bootstrap: &BootstrapResolver, dn: &str) -> Result<Vec<IpAddr>, DnsError> {
    let Ok(ips) = bootstrap.lookup_ip(dn).await else {
        return Err(DnsError::ResolveServer(dn.to_string()));
    };
    if ips.is_empty() {
        Err(DnsError::ResolveServer(dn.to_string()))
    } else {
        Ok(ips)
    }
}

pub fn new_bootstrap_resolver(iface_name: &str, addr: &[IpAddr]) -> BootstrapResolver {
    let cfg = ResolverConfig::from_parts(
        None,
        vec![],
        addr.iter().copied().map(NameServerConfig::udp).collect(),
    );
    BootstrapResolver::new(
        Resolver::builder_with_config(cfg, IfaceProvider::new(iface_name))
            .build()
            .expect("rustls miscompiled"),
    )
}

pub async fn parse_dns_config(
    lines: impl Iterator<Item = &String>,
    bootstrap: &BootstrapResolver,
) -> Result<Vec<NameServerConfigEnum>, DnsConfigError> {
    let mut arr = Vec::new();
    for l in lines {
        let parts: Vec<&str> = l.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return Err(DnsConfigError::Invalid(l.clone()));
        }
        let (proto, content) = (
            parts.first().unwrap().to_string(),
            parts.get(1).unwrap().to_string(),
        );
        arr.push(parse_single_dns(proto.as_str(), content.as_str(), bootstrap).await?);
    }
    Ok(arr)
}

pub async fn parse_single_dns(
    proto: &str,
    content: &str,
    bootstrap: &BootstrapResolver,
) -> Result<NameServerConfigEnum, DnsConfigError> {
    Ok(NameServerConfigEnum::Normal(match proto {
        "dhcp" => {
            return Ok(NameServerConfigEnum::Dhcp(content.to_string()));
        }
        "udp" => vec![NameServerConfig::udp(
            content
                .parse::<IpAddr>()
                .map_err(|_| DnsConfigError::Invalid(content.to_string()))?,
        )],
        "dot" => encrypted_server_configs(
            resolve_dns(bootstrap, content).await?.as_slice(),
            ConnectionConfig::tls(content.into()),
        ),
        "doh" => encrypted_server_configs(
            resolve_dns(bootstrap, content).await?.as_slice(),
            ConnectionConfig::https(content.into(), None),
        ),
        "dot-preset" => match content {
            "cloudflare" | "cf" => ResolverConfig::tls(&CLOUDFLARE).name_servers,
            "quad9" => ResolverConfig::tls(&QUAD9).name_servers,
            _ => return Err(DnsConfigError::InvalidPreset("dot", content.to_string())),
        },
        "doh-preset" => match content {
            "cloudflare" | "cf" => ResolverConfig::https(&CLOUDFLARE).name_servers,
            "quad9" => ResolverConfig::https(&QUAD9).name_servers,
            "google" => ResolverConfig::https(&GOOGLE).name_servers,
            _ => return Err(DnsConfigError::InvalidPreset("doh", content.to_string())),
        },
        _ => return Err(DnsConfigError::InvalidType(proto.to_string())),
    }))
}

pub fn extract_address(group: &[Vec<NameServerConfig>]) -> Vec<IpAddr> {
    group
        .iter()
        .flat_map(|configs| configs.iter().map(|config| config.ip))
        .collect()
}

fn default_resolver_opt() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(1600);
    opts.attempts = 3;
    opts
}

struct DhcpDnsRecord {
    iface: String,
    iface_addr: IpAddr,
    ns_addr: IpAddr,
    last_checked: std::time::Instant,
    resolver: Arc<Resolver<IfaceProvider>>,
}

impl DhcpDnsRecord {
    pub fn new(iface: &str) -> Self {
        let mut iface_addr = crate::platform::get_iface_address(iface).ok();
        let ns_addr = match crate::platform::dhcp::get_dhcp_dns(iface) {
            Ok(addr) => addr,
            Err(e) => {
                tracing::warn!(
                    "DHCP DNS: iface={}, iface_addr={:?}, error={}, use empty address",
                    iface,
                    iface_addr,
                    e
                );
                // we don't want the replayable fault stop the program from running
                // e.g. start offline but soon connect to a network with DHCP
                iface_addr = None;
                IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
            }
        };
        Self {
            iface: iface.to_string(),
            iface_addr: iface_addr.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            ns_addr,
            last_checked: std::time::Instant::now(),
            resolver: Self::create_resolver(ns_addr, iface),
        }
    }

    // return if the record is updated
    pub fn refresh(&mut self) -> Result<bool, DnsError> {
        if self.last_checked.elapsed() < Duration::from_secs(30) {
            Ok(false)
        } else {
            // when error occurs, update the record in a best-effort way
            let addr = crate::platform::get_iface_address(&self.iface)
                .map_err(|_| DnsError::DhcpNameServer("failed to get iface address"))?;
            if addr != self.iface_addr {
                let new_dns = crate::platform::dhcp::get_dhcp_dns(&self.iface)?;
                self.iface_addr = addr;
                self.ns_addr = new_dns;
                self.last_checked = std::time::Instant::now();
                self.resolver = Self::create_resolver(new_dns, &self.iface);
                Ok(true)
            } else {
                self.last_checked = std::time::Instant::now();
                Ok(false)
            }
        }
    }

    fn create_resolver(new_dns: IpAddr, iface: &str) -> Arc<Resolver<IfaceProvider>> {
        let cfg = ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp(new_dns)]);
        Arc::new(
            Resolver::builder_with_config(cfg, IfaceProvider::new(iface))
                .with_options(default_resolver_opt())
                .build()
                .expect("rustls miscompiled"),
        )
    }

    pub fn get_resolver(&self) -> Arc<Resolver<IfaceProvider>> {
        self.resolver.clone()
    }
}

enum AuxiliaryResolver<T> {
    Resolver(T),
    Dhcp(Mutex<DhcpDnsRecord>),
}

impl<T> AuxiliaryResolver<T> {
    pub fn new_normal(resolver: T) -> Self {
        Self::Resolver(resolver)
    }

    pub fn new_dhcp(iface: &str) -> Self {
        let record = DhcpDnsRecord::new(iface);
        Self::Dhcp(Mutex::new(record))
    }
}
