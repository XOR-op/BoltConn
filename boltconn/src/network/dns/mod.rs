mod bootstrap;
#[allow(clippy::module_inception)]
mod dns;
mod dns_table;
mod hijack_ctrl;
mod hosts;
mod ns_policy;
mod provider;

use crate::config::DnsConfigError;
use crate::proxy::error::{DnsError, TransportError};
pub use bootstrap::BootstrapResolver;
pub use dns::{Dns, GenericDns};
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::AsyncResolver;
pub use hijack_ctrl::DnsHijackController;
pub use ns_policy::NameserverPolicies;
use provider::IfaceProvider;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub enum NameServerConfigEnum {
    Normal(NameServerConfigGroup),
    Dhcp(String),
}

fn add_tls_server(
    ips: &[IpAddr],
    protocol: Protocol,
    port: u16,
    tls_name: &str,
) -> NameServerConfigGroup {
    let mut arr = vec![];
    for ip in ips {
        arr.push(NameServerConfig {
            socket_addr: SocketAddr::new(*ip, port),
            protocol,
            tls_dns_name: Some(tls_name.to_string()),
            trust_negative_responses: false,
            tls_config: None,
            bind_addr: None,
        })
    }
    NameServerConfigGroup::from(arr)
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
        NameServerConfigGroup::from(
            addr.iter()
                .map(|ip| NameServerConfig::new(SocketAddr::new(*ip, 53), Protocol::Udp))
                .collect::<Vec<NameServerConfig>>(),
        ),
    );
    BootstrapResolver::new(AsyncResolver::new(
        cfg,
        ResolverOpts::default(),
        GenericConnector::new(IfaceProvider::new(iface_name)),
    ))
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
        "udp" => NameServerConfigGroup::from(vec![NameServerConfig::new(
            SocketAddr::new(
                content
                    .parse::<IpAddr>()
                    .map_err(|_| DnsConfigError::Invalid(content.to_string()))?,
                53,
            ),
            Protocol::Udp,
        )]),
        "dot" => add_tls_server(
            resolve_dns(bootstrap, content).await?.as_slice(),
            Protocol::Tls,
            853,
            content,
        ),
        "doh" => add_tls_server(
            resolve_dns(bootstrap, content).await?.as_slice(),
            Protocol::Https,
            443,
            content,
        ),
        "dot-preset" => match content {
            "cloudflare" | "cf" => NameServerConfigGroup::cloudflare_tls(),
            "quad9" => NameServerConfigGroup::quad9_tls(),
            _ => return Err(DnsConfigError::InvalidPreset("dot", content.to_string())),
        },
        "doh-preset" => match content {
            "cloudflare" | "cf" => NameServerConfigGroup::cloudflare_https(),
            "quad9" => NameServerConfigGroup::quad9_https(),
            "google" => NameServerConfigGroup::google_https(),
            _ => return Err(DnsConfigError::InvalidPreset("doh", content.to_string())),
        },
        _ => return Err(DnsConfigError::InvalidType(proto.to_string())),
    }))
}

pub fn extract_address(group: &[NameServerConfigGroup]) -> Vec<IpAddr> {
    group
        .iter()
        .flat_map(|cg| {
            cg.iter()
                .map(|cfg| cfg.socket_addr.ip())
                .collect::<Vec<IpAddr>>()
        })
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
    resolver: Arc<AsyncResolver<GenericConnector<IfaceProvider>>>,
}

impl DhcpDnsRecord {
    pub fn new(iface: &str) -> Result<Self, DnsError> {
        let iface_addr = crate::platform::get_iface_address(iface)
            .map_err(|_| DnsError::DhcpNameServer("failed to get iface address"))?;
        let ns_addr = crate::platform::dhcp::get_dhcp_dns(iface)?;
        tracing::debug!(
            "DHCP DNS: iface={}, iface_addr={}, ns_addr={}",
            iface,
            iface_addr,
            ns_addr
        );
        Ok(Self {
            iface: iface.to_string(),
            iface_addr,
            ns_addr,
            last_checked: std::time::Instant::now(),
            resolver: Self::create_resolver(ns_addr, iface),
        })
    }

    // return if the record is updated
    pub fn refresh(&mut self) -> Result<bool, TransportError> {
        if self.last_checked.elapsed() < Duration::from_secs(30) {
            Ok(false)
        } else {
            // when error occurs, update the record in a best-effort way
            let addr = crate::platform::get_iface_address(&self.iface)?;
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

    fn create_resolver(
        new_dns: IpAddr,
        iface: &str,
    ) -> Arc<AsyncResolver<GenericConnector<IfaceProvider>>> {
        let cfg = ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from(vec![NameServerConfig::new(
                SocketAddr::new(new_dns, 53),
                Protocol::Udp,
            )]),
        );
        Arc::new(AsyncResolver::new(
            cfg,
            default_resolver_opt(),
            GenericConnector::new(IfaceProvider::new(iface)),
        ))
    }

    pub fn get_resolver(&self) -> Arc<AsyncResolver<GenericConnector<IfaceProvider>>> {
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

    pub fn new_dhcp(iface: &str) -> Result<Self, DnsError> {
        let record = DhcpDnsRecord::new(iface)?;
        Ok(Self::Dhcp(Mutex::new(record)))
    }
}
