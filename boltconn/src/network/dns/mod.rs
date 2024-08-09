mod bootstrap;
#[allow(clippy::module_inception)]
mod dns;
mod dns_table;
mod hosts;
mod ns_policy;
mod provider;

use crate::config::DnsConfigError;
use crate::proxy::error::DnsError;
pub use bootstrap::BootstrapResolver;
pub use dns::{Dns, GenericDns};
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::AsyncResolver;
pub use ns_policy::NameserverPolicies;
use provider::IfaceProvider;
use std::net::{IpAddr, SocketAddr};

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
) -> Result<Vec<NameServerConfigGroup>, DnsConfigError> {
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
) -> Result<NameServerConfigGroup, DnsConfigError> {
    Ok(match proto {
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
    })
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
