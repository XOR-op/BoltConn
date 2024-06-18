#[allow(clippy::module_inception)]
mod dns;
mod dns_table;
mod hosts;
mod ns_policy;
mod provider;

use crate::network::dns::provider::IfaceProvider;
pub use dns::{Dns, GenericDns};
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::AsyncResolver;
pub use ns_policy::NameserverPolicies;
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

async fn resolve_dns(
    bootstrap: Option<&AsyncResolver<GenericConnector<IfaceProvider>>>,
    dn: &str,
) -> anyhow::Result<Vec<IpAddr>> {
    let Some(resolver) = bootstrap else {
        return Err(anyhow::anyhow!(
            "DoT requires bootstrap udp DNS nameserver {}",
            dn
        ));
    };
    let Ok(ips) = resolver.lookup_ip(dn).await else {
        return Err(anyhow::anyhow!("Failed to resolve DNS {}", dn));
    };
    let result: Vec<IpAddr> = ips.iter().collect();
    if result.is_empty() {
        Err(anyhow::anyhow!("Failed to resolve DNS {}", dn))
    } else {
        Ok(result)
    }
}

pub fn new_bootstrap_resolver(
    iface_name: &str,
    addr: &[IpAddr],
) -> anyhow::Result<AsyncResolver<GenericConnector<IfaceProvider>>> {
    let cfg = ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from(
            addr.iter()
                .map(|ip| NameServerConfig::new(SocketAddr::new(*ip, 53), Protocol::Udp))
                .collect::<Vec<NameServerConfig>>(),
        ),
    );
    let resolver = AsyncResolver::new(
        cfg,
        ResolverOpts::default(),
        GenericConnector::new(IfaceProvider::new(iface_name)),
    );
    Ok(resolver)
}

pub async fn parse_dns_config(
    lines: impl Iterator<Item = &String>,
    bootstrap: Option<&AsyncResolver<GenericConnector<IfaceProvider>>>,
) -> anyhow::Result<Vec<NameServerConfigGroup>> {
    let mut arr = Vec::new();
    for l in lines {
        let parts: Vec<&str> = l.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid dns format {}", l));
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
    bootstrap: Option<&AsyncResolver<GenericConnector<IfaceProvider>>>,
) -> anyhow::Result<NameServerConfigGroup> {
    Ok(match proto {
        "udp" => NameServerConfigGroup::from(vec![NameServerConfig::new(
            SocketAddr::new(content.parse::<IpAddr>()?, 53),
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
            _ => return Err(anyhow::anyhow!("Unknown DoT preset {}", content)),
        },
        "doh-preset" => match content {
            "cloudflare" | "cf" => NameServerConfigGroup::cloudflare_https(),
            "quad9" => NameServerConfigGroup::quad9_https(),
            "google" => NameServerConfigGroup::google_https(),
            _ => return Err(anyhow::anyhow!("Unknown DoH preset {}", content)),
        },
        _ => {
            return Err(anyhow::anyhow!("Unknown DNS type {}", proto));
        }
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
