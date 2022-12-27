mod dns;
mod dns_table;

pub use dns::Dns;
use std::net::{IpAddr, SocketAddr};
use trust_dns_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::TokioAsyncResolver;

fn add_tls_server(
    arr: &mut Vec<NameServerConfig>,
    ips: &[IpAddr],
    protocol: Protocol,
    port: u16,
    tls_name: &str,
) {
    for ip in ips {
        arr.push(NameServerConfig {
            socket_addr: SocketAddr::new(*ip, port),
            protocol,
            tls_dns_name: Some(tls_name.to_string()),
            trust_nx_responses: false,
            tls_config: None,
            bind_addr: None,
        })
    }
}

async fn resolve_dns(
    bootstrap: &Option<TokioAsyncResolver>,
    dn: &str,
) -> anyhow::Result<Vec<IpAddr>> {
    let Some(resolver) = bootstrap else {
        return Err(anyhow::anyhow!("DoT requires bootstrap udp DNS nameserver {}", dn));
    };
    let Ok(ips) = resolver.lookup_ip(dn).await else {
        return Err(anyhow::anyhow!("Failed to resolve DNS {}", dn));
    };
    let result: Vec<IpAddr> = ips.iter().collect();
    return if result.is_empty() {
        Err(anyhow::anyhow!("Failed to resolve DNS {}", dn))
    } else {
        Ok(result)
    };
}

pub fn new_bootstrap_resolver(addr: &[IpAddr]) -> anyhow::Result<TokioAsyncResolver> {
    let cfg = ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from(
            addr.iter()
                .map(|ip| NameServerConfig::new(SocketAddr::new(*ip, 53), Protocol::Udp))
                .collect::<Vec<NameServerConfig>>(),
        ),
    );
    let resolver = TokioAsyncResolver::tokio(cfg, ResolverOpts::default())?;
    Ok(resolver)
}

pub async fn parse_dns_config(
    lines: &Vec<String>,
    bootstrap: Option<TokioAsyncResolver>,
) -> anyhow::Result<NameServerConfigGroup> {
    let mut arr = Vec::new();
    for l in lines {
        let parts: Vec<&str> = l.split(",").map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid dns format {}", l));
        }
        let (proto, content) = (
            parts.get(0).unwrap().to_string(),
            parts.get(1).unwrap().to_string(),
        );
        match proto.as_str() {
            "udp" => {
                arr.push(NameServerConfig::new(
                    SocketAddr::new(content.parse::<IpAddr>()?, 53),
                    Protocol::Udp,
                ));
            }
            "dot" => {
                add_tls_server(
                    &mut arr,
                    resolve_dns(&bootstrap, content.as_str()).await?.as_slice(),
                    Protocol::Tls,
                    853,
                    content.as_str(),
                );
            }
            "doh" => {
                add_tls_server(
                    &mut arr,
                    resolve_dns(&bootstrap, content.as_str()).await?.as_slice(),
                    Protocol::Https,
                    443,
                    content.as_str(),
                );
            }
            "dot-preset" => {
                let ns_cfg_group = match content.as_str() {
                    "cloudflare" | "cf" => NameServerConfigGroup::cloudflare_tls(),
                    "quad9" => NameServerConfigGroup::quad9_tls(),
                    _ => return Err(anyhow::anyhow!("Unknown DoT preset {}", content)),
                };
                arr.extend(ns_cfg_group.into_inner());
            }
            "doh-preset" => {
                let ns_cfg_group = match content.as_str() {
                    "cloudflare" | "cf" => NameServerConfigGroup::cloudflare_https(),
                    "quad9" => NameServerConfigGroup::quad9_https(),
                    "google" => NameServerConfigGroup::google_https(),
                    _ => return Err(anyhow::anyhow!("Unknown DoH preset {}", content)),
                };
                arr.extend(ns_cfg_group.into_inner());
            }
            _ => {
                return Err(anyhow::anyhow!("Unknown DNS type {}", proto));
            }
        }
    }
    Ok(NameServerConfigGroup::from(arr))
}
