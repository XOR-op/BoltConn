use crate::common::host_matcher::{HostMatcher, HostMatcherBuilder};
use crate::config::DnsConfigError;
use crate::network::dns::bootstrap::BootstrapResolver;
use crate::network::dns::provider::{IfaceProvider, PlainProvider};
use crate::network::dns::{AuxiliaryResolver, NameServerConfigEnum, parse_single_dns};
use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverConfig;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

pub struct NameserverPolicies {
    matchers: Vec<(HostMatcher, DispatchedDnsResolver)>,
}

pub(super) enum DispatchedDnsResolver {
    Iface(AuxiliaryResolver<Resolver<IfaceProvider>>),
    Plain(Resolver<PlainProvider>),
}

impl NameserverPolicies {
    pub async fn new(
        policies: &HashMap<String, String>,
        bootstrap: &BootstrapResolver,
        outbound_iface: &str,
    ) -> Result<Self, DnsConfigError> {
        let mut builder: HashMap<
            (String, String),
            (HostMatcherBuilder, NameServerConfigEnum, bool),
        > = HashMap::new();
        for (host, policy) in policies {
            /*
             * Examples:
             * - "*.example.com": doh, 1.1.1.1
             * - "dns-through-proxy.example.org", udp, 8.8.8.8, plain
             * - "*.msftconnecttest.com", udp, dhcp://en0
             */
            let parts: Vec<&str> = policy.split(',').map(|s| s.trim()).collect();
            let follow_tun = match parts.len() {
                2 => false,
                3 => {
                    if *parts.get(2).unwrap() != "plain" {
                        return Err(DnsConfigError::Invalid(policy.clone()));
                    }
                    true
                }
                _ => {
                    return Err(DnsConfigError::Invalid(policy.clone()));
                }
            };
            let key = (
                parts.first().unwrap().to_string(),
                parts.get(1).unwrap().to_string(),
            );

            // clustering
            match builder.entry(key) {
                Entry::Occupied(mut e) => e.get_mut().0.add_auto(host),
                Entry::Vacant(e) => {
                    let ns_config =
                        parse_single_dns(e.key().0.as_str(), e.key().1.as_str(), bootstrap).await?;
                    let mut matcher = HostMatcher::builder();
                    matcher.add_auto(host);
                    e.insert((matcher, ns_config, follow_tun));
                }
            }
        }
        let res = {
            let mut res = Vec::new();
            for (_, (m, c, follow_tun)) in builder.into_iter() {
                let resolver = match c {
                    NameServerConfigEnum::Normal(c) => {
                        if follow_tun {
                            DispatchedDnsResolver::Plain(
                                Resolver::builder_with_config(
                                    ResolverConfig::from_parts(None, vec![], c),
                                    PlainProvider::new(),
                                )
                                .build()
                                .expect("rustls miscompiled"),
                            )
                        } else {
                            DispatchedDnsResolver::Iface(AuxiliaryResolver::new_normal(
                                Resolver::builder_with_config(
                                    ResolverConfig::from_parts(None, vec![], c),
                                    IfaceProvider::new(outbound_iface),
                                )
                                .build()
                                .expect("rustls miscompiled"),
                            ))
                        }
                    }
                    NameServerConfigEnum::Dhcp(iface) => {
                        DispatchedDnsResolver::Iface(AuxiliaryResolver::new_dhcp(&iface))
                    }
                };
                let matcher = m.build();
                res.push((matcher, resolver))
            }
            res
        };
        Ok(Self { matchers: res })
    }

    pub fn empty() -> Self {
        Self {
            matchers: Vec::new(),
        }
    }

    pub(super) fn resolve(&self, host: &str) -> Option<&DispatchedDnsResolver> {
        for (matcher, resolver) in &self.matchers {
            if matcher.matches(host) {
                return Some(resolver);
            }
        }
        None
    }
}
