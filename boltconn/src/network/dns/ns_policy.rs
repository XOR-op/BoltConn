use crate::common::host_matcher::{HostMatcher, HostMatcherBuilder};
use crate::config::DnsConfigError;
use crate::network::dns::bootstrap::BootstrapResolver;
use crate::network::dns::parse_single_dns;
use crate::network::dns::provider::{IfaceProvider, PlainProvider};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::AsyncResolver;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

pub struct NameserverPolicies {
    matchers: Vec<(HostMatcher, DispatchedDnsResolver)>,
}

pub(super) enum DispatchedDnsResolver {
    Iface(AsyncResolver<GenericConnector<IfaceProvider>>),
    Plain(AsyncResolver<GenericConnector<PlainProvider>>),
}

impl NameserverPolicies {
    pub async fn new(
        policies: &HashMap<String, String>,
        bootstrap: &BootstrapResolver,
        outbound_iface: &str,
    ) -> Result<Self, DnsConfigError> {
        let mut builder: HashMap<
            (String, String),
            (HostMatcherBuilder, NameServerConfigGroup, bool),
        > = HashMap::new();
        for (host, policy) in policies {
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
        let res = builder
            .into_iter()
            .map(|(_, (m, c, follow_tun))| {
                let matcher = m.build();
                let resolver = if follow_tun {
                    DispatchedDnsResolver::Plain(AsyncResolver::new(
                        ResolverConfig::from_parts(None, vec![], c),
                        ResolverOpts::default(),
                        GenericConnector::new(PlainProvider::new()),
                    ))
                } else {
                    DispatchedDnsResolver::Iface(AsyncResolver::new(
                        ResolverConfig::from_parts(None, vec![], c),
                        ResolverOpts::default(),
                        GenericConnector::new(IfaceProvider::new(outbound_iface)),
                    ))
                };
                (matcher, resolver)
            })
            .collect();
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
