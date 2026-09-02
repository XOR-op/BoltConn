use crate::common::host_matcher::{HostMatcher, HostMatcherBuilder};
use crate::config::DnsConfigError;
use crate::network::dns::bootstrap::BootstrapResolver;
use crate::network::dns::default_resolver_opt;
use crate::network::dns::observability::{
    DnsResolverIdentity, DnsResolverRecord, identity_from_config,
};
use crate::network::dns::provider::{IfaceProvider, PlainProvider};
use crate::network::dns::{AuxiliaryResolver, NameServerConfigEnum, parse_single_dns};
use boltapi::{DnsAttemptScope, DnsScope, RouteEgress};
use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverConfig;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

type PolicyGroupKey = (String, String, bool);
type PolicyGroup = (HostMatcherBuilder, Vec<String>, NameServerConfigEnum);

pub struct NameserverPolicies {
    entries: Vec<PolicyResolver>,
}

pub(super) enum DispatchedDnsResolver {
    Iface(AuxiliaryResolver<Resolver<IfaceProvider>>),
    Plain(Resolver<PlainProvider>),
}

pub(super) struct PolicyResolver {
    matcher: HostMatcher,
    pub matchers: Vec<String>,
    pub matcher_summary: String,
    pub resolver: DispatchedDnsResolver,
    pub identity: DnsResolverIdentity,
    pub record: Arc<DnsResolverRecord>,
}

impl NameserverPolicies {
    pub async fn new(
        policies: &HashMap<String, String>,
        bootstrap: &BootstrapResolver,
        outbound_iface: &str,
    ) -> Result<Self, DnsConfigError> {
        let builder = parse_policy_groups(policies, bootstrap).await?;
        let res = {
            let mut res = Vec::new();
            for ((_, _, follow_tun), (matcher, mut matchers, config)) in builder {
                matchers.sort();
                matchers.dedup();
                let matcher_summary = canonical_matcher_summary(&matchers);
                let via = match &config {
                    NameServerConfigEnum::Dhcp(interface) => RouteEgress::Interface {
                        name: interface.clone(),
                    },
                    NameServerConfigEnum::Normal(_) if follow_tun => RouteEgress::Direct,
                    NameServerConfigEnum::Normal(_) => RouteEgress::Interface {
                        name: outbound_iface.to_string(),
                    },
                };
                let identity = identity_from_config(&config, via, 1600, 3);
                let record = Arc::new(DnsResolverRecord::new(&identity));
                let resolver = match config {
                    NameServerConfigEnum::Normal(c) => {
                        if follow_tun {
                            DispatchedDnsResolver::Plain(
                                Resolver::builder_with_config(
                                    ResolverConfig::from_parts(None, vec![], c),
                                    PlainProvider::new(),
                                )
                                .with_options(default_resolver_opt())
                                .build()
                                .expect("rustls miscompiled"),
                            )
                        } else {
                            DispatchedDnsResolver::Iface(AuxiliaryResolver::new_normal(
                                Resolver::builder_with_config(
                                    ResolverConfig::from_parts(None, vec![], c),
                                    IfaceProvider::new(outbound_iface),
                                )
                                .with_options(default_resolver_opt())
                                .build()
                                .expect("rustls miscompiled"),
                            ))
                        }
                    }
                    NameServerConfigEnum::Dhcp(iface) => {
                        DispatchedDnsResolver::Iface(AuxiliaryResolver::new_dhcp(&iface))
                    }
                };
                res.push(PolicyResolver {
                    matcher: matcher.build(),
                    matchers,
                    matcher_summary,
                    resolver,
                    identity,
                    record,
                });
            }
            // Policy order is observable. Canonical sorting avoids HashMap
            // iteration order changing both selection and list presentation.
            res.sort_by(|left, right| left.matchers.cmp(&right.matchers));
            res
        };
        Ok(Self { entries: res })
    }

    /// Check policy syntax and nameserver values without constructing resolvers.
    pub(crate) async fn validate(
        policies: &HashMap<String, String>,
        bootstrap: &BootstrapResolver,
    ) -> Result<(), DnsConfigError> {
        parse_policy_groups(policies, bootstrap).await.map(|_| ())
    }

    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(super) fn resolve(&self, host: &str) -> Option<&PolicyResolver> {
        self.entries
            .iter()
            .find(|entry| entry.matcher.matches(host))
    }

    pub(super) fn entries(&self) -> impl Iterator<Item = &PolicyResolver> {
        self.entries.iter()
    }

    pub(super) fn entries_mut(&mut self) -> impl Iterator<Item = &mut PolicyResolver> {
        self.entries.iter_mut()
    }
}

async fn parse_policy_groups(
    policies: &HashMap<String, String>,
    bootstrap: &BootstrapResolver,
) -> Result<HashMap<PolicyGroupKey, PolicyGroup>, DnsConfigError> {
    let mut groups: HashMap<PolicyGroupKey, PolicyGroup> = HashMap::new();
    for (host, policy) in policies {
        // Policies contain a nameserver and an optional `plain` routing mode.
        let parts: Vec<&str> = policy.split(',').map(str::trim).collect();
        let follow_tun = match parts.as_slice() {
            [_, _] => false,
            [_, _, "plain"] => true,
            _ => return Err(DnsConfigError::Invalid(policy.clone())),
        };
        let key = (parts[0].to_string(), parts[1].to_string(), follow_tun);

        match groups.entry(key) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().0.add_auto(host);
                entry.get_mut().1.push(host.clone());
            }
            Entry::Vacant(entry) => {
                let nameserver =
                    parse_single_dns(entry.key().0.as_str(), entry.key().1.as_str(), bootstrap)
                        .await?;
                let mut matcher = HostMatcher::builder();
                matcher.add_auto(host);
                entry.insert((matcher, vec![host.clone()], nameserver));
            }
        }
    }
    Ok(groups)
}

impl PolicyResolver {
    pub(super) fn scope(&self) -> DnsScope {
        DnsScope::Policy {
            matchers: self.matchers.clone(),
        }
    }

    pub(super) fn attempt_scope(&self) -> DnsAttemptScope {
        DnsAttemptScope::Policy {
            matcher: self.matcher_summary.clone(),
        }
    }

    pub(super) fn refresh_dhcp_endpoint(&self) {
        if let DispatchedDnsResolver::Iface(resolver) = &self.resolver
            && let Some(endpoint) = resolver.current_dhcp_endpoint()
        {
            self.record.set_current_endpoints(vec![endpoint]);
        }
    }
}

fn canonical_matcher_summary(matchers: &[String]) -> String {
    match matchers {
        [] => String::new(),
        [only] => only.clone(),
        [first, rest @ ..] => format!("{first},+{}", rest.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::canonical_matcher_summary;

    #[test]
    fn matcher_summary_is_compact_and_deterministic() {
        assert_eq!(canonical_matcher_summary(&[]), "");
        assert_eq!(canonical_matcher_summary(&["*.corp".to_string()]), "*.corp");
        assert_eq!(
            canonical_matcher_summary(&[
                "*.corp".to_string(),
                "api.corp".to_string(),
                "git.corp".to_string(),
            ]),
            "*.corp,+2"
        );
    }
}
