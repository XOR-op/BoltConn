use crate::common::host_matcher::HostMatcher;
use std::collections::HashMap;
use std::net::IpAddr;

pub(super) struct HostsResolver {
    matcher: HostMatcher,
    exact_resolver: HashMap<String, IpAddr>,
    suffix_resolver: Vec<(String, IpAddr)>,
}

impl HostsResolver {
    pub fn new(hosts: &HashMap<String, IpAddr>) -> Self {
        let mut exact_resolver = HashMap::new();
        let mut suffix_resolver = Vec::new();
        let mut builder = HostMatcher::builder();
        for (host, ip) in hosts {
            if let Some(stripped_host) = host.strip_prefix("*.") {
                suffix_resolver.push((stripped_host.to_string(), *ip));
                builder.add_suffix(stripped_host);
            } else {
                exact_resolver.insert(host.to_string(), *ip);
                builder.add_exact(host);
            }
        }
        Self {
            matcher: builder.build(),
            exact_resolver,
            suffix_resolver,
        }
    }

    pub fn empty() -> Self {
        Self {
            matcher: HostMatcher::builder().build(),
            exact_resolver: HashMap::new(),
            suffix_resolver: Vec::new(),
        }
    }

    pub fn resolve(&self, host: &str) -> Option<IpAddr> {
        if !self.matcher.matches(host) {
            return None;
        } else if let Some(ip) = self.exact_resolver.get(host) {
            return Some(*ip);
        }
        for (suffix, ip) in &self.suffix_resolver {
            if host.ends_with(suffix) {
                return Some(*ip);
            }
        }
        None
    }
}
