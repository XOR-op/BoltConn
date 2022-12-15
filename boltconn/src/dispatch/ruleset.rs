use crate::config::RuleSchema;
use crate::dispatch::rule::{Rule, RuleBuilder, RuleImpl};
use crate::dispatch::{ConnInfo, GeneralProxy, Proxy, ProxyGroup, ProxyImpl};
use crate::platform::process::NetworkType;
use crate::proxy::NetworkAddr;
use aho_corasick::AhoCorasick;
use ipnet::{IpNet, Ipv4Net};
use radix_trie::{Trie, TrieCommon};
use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use crate::common::host_matcher::{HostMatcherBuilder, HostMatcher};

fn ip4_to_vec(ip: Ipv4Addr) -> Vec<u8> {
    let mut ret = vec![0; 32];
    for (idx, oct) in ip.octets().iter().enumerate() {
        for i in (0..8).rev() {
            ret[idx * 8 + i] = if oct & (1 << i) != 0 { 1 } else { 0 };
        }
    }
    ret
}

fn ip4net_to_vec(ip: Ipv4Net) -> Vec<u8> {
    let mut ret = Vec::with_capacity(ip.prefix_len() as usize);
    let prefix_len = ip.prefix_len();
    let idx = 0;
    for oct in ip.addr().octets() {
        for i in (0..8).rev() {
            if idx == prefix_len {
                return ret;
            }
            ret.push(if oct & (1 << i) != 0 { 1 } else { 0 })
        }
    }
    ret
}

/// Matcher for rules in the same group
pub struct RuleSet {
    domain: HostMatcher,
    ip: Trie<Vec<u8>, bool>,
    port: HashSet<u16>,
    domain_keyword: AhoCorasick,
    process_name: AhoCorasick,
}

impl Debug for RuleSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RULE-SET")
    }
}

impl RuleSet {
    pub fn matches(&self, info: &ConnInfo) -> bool {
        // do NOT perform DNS lookup
        let port = match &info.dst {
            NetworkAddr::Raw(addr) => {
                if let IpAddr::V4(v4) = addr.ip() {
                    if let Some(result) = self.ip.get_ancestor(ip4_to_vec(v4).as_slice()) {
                        if result.key().is_some() {
                            // IP-CIDR rule
                            return true;
                        }
                    }
                }
                addr.port()
            }
            NetworkAddr::DomainName { domain_name, port } => {
                if self.domain.matches(domain_name) || self.domain_keyword.is_match(domain_name.as_str()) {
                    return true;
                }
                port.clone()
            }
        };
        if self.port.contains(&port) {
            return true;
        }
        if let Some(proc) = &info.process_info {
            if self.process_name.is_match(proc.name.as_str()) {
                // PROCESS-NAME
                return true;
            }
        }
        false
    }
}

pub struct RuleSetBuilder {
    domain: HostMatcherBuilder,
    domain_keyword: Vec<String>,
    ip_cidr: Vec<(Vec<u8>, bool)>,
    process_name: Vec<String>,
    port: HashSet<u16>,
}

impl RuleSetBuilder {
    pub fn new(payload: RuleSchema) -> Option<Self> {
        let mut retval = Self {
            domain: HostMatcherBuilder::new(),
            domain_keyword: vec![],
            ip_cidr: vec![],
            process_name: vec![],
            port: HashSet::new(),
        };
        let fake = GeneralProxy::Single(Arc::new(Proxy::new("FAKE", ProxyImpl::Direct)));
        for str in &payload.payload {
            if let Some(rule) = RuleBuilder::parse_ruleset(str, fake.clone()) {
                match rule.get_impl() {
                    RuleImpl::ProcessName(pn) => retval.process_name.push(pn.clone()),
                    RuleImpl::Domain(dn) => retval.domain.add_exact(dn.as_str()),
                    RuleImpl::DomainSuffix(sfx) => retval.domain.add_suffix(sfx.as_str()),
                    RuleImpl::DomainKeyword(kw) => retval.domain_keyword.push(kw.clone()),
                    RuleImpl::IpCidr(ip) => match ip {
                        IpNet::V4(v4) => retval.ip_cidr.push((ip4net_to_vec(v4.clone()), true)),
                        IpNet::V6(_) => tracing::warn!("IpCidr6 is not supported now: {:?}", rule),
                    },
                    RuleImpl::Port(p) => {
                        retval.port.insert(*p);
                    }
                    _ => return None,
                }
            } else {
                return None;
            }
        }
        Some(retval)
    }

    pub fn merge(mut self, rhs: Self) -> Self {
        self.domain.merge(rhs.domain);
        self.ip_cidr.extend(rhs.ip_cidr.into_iter());
        self.process_name.extend(rhs.process_name.into_iter());
        self.port.extend(rhs.port.into_iter());
        self.domain_keyword.extend(rhs.domain_keyword.into_iter());
        self
    }

    pub fn build(self) -> RuleSet {
        RuleSet {
            domain: self.domain.build(),
            ip: Trie::from_iter(self.ip_cidr.into_iter()),
            port: self.port,
            domain_keyword: AhoCorasick::new_auto_configured(self.domain_keyword.as_slice()),
            process_name: AhoCorasick::new_auto_configured(self.process_name.as_slice()),
        }
    }
}

#[ignore]
#[test]
fn test_rule_provider() {
    let config_text = fs::read_to_string("../_private/config/Rules/Apple").unwrap();
    let deserialized: RuleSchema = serde_yaml::from_str(&config_text).unwrap();
    println!("{:?}", deserialized);
    let builder = RuleSetBuilder::new(deserialized);
    assert!(builder.is_some());
    let ruleset = builder.unwrap().build();
    // println!("kw:{}, domain:{}", ruleset.domain_keyword.pattern_count(), ruleset.domain.len());
    let info1 = ConnInfo {
        src: "127.0.0.1:12345".parse().unwrap(),
        dst: NetworkAddr::DomainName {
            domain_name: "kb.apple.com".to_string(),
            port: 1234,
        },
        connection_type: NetworkType::TCP,
        process_info: None,
    };
    assert!(ruleset.matches(&info1));
    let info2 = ConnInfo {
        src: "127.0.0.1:12345".parse().unwrap(),
        dst: NetworkAddr::DomainName {
            domain_name: "apple.com".to_string(),
            port: 1234,
        },
        connection_type: NetworkType::TCP,
        process_info: None,
    };
    assert!(ruleset.matches(&info2));
    let info3 = ConnInfo {
        src: "127.0.0.1:12345".parse().unwrap(),
        dst: NetworkAddr::DomainName {
            domain_name: "icloud.com.akadns.net.com".to_string(),
            port: 1234,
        },
        connection_type: NetworkType::TCP,
        process_info: None,
    };
    assert!(ruleset.matches(&info3));
    let info4 = ConnInfo {
        src: "127.0.0.1:12345".parse().unwrap(),
        dst: NetworkAddr::DomainName {
            domain_name: "apple.io".to_string(),
            port: 1234,
        },
        connection_type: NetworkType::TCP,
        process_info: None,
    };
    assert!(!ruleset.matches(&info4));
}
