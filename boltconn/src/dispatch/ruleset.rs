use crate::common::host_matcher::{HostMatcher, HostMatcherBuilder};
use crate::config::RuleSchema;
use crate::dispatch::rule::{RuleBuilder, RuleImpl};
use crate::dispatch::{ConnInfo, GeneralProxy, Proxy, ProxyImpl};
use crate::proxy::NetworkAddr;
use aho_corasick::AhoCorasick;
use ip_network_table::IpNetworkTable;
use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::sync::Arc;

/// Matcher for rules in the same group
pub struct RuleSet {
    domain: HostMatcher,
    ip: IpNetworkTable<()>,
    port: HashSet<u16>,
    domain_keyword: AhoCorasick,
    process_name: HashSet<String>,
    process_keyword: AhoCorasick,
    procpath_keyword: AhoCorasick,
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
                if self.ip.longest_match(addr.ip()).is_some() {
                    return true;
                }
                addr.port()
            }
            NetworkAddr::DomainName { domain_name, port } => {
                if self.domain.matches(domain_name)
                    || self.domain_keyword.is_match(domain_name.as_str())
                {
                    return true;
                }
                *port
            }
        };
        if self.port.contains(&port) {
            return true;
        }
        if let Some(proc) = &info.process_info {
            if self.process_name.contains(&proc.name)
                || self.process_keyword.is_match(proc.name.as_str())
                || self.procpath_keyword.is_match(proc.path.as_str())
            {
                return true;
            }
        }
        false
    }
}

pub struct RuleSetBuilder {
    domain: HostMatcherBuilder,
    domain_keyword: Vec<String>,
    ip_cidr: IpNetworkTable<()>,
    process_name: HashSet<String>,
    process_keyword: Vec<String>,
    procpath_keyword: Vec<String>,
    port: HashSet<u16>,
}

impl RuleSetBuilder {
    pub fn new(payload: RuleSchema) -> Option<Self> {
        let mut retval = Self {
            domain: HostMatcherBuilder::new(),
            domain_keyword: vec![],
            ip_cidr: Default::default(),
            process_name: HashSet::new(),
            process_keyword: vec![],
            procpath_keyword: vec![],
            port: HashSet::new(),
        };
        let fake = GeneralProxy::Single(Arc::new(Proxy::new("FAKE", ProxyImpl::Direct)));
        for str in &payload.payload {
            if let Some(rule) = RuleBuilder::parse_ruleset(str, fake.clone()) {
                match rule.get_impl() {
                    RuleImpl::ProcessName(pn) => {
                        retval.process_name.insert(pn.clone());
                    }
                    RuleImpl::ProcessKeyword(kw) => retval.process_keyword.push(kw.clone()),
                    RuleImpl::ProcPathKeyword(kw) => retval.procpath_keyword.push(kw.clone()),
                    RuleImpl::Domain(dn) => retval.domain.add_exact(dn.as_str()),
                    RuleImpl::DomainSuffix(sfx) => retval.domain.add_suffix(sfx.as_str()),
                    RuleImpl::DomainKeyword(kw) => retval.domain_keyword.push(kw.clone()),
                    RuleImpl::IpCidr(ip) => {
                        let ip = ip_network::IpNetwork::new_truncate(ip.addr(), ip.prefix_len())
                            .unwrap();
                        retval.ip_cidr.insert(ip, ());
                    }
                    RuleImpl::Port(p) => {
                        retval.port.insert(*p);
                    }
                    RuleImpl::RuleSet(_) => return None,
                }
            } else {
                return None;
            }
        }
        Some(retval)
    }

    pub fn merge(mut self, rhs: Self) -> Self {
        self.domain.merge(rhs.domain);
        rhs.ip_cidr.iter().for_each(|(ip, _)| {
            let _ = self.ip_cidr.insert(ip, ());
        });
        self.process_name.extend(rhs.process_name.into_iter());
        self.process_keyword.extend(rhs.process_keyword.into_iter());
        self.procpath_keyword
            .extend(rhs.procpath_keyword.into_iter());
        self.port.extend(rhs.port.into_iter());
        self.domain_keyword.extend(rhs.domain_keyword.into_iter());
        self
    }

    pub fn build(self) -> RuleSet {
        RuleSet {
            domain: self.domain.build(),
            ip: self.ip_cidr,
            port: self.port,
            domain_keyword: AhoCorasick::new_auto_configured(self.domain_keyword.as_slice()),
            process_name: self.process_name,
            process_keyword: AhoCorasick::new_auto_configured(self.process_keyword.as_slice()),
            procpath_keyword: AhoCorasick::new_auto_configured(self.procpath_keyword.as_slice()),
        }
    }

    pub fn from_ipaddrs(list: Vec<IpAddr>) -> Self {
        let mut table = IpNetworkTable::new();
        list.iter().for_each(|ip| {
            table.insert(*ip, ());
        });
        Self {
            domain: HostMatcherBuilder::new(),
            domain_keyword: vec![],
            ip_cidr: table,
            process_name: HashSet::new(),
            process_keyword: vec![],
            procpath_keyword: vec![],
            port: HashSet::new(),
        }
    }
}

#[ignore]
#[test]
fn test_rule_provider() {
    use crate::platform::process::NetworkType;
    let config_text = std::fs::read_to_string("../examples/Rules/Apple").unwrap();
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
        connection_type: NetworkType::Tcp,
        process_info: None,
    };
    assert!(ruleset.matches(&info1));
    let info2 = ConnInfo {
        src: "127.0.0.1:12345".parse().unwrap(),
        dst: NetworkAddr::DomainName {
            domain_name: "apple.com".to_string(),
            port: 1234,
        },
        connection_type: NetworkType::Tcp,
        process_info: None,
    };
    assert!(ruleset.matches(&info2));
    let info3 = ConnInfo {
        src: "127.0.0.1:12345".parse().unwrap(),
        dst: NetworkAddr::DomainName {
            domain_name: "icloud.com.akadns.net.com".to_string(),
            port: 1234,
        },
        connection_type: NetworkType::Tcp,
        process_info: None,
    };
    assert!(ruleset.matches(&info3));
    let info4 = ConnInfo {
        src: "127.0.0.1:12345".parse().unwrap(),
        dst: NetworkAddr::DomainName {
            domain_name: "apple.io".to_string(),
            port: 1234,
        },
        connection_type: NetworkType::Tcp,
        process_info: None,
    };
    assert!(!ruleset.matches(&info4));
}
