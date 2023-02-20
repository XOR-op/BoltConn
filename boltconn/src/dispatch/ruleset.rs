use crate::common::host_matcher::{HostMatcher, HostMatcherBuilder};
use crate::config::RuleSchema;
use crate::dispatch::rule::{PortRule, RuleBuilder, RuleImpl};
use crate::dispatch::ConnInfo;
use crate::platform::process::NetworkType;
use crate::proxy::NetworkAddr;
use aho_corasick::AhoCorasick;
use ip_network_table::IpNetworkTable;
use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;

/// Matcher for rules in the same group
pub struct RuleSet {
    name: String,
    domain: HostMatcher,
    ip: IpNetworkTable<()>,
    tcp_port: HashSet<u16>,
    udp_port: HashSet<u16>,
    any_tcp: bool,
    any_udp: bool,
    domain_keyword: AhoCorasick,
    process_name: HashSet<String>,
    process_keyword: AhoCorasick,
    procpath_keyword: AhoCorasick,
}

impl Debug for RuleSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name.as_str())
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
        match info.connection_type {
            NetworkType::Tcp => {
                if self.any_tcp || self.tcp_port.contains(&port) {
                    return true;
                }
            }
            NetworkType::Udp => {
                if self.any_udp || self.udp_port.contains(&port) {
                    return true;
                }
            }
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
    name: String,
    domain: HostMatcherBuilder,
    domain_keyword: Vec<String>,
    ip_cidr: IpNetworkTable<()>,
    process_name: HashSet<String>,
    process_keyword: Vec<String>,
    procpath_keyword: Vec<String>,
    tcp_port: HashSet<u16>,
    udp_port: HashSet<u16>,
    any_tcp: bool,
    any_udp: bool,
}

impl RuleSetBuilder {
    pub fn new(name: &str, payload: RuleSchema) -> Option<Self> {
        let mut retval = Self {
            name: name.to_string(),
            domain: HostMatcherBuilder::new(),
            domain_keyword: vec![],
            ip_cidr: Default::default(),
            process_name: HashSet::new(),
            process_keyword: vec![],
            procpath_keyword: vec![],
            tcp_port: HashSet::new(),
            udp_port: HashSet::new(),
            any_tcp: false,
            any_udp: false,
        };
        for str in &payload.payload {
            if let Some(rule) = RuleBuilder::parse_ruleset(str) {
                match rule {
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
                    RuleImpl::Port(p) => match p {
                        PortRule::Tcp(p) => {
                            retval.tcp_port.insert(p);
                        }
                        PortRule::Udp(p) => {
                            retval.udp_port.insert(p);
                        }
                        PortRule::All(p) => {
                            retval.tcp_port.insert(p);
                            retval.udp_port.insert(p);
                        }
                        PortRule::AnyTcp => retval.any_tcp = true,
                        PortRule::AnyUdp => retval.any_udp = true,
                    },
                    // Slow for ruleset; better to write as a standalone rule
                    RuleImpl::RuleSet(_)
                    | RuleImpl::And(..)
                    | RuleImpl::Or(..)
                    | RuleImpl::Not(_) => return None,
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
        self.tcp_port.extend(rhs.tcp_port.into_iter());
        self.udp_port.extend(rhs.udp_port.into_iter());
        self.any_tcp |= rhs.any_tcp;
        self.any_udp |= rhs.any_udp;
        self.domain_keyword.extend(rhs.domain_keyword.into_iter());
        self
    }

    pub fn build(self) -> RuleSet {
        RuleSet {
            name: self.name,
            domain: self.domain.build(),
            ip: self.ip_cidr,
            tcp_port: self.tcp_port,
            udp_port: self.udp_port,
            any_tcp: self.any_tcp,
            any_udp: self.any_udp,
            domain_keyword: AhoCorasick::new_auto_configured(self.domain_keyword.as_slice()),
            process_name: self.process_name,
            process_keyword: AhoCorasick::new_auto_configured(self.process_keyword.as_slice()),
            procpath_keyword: AhoCorasick::new_auto_configured(self.procpath_keyword.as_slice()),
        }
    }

    pub fn from_ipaddrs(name: &str, list: Vec<IpAddr>) -> Self {
        let mut table = IpNetworkTable::new();
        list.iter().for_each(|ip| {
            table.insert(*ip, ());
        });
        Self {
            name: name.to_string(),
            domain: HostMatcherBuilder::new(),
            domain_keyword: vec![],
            ip_cidr: table,
            process_name: HashSet::new(),
            process_keyword: vec![],
            procpath_keyword: vec![],
            tcp_port: HashSet::new(),
            udp_port: HashSet::new(),
            any_tcp: false,
            any_udp: false,
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
    let builder = RuleSetBuilder::new("Test", deserialized);
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
