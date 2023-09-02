use crate::common::host_matcher::{HostMatcher, HostMatcherBuilder};
use crate::config::{ProviderBehavior, RuleSchema};
use crate::dispatch::rule::{PortRule, RuleBuilder, RuleImpl};
use crate::dispatch::{ConnInfo, InboundInfo};
use crate::external::MmdbReader;
use crate::platform::process::NetworkType;
use crate::proxy::NetworkAddr;
use aho_corasick::AhoCorasick;
use ip_network_table::IpNetworkTable;
use ipnet::IpNet;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

pub type RuleSetTable = HashMap<String, Arc<RuleSet>>;

/// Matcher for rules in the same group
pub struct RuleSet {
    name: String,
    domain: HostMatcher,
    ip: IpNetworkTable<()>,
    src_tcp_port: PortFilter,
    src_udp_port: PortFilter,
    dst_tcp_port: PortFilter,
    dst_udp_port: PortFilter,
    http_inbound: InboundFilter,
    socks5_inbound: InboundFilter,
    tun_inbound: bool,
    domain_keyword: AhoCorasick,
    process_name: HashSet<String>,
    mmdb: Option<(Arc<MmdbReader>, HashSet<u32>, HashSet<String>)>,
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
                    || info
                        .resolved_dst
                        .as_ref()
                        .is_some_and(|dst| self.ip.longest_match(dst.ip()).is_some())
                {
                    return true;
                }
                *port
            }
        };
        match info.connection_type {
            NetworkType::Tcp => {
                if self.dst_tcp_port.contains(port) || self.src_tcp_port.contains(info.src.port()) {
                    return true;
                }
            }
            NetworkType::Udp => {
                if self.dst_udp_port.contains(port) || self.src_udp_port.contains(info.src.port()) {
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
        if let Some((mmdb, asn, countries)) = &self.mmdb {
            if info.socketaddr().is_some_and(|s| {
                mmdb.search_asn(s.ip()).is_some_and(|a| asn.contains(&a))
                    || mmdb
                        .search_country(s.ip())
                        .is_some_and(|c| countries.contains(c))
            }) {
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
    src_tcp_port: PortFilter,
    src_udp_port: PortFilter,
    dst_tcp_port: PortFilter,
    dst_udp_port: PortFilter,
    http_inbound: InboundFilter,
    socks5_inbound: InboundFilter,
    tun_inbound: bool,
    asn: HashSet<u32>,
    geoip_country: HashSet<String>,
    mmdb: Option<Arc<MmdbReader>>,
}

impl RuleSetBuilder {
    pub fn new(name: &str, payload: &RuleSchema) -> Option<Self> {
        let mut retval = Self {
            name: name.to_string(),
            domain: HostMatcherBuilder::new(),
            domain_keyword: vec![],
            ip_cidr: Default::default(),
            process_name: Default::default(),
            process_keyword: vec![],
            procpath_keyword: vec![],
            src_tcp_port: Default::default(),
            src_udp_port: Default::default(),
            dst_tcp_port: Default::default(),
            dst_udp_port: Default::default(),
            http_inbound: Default::default(),
            socks5_inbound: Default::default(),
            tun_inbound: false,
            asn: Default::default(),
            geoip_country: Default::default(),
            mmdb: None,
        };
        match payload.behavior {
            ProviderBehavior::Domain => {
                let prefix_reg = Regex::new(r"[*+]\.").unwrap();
                for str in &payload.payload {
                    // here we treat all */+ as DomainSuffix
                    if prefix_reg.find(str).is_some() {
                        let r = prefix_reg.replace_all(str, "");
                        retval.domain.add_suffix(&r);
                    } else {
                        retval.domain.add_exact(str);
                    }
                }
                Some(retval)
            }
            ProviderBehavior::IpCidr => {
                for str in &payload.payload {
                    let ip = IpNet::from_str(str).ok()?;
                    let ip =
                        ip_network::IpNetwork::new_truncate(ip.addr(), ip.prefix_len()).unwrap();
                    retval.ip_cidr.insert(ip, ());
                }
                Some(retval)
            }
            ProviderBehavior::Classical => {
                for str in &payload.payload {
                    let rule = RuleBuilder::parse_rulesets(str, retval.mmdb.as_ref(), None)?;
                    match rule {
                        RuleImpl::Inbound(inbound) => match inbound {
                            InboundInfo::Tun => retval.tun_inbound = true,
                            InboundInfo::HttpAny => retval.http_inbound.set_any(),
                            InboundInfo::Socks5Any => retval.socks5_inbound.set_any(),
                            InboundInfo::Http(user) => {
                                if let Some(s) = user {
                                    retval.http_inbound.insert(s)
                                }
                            }
                            InboundInfo::Socks5(user) => {
                                if let Some(s) = user {
                                    retval.socks5_inbound.insert(s)
                                }
                            }
                        },
                        RuleImpl::ProcessName(pn) => {
                            retval.process_name.insert(pn.clone());
                        }
                        RuleImpl::ProcessKeyword(kw) => retval.process_keyword.push(kw.clone()),
                        RuleImpl::ProcPathKeyword(kw) => retval.procpath_keyword.push(kw.clone()),
                        RuleImpl::Domain(dn) => retval.domain.add_exact(dn.as_str()),
                        RuleImpl::DomainSuffix(sfx) => retval.domain.add_suffix(sfx.as_str()),
                        RuleImpl::DomainKeyword(kw) => retval.domain_keyword.push(kw.clone()),
                        RuleImpl::IpCidr(ip) => {
                            let ip =
                                ip_network::IpNetwork::new_truncate(ip.addr(), ip.prefix_len())
                                    .unwrap();
                            retval.ip_cidr.insert(ip, ());
                        }
                        RuleImpl::Asn(mmdb, asn) => {
                            retval.asn.insert(asn);
                            retval.mmdb = Some(mmdb)
                        }
                        RuleImpl::GeoIP(mmdb, country) => {
                            retval.geoip_country.insert(country);
                            retval.mmdb = Some(mmdb)
                        }
                        RuleImpl::SrcPort(p) => match p {
                            PortRule::Tcp(p) => {
                                retval.src_tcp_port.insert(p);
                            }
                            PortRule::Udp(p) => {
                                retval.src_udp_port.insert(p);
                            }
                            PortRule::All(p) => {
                                retval.src_tcp_port.insert(p);
                                retval.src_udp_port.insert(p);
                            }
                            PortRule::AnyTcp => retval.src_tcp_port.set_any(),
                            PortRule::AnyUdp => retval.src_udp_port.set_any(),
                        },
                        RuleImpl::DstPort(p) => match p {
                            PortRule::Tcp(p) => {
                                retval.dst_tcp_port.insert(p);
                            }
                            PortRule::Udp(p) => {
                                retval.dst_udp_port.insert(p);
                            }
                            PortRule::All(p) => {
                                retval.dst_tcp_port.insert(p);
                                retval.dst_udp_port.insert(p);
                            }
                            PortRule::AnyTcp => retval.dst_tcp_port.set_any(),
                            PortRule::AnyUdp => retval.dst_udp_port.set_any(),
                        },
                        // Slow for ruleset; better to write as a standalone rule
                        RuleImpl::RuleSet(_)
                        | RuleImpl::And(..)
                        | RuleImpl::Or(..)
                        | RuleImpl::Not(_)
                        | RuleImpl::ProcCmdRegex(_) => return None,
                    }
                }
                Some(retval)
            }
        }
    }

    pub fn merge(mut self, rhs: Self) -> Self {
        self.domain.merge(rhs.domain);
        rhs.ip_cidr.iter().for_each(|(ip, _)| {
            let _ = self.ip_cidr.insert(ip, ());
        });
        self.process_name.extend(rhs.process_name);
        self.process_keyword.extend(rhs.process_keyword);
        self.procpath_keyword.extend(rhs.procpath_keyword);
        self.src_tcp_port.extend(rhs.src_tcp_port);
        self.src_udp_port.extend(rhs.src_udp_port);
        self.dst_tcp_port.extend(rhs.dst_tcp_port);
        self.dst_udp_port.extend(rhs.dst_udp_port);
        self.domain_keyword.extend(rhs.domain_keyword);
        self
    }

    pub fn build(self) -> anyhow::Result<RuleSet> {
        Ok(RuleSet {
            name: self.name,
            domain: self.domain.build(),
            ip: self.ip_cidr,
            src_tcp_port: self.src_tcp_port,
            src_udp_port: self.src_udp_port,
            dst_tcp_port: self.dst_tcp_port,
            dst_udp_port: self.dst_udp_port,
            http_inbound: self.http_inbound,
            socks5_inbound: self.socks5_inbound,
            tun_inbound: self.tun_inbound,
            domain_keyword: AhoCorasick::new(self.domain_keyword.into_iter())?,
            process_name: self.process_name,
            mmdb: self.mmdb.map(|m| (m, self.asn, self.geoip_country)),
            process_keyword: AhoCorasick::new(self.process_keyword.into_iter())?,
            procpath_keyword: AhoCorasick::new(self.procpath_keyword.into_iter())?,
        })
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
            process_name: Default::default(),
            process_keyword: vec![],
            procpath_keyword: vec![],
            src_tcp_port: Default::default(),
            src_udp_port: Default::default(),
            dst_tcp_port: Default::default(),
            dst_udp_port: Default::default(),
            http_inbound: Default::default(),
            socks5_inbound: Default::default(),
            tun_inbound: false,
            asn: Default::default(),
            geoip_country: Default::default(),
            mmdb: None,
        }
    }
}

enum PortFilter {
    Any,
    Some(HashSet<u16>),
}

impl PortFilter {
    pub fn insert(&mut self, port: u16) {
        match self {
            PortFilter::Any => {}
            PortFilter::Some(s) => {
                s.insert(port);
            }
        }
    }

    pub fn set_any(&mut self) {
        *self = PortFilter::Any
    }

    pub fn contains(&self, port: u16) -> bool {
        match self {
            PortFilter::Any => true,
            PortFilter::Some(s) => s.contains(&port),
        }
    }

    pub fn extend(&mut self, rhs: Self) {
        match rhs {
            PortFilter::Any => self.set_any(),
            PortFilter::Some(rs) => match self {
                PortFilter::Any => {}
                PortFilter::Some(ls) => ls.extend(rs),
            },
        }
    }
}

impl Default for PortFilter {
    fn default() -> Self {
        PortFilter::Some(Default::default())
    }
}

enum InboundFilter {
    Any,
    Some(HashSet<String>),
}

impl InboundFilter {
    pub fn insert(&mut self, user: String) {
        match self {
            InboundFilter::Any => {}
            InboundFilter::Some(s) => {
                s.insert(user);
            }
        }
    }

    pub fn set_any(&mut self) {
        *self = InboundFilter::Any
    }

    pub fn contains(&self, user: &str) -> bool {
        match self {
            InboundFilter::Any => true,
            InboundFilter::Some(s) => s.contains(user),
        }
    }

    pub fn extend(&mut self, rhs: Self) {
        match rhs {
            InboundFilter::Any => self.set_any(),
            InboundFilter::Some(rs) => match self {
                InboundFilter::Any => {}
                InboundFilter::Some(ls) => ls.extend(rs),
            },
        }
    }
}

impl Default for InboundFilter {
    fn default() -> Self {
        InboundFilter::Some(Default::default())
    }
}

#[ignore]
#[test]
fn test_rule_provider() {
    use crate::config::RawRuleSchema;
    use crate::dispatch::InboundInfo;
    use crate::platform::process::NetworkType;
    let config_text = std::fs::read_to_string("../examples/Rules/Apple").unwrap();
    let deserialized: RawRuleSchema = serde_yaml::from_str(&config_text).unwrap();
    println!("{:?}", deserialized);
    let builder = RuleSetBuilder::new(
        "Test",
        &RuleSchema {
            behavior: ProviderBehavior::Classical,
            payload: deserialized.payload,
        },
    );
    assert!(builder.is_some());
    let ruleset = builder.unwrap().build().unwrap();
    // println!("kw:{}, domain:{}", ruleset.domain_keyword.pattern_count(), ruleset.domain.len());
    let info1 = ConnInfo {
        src: "127.0.0.1:12345".parse().unwrap(),
        dst: NetworkAddr::DomainName {
            domain_name: "kb.apple.com".to_string(),
            port: 1234,
        },
        inbound: InboundInfo::Tun,
        resolved_dst: None,
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
        inbound: InboundInfo::Tun,
        resolved_dst: None,
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
        inbound: InboundInfo::Tun,
        resolved_dst: None,
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
        inbound: InboundInfo::Tun,
        resolved_dst: None,
        connection_type: NetworkType::Tcp,
        process_info: None,
    };
    assert!(!ruleset.matches(&info4));
}
