use crate::config::{ConfigError, ProxyError, RuleError};
use crate::dispatch::action::{Action, LocalResolve};
use crate::dispatch::ruleset::RuleSet;
use crate::dispatch::{ConnInfo, GeneralProxy, InboundInfo, Proxy, ProxyGroup};
use crate::external::MmdbReader;
use crate::network::dns::Dns;
use crate::platform::process::NetworkType;
use crate::proxy::NetworkAddr;
use ipnet::IpNet;
use regex::Regex;
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::mem;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum PortRule {
    Tcp(u16),
    Udp(u16),
    All(u16),
    AnyTcp,
    AnyUdp,
}

impl FromStr for PortRule {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Self::AnyTcp),
            "udp" => Ok(Self::AnyUdp),
            s => {
                if s.ends_with("/tcp") {
                    s.split_once("/tcp")
                        .and_then(|(p, _)| p.parse::<u16>().ok())
                        .map(Self::Tcp)
                        .ok_or(())
                } else if s.ends_with("/udp") {
                    s.split_once("/udp")
                        .and_then(|(p, _)| p.parse::<u16>().ok())
                        .map(Self::Udp)
                        .ok_or(())
                } else {
                    s.parse::<u16>().map(Self::All).map_err(|_| ())
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum RuleImpl {
    Inbound(InboundInfo),
    ProcessName(String),
    ProcessKeyword(String),
    ProcPathKeyword(String),
    ProcCmdRegex(Regex),
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    LocalIpCidr(IpNet),
    SrcIpCidr(IpNet),
    IpCidr(IpNet),
    SrcPort(PortRule),
    DstPort(PortRule),
    RuleSet(Arc<RuleSet>),
    GeoIP(Arc<MmdbReader>, String),
    Asn(Arc<MmdbReader>, u32),
    And(Vec<RuleImpl>),
    Or(Vec<RuleImpl>),
    Not(Box<RuleImpl>),
    Always,
    Never,
}

impl RuleImpl {
    pub fn matches(&self, info: &ConnInfo) -> bool {
        match &self {
            RuleImpl::Domain(d) => {
                if let NetworkAddr::DomainName { domain_name, .. } = &info.dst {
                    d == domain_name
                } else {
                    false
                }
            }
            RuleImpl::DomainSuffix(d) => {
                if let NetworkAddr::DomainName { domain_name, .. } = &info.dst {
                    if domain_name.len() == d.len() {
                        domain_name == d
                    } else {
                        domain_name.len() > d.len()
                            && domain_name.ends_with(d)
                            && domain_name.chars().rev().nth(d.len()) == Some('.')
                    }
                } else {
                    false
                }
            }
            RuleImpl::DomainKeyword(kw) => {
                if let NetworkAddr::DomainName { domain_name, .. } = &info.dst {
                    domain_name.contains(kw)
                } else {
                    false
                }
            }
            RuleImpl::LocalIpCidr(net) => info.local_ip.as_ref().map_or(false, |s| net.contains(s)),
            RuleImpl::SrcIpCidr(net) => net.contains(&info.src.ip()),
            RuleImpl::IpCidr(net) => info.dst_addr().is_some_and(|s| net.contains(&s.ip())),
            RuleImpl::GeoIP(mmdb, country) => info
                .dst_addr()
                .is_some_and(|s| mmdb.search_country(s.ip()).is_some_and(|c| c == country)),
            RuleImpl::Asn(mmdb, asn) => info
                .dst_addr()
                .is_some_and(|s| mmdb.search_asn(s.ip()).is_some_and(|a| a == *asn)),
            RuleImpl::SrcPort(port) => match port {
                PortRule::Tcp(p) => {
                    info.connection_type == NetworkType::Tcp && info.src.port() == *p
                }
                PortRule::Udp(p) => {
                    info.connection_type == NetworkType::Udp && info.src.port() == *p
                }
                PortRule::All(p) => info.src.port() == *p,
                PortRule::AnyTcp => info.connection_type == NetworkType::Tcp,
                PortRule::AnyUdp => info.connection_type == NetworkType::Udp,
            },
            RuleImpl::DstPort(port) => match port {
                PortRule::Tcp(p) => {
                    info.connection_type == NetworkType::Tcp && info.dst.port() == *p
                }
                PortRule::Udp(p) => {
                    info.connection_type == NetworkType::Udp && info.dst.port() == *p
                }
                PortRule::All(p) => info.dst.port() == *p,
                PortRule::AnyTcp => info.connection_type == NetworkType::Tcp,
                PortRule::AnyUdp => info.connection_type == NetworkType::Udp,
            },
            RuleImpl::Inbound(inbound) => inbound.contains(&info.inbound),
            RuleImpl::ProcessName(proc) => info
                .process_info
                .as_ref()
                .map_or_else(|| false, |proc_info| proc_info.name == *proc),
            RuleImpl::ProcessKeyword(proc) => info
                .process_info
                .as_ref()
                .map_or_else(|| false, |proc_info| proc_info.name.contains(proc)),
            RuleImpl::ProcPathKeyword(proc) => info
                .process_info
                .as_ref()
                .map_or_else(|| false, |proc_info| proc_info.path.contains(proc)),
            RuleImpl::ProcCmdRegex(regex) => info
                .process_info
                .as_ref()
                .map_or_else(|| false, |proc_info| regex.is_match(&proc_info.cmdline)),
            RuleImpl::RuleSet(rs) => rs.matches(info),
            RuleImpl::And(subs) => (|| {
                for i in subs {
                    if !i.matches(info) {
                        return false;
                    }
                }
                true
            })(),
            RuleImpl::Or(subs) => (|| {
                for i in subs {
                    if i.matches(info) {
                        return true;
                    }
                }
                false
            })(),
            RuleImpl::Not(r) => !r.matches(info),
            RuleImpl::Always => true,
            RuleImpl::Never => false,
        }
    }
}

pub(crate) struct RuleBuilder<'a> {
    proxies: &'a HashMap<String, Arc<Proxy>>,
    groups: &'a HashMap<String, Arc<ProxyGroup>>,
    rulesets: &'a HashMap<String, Arc<RuleSet>>,
    buffer: Vec<RuleOrAction>,
    dns: Arc<Dns>,
    mmdb: Option<Arc<MmdbReader>>,
}

impl RuleBuilder<'_> {
    pub fn new<'a>(
        dns: Arc<Dns>,
        mmdb: Option<Arc<MmdbReader>>,
        proxies: &'a HashMap<String, Arc<Proxy>>,
        groups: &'a HashMap<String, Arc<ProxyGroup>>,
        rulesets: &'a HashMap<String, Arc<RuleSet>>,
    ) -> RuleBuilder<'a> {
        RuleBuilder {
            proxies,
            groups,
            rulesets,
            buffer: vec![],
            dns,
            mmdb,
        }
    }

    pub fn append_local_resolve(&mut self) {
        self.buffer.push(RuleOrAction::Action(Action::LocalResolve(
            LocalResolve::new(self.dns.clone()),
        )));
    }

    pub fn append(&mut self, rule_or_action: RuleOrAction) {
        self.buffer.push(rule_or_action)
    }

    pub fn append_literal(&mut self, s: &str) -> Result<(), ConfigError> {
        let r = self.parse_literal(s)?;
        self.buffer.push(RuleOrAction::Rule(r));
        Ok(())
    }

    #[allow(clippy::get_first)]
    pub fn parse_literal(&mut self, s: &str) -> Result<Rule<GeneralProxy>, ConfigError> {
        let invalid_err = || RuleError::Invalid(s.to_string());
        let processed_str = "[".to_string() + s + "]";
        let list: serde_yaml::Sequence = serde_yaml::from_str(processed_str.as_str())
            .map_err(|_| RuleError::Invalid(s.to_string()))?;

        // Normal rules
        if list.len() < 3 {
            return Err(ConfigError::Rule(invalid_err()));
        }
        let (mut first, mut may_proxy) = list.split_at(list.len() - 1);
        let mut may_proxy_str =
            retrive_string(may_proxy.get(0).unwrap()).ok_or_else(invalid_err)?;
        // e.g. IP-CIDR, #ip#, #proxy#, no-resolve
        if may_proxy_str.as_str() == "no-resolve" {
            (first, may_proxy) = first.split_at(first.len() - 1);
            may_proxy_str = retrive_string(may_proxy.get(0).unwrap()).ok_or_else(invalid_err)?;
        }

        let general = {
            if let Some(p) = self.proxies.get(&may_proxy_str) {
                GeneralProxy::Single(p.clone())
            } else if let Some(p) = self.groups.get(&may_proxy_str) {
                GeneralProxy::Group(p.clone())
            } else {
                return Err(ProxyError::MissingProxy(may_proxy_str).into());
            }
        };

        let rule = self.parse_sub_rule(first, s)?;
        Ok(Rule::new(rule, general))
    }

    pub fn parse_incomplete(&mut self, s: &str) -> Result<RuleImpl, RuleError> {
        let processed_str = "[".to_string() + s + "]";
        let list: serde_yaml::Sequence = serde_yaml::from_str(processed_str.as_str())
            .map_err(|_| RuleError::Invalid(s.to_string()))?;
        if list.len() < 2 {
            return Err(RuleError::Invalid(s.to_string()));
        }
        self.parse_sub_rule(list.as_slice(), s)
    }

    fn parse_sub_rule(
        &self,
        list: &[serde_yaml::Value],
        original_text: &str,
    ) -> Result<RuleImpl, RuleError> {
        let invalid_err = || RuleError::Invalid(original_text.to_string());
        let prefix = retrive_string(list.first().unwrap()).ok_or_else(invalid_err)?;
        match prefix.as_str() {
            "AND" | "OR" => {
                if list.len() <= 2 {
                    return Err(invalid_err());
                }
                let mut subs = vec![];
                for val in list[1..].iter() {
                    let serde_yaml::Value::Sequence(seq) = val else {
                        return Err(invalid_err());
                    };
                    subs.push(self.parse_sub_rule(seq, original_text)?);
                }

                match prefix.as_str() {
                    "AND" => Ok(RuleImpl::And(subs)),
                    "OR" => Ok(RuleImpl::Or(subs)),
                    _ => unreachable!(),
                }
            }
            _ => {
                match list.len() {
                    2 => match prefix.as_str() {
                        "NOT" => {
                            let serde_yaml::Value::Sequence(seq) = list.get(1).unwrap() else {
                                return Err(RuleError::Invalid(original_text.to_string()));
                            };
                            Ok(RuleImpl::Not(Box::new(
                                self.parse_sub_rule(seq, original_text)?,
                            )))
                        }
                        _ => {
                            // all other rules
                            let content =
                                retrive_string(list.get(1).unwrap()).ok_or_else(invalid_err)?;
                            Self::parse(prefix, content, Some(self.rulesets), self.mmdb.as_ref())
                                .ok_or_else(invalid_err)
                        }
                    },
                    3 => {
                        match prefix.as_str() {
                            "IP-CIDR" | "IP-CIDR6" | "LOCAL-IP-CIDR" => {
                                // ignore IP-CIDR,#ip#,no-resolve
                                if *list.get(2).unwrap()
                                    != serde_yaml::Value::String("no-resolve".to_string())
                                {
                                    return Err(invalid_err());
                                }
                                let content =
                                    retrive_string(list.get(1).unwrap()).ok_or_else(invalid_err)?;
                                Self::parse(
                                    prefix,
                                    content,
                                    Some(self.rulesets),
                                    self.mmdb.as_ref(),
                                )
                                .ok_or_else(invalid_err)
                            }
                            _ => Err(invalid_err()),
                        }
                    }
                    _ => Err(invalid_err()),
                }
            }
        }
    }

    pub fn parse_fallback(&mut self, s: &str) -> Result<GeneralProxy, ConfigError> {
        let processed_str: String = s.chars().filter(|c| *c != ' ').collect();
        let list: Vec<&str> = processed_str.split(',').collect();
        if list.len() != 2 || *list.first().unwrap() != "FALLBACK" {
            return Err(RuleError::Invalid(s.to_string()).into());
        }
        let general = {
            if let Some(p) = self.proxies.get(*list.get(1).unwrap()) {
                GeneralProxy::Single(p.clone())
            } else if let Some(p) = self.groups.get(*list.get(1).unwrap()) {
                GeneralProxy::Group(p.clone())
            } else {
                return Err(ProxyError::MissingGroup((*list.get(1).unwrap()).to_string()).into());
            }
        };
        Ok(general)
    }

    #[allow(clippy::get_first)]
    pub fn parse_rulesets(
        s: &str,
        mmdb: Option<&Arc<MmdbReader>>,
        rulesets: Option<&HashMap<String, Arc<RuleSet>>>,
    ) -> Option<RuleImpl> {
        let processed_str: String = s.chars().filter(|c| *c != ' ').collect();
        let list: Vec<&str> = processed_str.split(',').collect();
        // ignore no-resolve
        // For compatibility with Clash, we cannot have strict syntax constraint on ruleset rules.
        if list.len() < 2 {
            return None;
        }
        let (prefix, content) = (
            String::from(*list.get(0).unwrap()),
            String::from(*list.get(1).unwrap()),
        );
        Self::parse(prefix, content, rulesets, mmdb)
    }

    fn parse(
        prefix: String,
        content: String,
        rulesets: Option<&HashMap<String, Arc<RuleSet>>>,
        mmdb: Option<&Arc<MmdbReader>>,
    ) -> Option<RuleImpl> {
        match prefix.as_str() {
            "INBOUND" => Some(RuleImpl::Inbound(InboundInfo::from_str(&content).ok()?)),
            "DOMAIN-SUFFIX" => Some(RuleImpl::DomainSuffix(content)),
            "DOMAIN-KEYWORD" => Some(RuleImpl::DomainKeyword(content)),
            "DOMAIN" => Some(RuleImpl::Domain(content)),
            "PROCESS-NAME" => Some(RuleImpl::ProcessName(content)),
            "PROCESS-KEYWORD" => Some(RuleImpl::ProcessKeyword(content)),
            "PROC-PATH-KEYWORD" => Some(RuleImpl::ProcPathKeyword(content)),
            "PROC-CMD-REGEX" => Some(RuleImpl::ProcCmdRegex(Regex::new(&content).ok()?)),
            "LOCAL-IP-CIDR" => IpNet::from_str(content.as_str())
                .ok()
                .map(RuleImpl::LocalIpCidr),
            "SRC-IP-CIDR" => IpNet::from_str(content.as_str())
                .ok()
                .map(RuleImpl::SrcIpCidr),
            "IP-CIDR" | "IP-CIDR6" => IpNet::from_str(content.as_str()).ok().map(RuleImpl::IpCidr),
            "GEOIP" => mmdb.map(|x| RuleImpl::GeoIP(x.clone(), content)),
            "ASN" => {
                mmdb.and_then(|x| Some(RuleImpl::Asn(x.clone(), content.parse::<u32>().ok()?)))
            }
            "SRC-PORT" => content.parse::<PortRule>().ok().map(RuleImpl::SrcPort),
            "DST-PORT" => content.parse::<PortRule>().ok().map(RuleImpl::DstPort),
            "RULE-SET" => rulesets
                .and_then(|table| table.get(&content))
                .map(|rs| RuleImpl::RuleSet(rs.clone())),
            "ALWAYS" => Some(RuleImpl::Always),
            "NEVER" => Some(RuleImpl::Never),
            _ => None,
        }
    }

    pub fn emit_all(&mut self) -> Vec<RuleOrAction> {
        mem::take(&mut self.buffer)
    }
}

pub struct Rule<T: Clone> {
    rule: RuleImpl,
    result: T,
}

impl<T: Clone> Rule<T> {
    pub(crate) fn new(rule: RuleImpl, result: T) -> Self {
        Self { rule, result }
    }

    pub fn matches(&self, info: &ConnInfo) -> Option<T> {
        self.rule.matches(info).then(|| self.result.clone())
    }

    pub fn get_impl(&self) -> &RuleImpl {
        &self.rule
    }
}

impl<T: Clone> Debug for Rule<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.rule.fmt(f)
    }
}

impl<T: Clone> Display for Rule<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.rule.fmt(f)
    }
}

fn retrive_string(val: &serde_yaml::Value) -> Option<String> {
    match val {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub enum RuleOrAction {
    Rule(Rule<GeneralProxy>),
    Action(Action),
}
