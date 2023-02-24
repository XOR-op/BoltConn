use crate::dispatch::ruleset::RuleSet;
use crate::dispatch::{ConnInfo, GeneralProxy, Proxy, ProxyGroup};
use crate::platform::process::NetworkType;
use crate::proxy::NetworkAddr;
use anyhow::anyhow;
use ipnet::IpNet;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
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
    ProcessName(String),
    ProcessKeyword(String),
    ProcPathKeyword(String),
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr(IpNet),
    Port(PortRule),
    RuleSet(Arc<RuleSet>),
    And(Vec<RuleImpl>),
    Or(Vec<RuleImpl>),
    Not(Box<RuleImpl>),
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
                    domain_name.ends_with(d)
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
            RuleImpl::IpCidr(net) => {
                if let NetworkAddr::Raw(addr) = &info.dst {
                    net.contains(&addr.ip())
                } else {
                    false
                }
            }
            RuleImpl::Port(port) => match port {
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
        }
    }
}

pub(crate) struct RuleBuilder<'a> {
    proxies: &'a HashMap<String, Arc<Proxy>>,
    groups: &'a HashMap<String, Arc<ProxyGroup>>,
    rulesets: HashMap<String, Arc<RuleSet>>,
    buffer: Vec<(RuleImpl, GeneralProxy)>,
}

impl RuleBuilder<'_> {
    pub fn new<'a>(
        proxies: &'a HashMap<String, Arc<Proxy>>,
        groups: &'a HashMap<String, Arc<ProxyGroup>>,
        rulesets: HashMap<String, Arc<RuleSet>>,
    ) -> RuleBuilder<'a> {
        RuleBuilder {
            proxies,
            groups,
            rulesets,
            buffer: vec![],
        }
    }

    #[allow(clippy::get_first)]
    pub fn append_literal(&mut self, s: &str) -> anyhow::Result<()> {
        let processed_str = "[".to_string() + s + "]";
        let list: serde_yaml::Sequence = serde_yaml::from_str(processed_str.as_str())?;
        if list.len() < 3 {
            return Err(anyhow!("Invalid length"));
        }
        let (mut first, mut may_proxy) = list.split_at(list.len() - 1);
        let mut may_proxy_str = retrive_string(may_proxy.get(0).unwrap())?;
        // e.g. IP-CIDR, #ip#, #proxy#, no-resolve
        if may_proxy_str.as_str() == "no-resolve" {
            (first, may_proxy) = first.split_at(first.len() - 1);
            may_proxy_str = retrive_string(may_proxy.get(0).unwrap())?;
        }

        let general = {
            if let Some(p) = self.proxies.get(&may_proxy_str) {
                GeneralProxy::Single(p.clone())
            } else if let Some(p) = self.groups.get(&may_proxy_str) {
                GeneralProxy::Group(p.clone())
            } else {
                return Err(anyhow!("Group not found"));
            }
        };

        let rule = self.parse_sub_rule(first)?;

        self.buffer.push((rule, general));
        Ok(())
    }

    fn parse_sub_rule(&self, list: &[serde_yaml::Value]) -> anyhow::Result<RuleImpl> {
        let prefix = retrive_string(list.get(0).unwrap())?;
        match prefix.as_str() {
            "AND" | "OR" => {
                if list.len() <= 2 {
                    return Err(anyhow!("Invalid length"));
                }
                let mut subs = vec![];
                for val in list[1..].iter() {
                    let serde_yaml::Value::Sequence(seq) = val else {
                        return Err(anyhow!("Invalid NOT rule"));
                    };
                    subs.push(self.parse_sub_rule(seq)?);
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
                                return Err(anyhow!("Invalid NOT rule"));
                            };
                            Ok(RuleImpl::Not(Box::new(self.parse_sub_rule(seq)?)))
                        }
                        _ => {
                            // all other rules
                            let content = retrive_string(list.get(1).unwrap())?;
                            Self::parse(prefix, content, Some(&self.rulesets))
                                .ok_or_else(|| anyhow!("Failed to parse"))
                        }
                    },
                    3 => {
                        match prefix.as_str() {
                            "IP-CIDR" | "IP-CIDR6" => {
                                // ignore IP-CIDR,#ip#,no-resolve
                                if *list.get(2).unwrap()
                                    != serde_yaml::Value::String("no-resolve".to_string())
                                {
                                    return Err(anyhow!("Invalid length"));
                                }
                                let content = retrive_string(list.get(1).unwrap())?;
                                Self::parse(prefix, content, Some(&self.rulesets))
                                    .ok_or_else(|| anyhow!("Failed to parse"))
                            }
                            _ => Err(anyhow!("Invalid length")),
                        }
                    }
                    _ => Err(anyhow!("Invalid length")),
                }
            }
        }
    }

    pub fn parse_fallback(&mut self, s: &str) -> anyhow::Result<GeneralProxy> {
        let processed_str: String = s.chars().filter(|c| *c != ' ').collect();
        let list: Vec<&str> = processed_str.split(',').collect();
        if list.len() != 2 || *list.first().unwrap() != "FALLBACK" {
            return Err(anyhow!("Invalid FALLBACK rule"));
        }
        let general = {
            if let Some(p) = self.proxies.get(*list.get(1).unwrap()) {
                GeneralProxy::Single(p.clone())
            } else if let Some(p) = self.groups.get(*list.get(1).unwrap()) {
                GeneralProxy::Group(p.clone())
            } else {
                return Err(anyhow!("Group not found"));
            }
        };
        Ok(general)
    }

    #[allow(clippy::get_first)]
    pub fn parse_ruleset(s: &str) -> Option<RuleImpl> {
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
        Self::parse(prefix, content, None)
    }

    fn parse(
        prefix: String,
        content: String,
        rulesets: Option<&HashMap<String, Arc<RuleSet>>>,
    ) -> Option<RuleImpl> {
        match prefix.as_str() {
            "DOMAIN-SUFFIX" => Some(RuleImpl::DomainSuffix(content)),
            "DOMAIN-KEYWORD" => Some(RuleImpl::DomainKeyword(content)),
            "DOMAIN" => Some(RuleImpl::Domain(content)),
            "PROCESS-NAME" => Some(RuleImpl::ProcessName(content)),
            "PROCESS-KEYWORD" => Some(RuleImpl::ProcessKeyword(content)),
            "PROCPATH-KEYWORD" => Some(RuleImpl::ProcPathKeyword(content)),
            "IP-CIDR" | "IP-CIDR6" => IpNet::from_str(content.as_str()).ok().map(RuleImpl::IpCidr),
            "DST-PORT" => content.parse::<PortRule>().ok().map(RuleImpl::Port),
            "RULE-SET" => rulesets
                .and_then(|table| table.get(&content))
                .map(|rs| RuleImpl::RuleSet(rs.clone())),
            _ => None,
        }
    }

    pub fn build(self) -> Vec<Rule> {
        self.buffer
            .into_iter()
            .map(|(r, e)| Rule::new(r, e))
            .collect()
    }
}

pub struct Rule {
    rule: RuleImpl,
    policy: GeneralProxy,
}

impl Rule {
    pub(crate) fn new(rule: RuleImpl, policy: GeneralProxy) -> Self {
        Self { rule, policy }
    }

    pub fn matches(&self, info: &ConnInfo) -> Option<GeneralProxy> {
        self.rule.matches(info).then(|| self.policy.clone())
    }

    pub fn get_impl(&self) -> &RuleImpl {
        &self.rule
    }
}

impl Debug for Rule {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.rule.fmt(f)
    }
}

fn retrive_string(val: &serde_yaml::Value) -> anyhow::Result<String> {
    match val {
        serde_yaml::Value::String(s) => Ok(s.clone()),
        serde_yaml::Value::Number(n) => Ok(n.to_string()),
        _ => Err(anyhow!("Not a valid string")),
    }
}
