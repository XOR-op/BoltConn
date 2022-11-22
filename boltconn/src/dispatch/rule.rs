use crate::dispatch::{ConnInfo, GeneralProxy, Proxy, ProxyGroup};
use crate::session::NetworkAddr;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub enum RuleImpl {
    ProcessName(String),
    Domain(String),
    DomainSuffix(String),
    Ip(IpAddr),
    IpCidr(IpNet),
    Port(u16),
}

pub(crate) struct RuleBuilder<'a> {
    pub(crate) proxies: &'a HashMap<String, Arc<Proxy>>,
    pub(crate) groups: &'a HashMap<String, Arc<ProxyGroup>>,
}

impl RuleBuilder {
    pub fn parse_literal(&self, s: &str) -> Option<Rule> {
        let list: Vec<&str> = s.split(',').collect();
        if list.len() != 3 {
            return None;
        }
        let general = {
            if let Some(p) = self.proxies.get(*list.get(2).unwrap()) {
                Arc::new(GeneralProxy::Single(p.clone()))
            } else if let Some(p) = self.groups.get(*list.get(2).unwrap()) {
                Arc::new(GeneralProxy::Group(p.clone()))
            } else {
                return None;
            }
        };
        return match *list.get(0).unwrap() {
            "DOMAIN-SUFFIX" =>
                Some(Rule {
                    rule: RuleImpl::DomainSuffix(String::from(*list.get(1).unwrap())),
                    policy: general,
                }),
            "DOMAIN" => Some(Rule {
                rule: RuleImpl::Domain(String::from(*list.get(1).unwrap())),
                policy: general,
            }),
            "PROCESS-NAME" => Some(Rule {
                rule: RuleImpl::ProcessName(String::from(*list.get(1).unwrap())),
                policy: general,
            }),
            "IP-CIDR" => {
                if let Ok(cidr) = IpNet::try_from(*list.get(1).unwrap()) {
                    Some(Rule {
                        rule: RuleImpl::IpCidr(cidr),
                        policy: general,
                    })
                } else {
                    None
                }
            }
            "PORT" => {
                if let Ok(port) = (*list.get(1).unwrap()).parse::<u16>() {
                    Some(Rule {
                        rule: RuleImpl::Port(port),
                        policy: general,
                    })
                } else {
                    None
                }
            }
            _ => None,
        };
    }
}

pub struct Rule {
    rule: RuleImpl,
    policy: Arc<GeneralProxy>,
}

impl Rule {
    pub fn matches(&self, info: &ConnInfo) -> Option<Arc<GeneralProxy>> {
        match &self.rule {
            RuleImpl::Domain(d) => {
                if let NetworkAddr::DomainName { domain_name, .. } = &info.dst {
                    if d == domain_name {
                        return Some(self.policy.clone());
                    }
                }
            }
            RuleImpl::DomainSuffix(d) => {
                if let NetworkAddr::DomainName { domain_name, .. } = &info.dst {
                    if domain_name.ends_with(d) {
                        return Some(self.policy.clone());
                    }
                }
            }
            RuleImpl::Ip(ip) => {
                if let NetworkAddr::Raw(addr) = &info.dst {
                    if addr.ip() == *ip {
                        return Some(self.policy.clone());
                    }
                }
            }
            RuleImpl::IpCidr(net) => {
                if let NetworkAddr::Raw(addr) = &info.dst {
                    if net.contains(&addr.ip()) {
                        return Some(self.policy.clone());
                    }
                }
            }
            RuleImpl::Port(port) => {
                if *port == info.dst.port() {
                    return Some(self.policy.clone());
                }
            }
            RuleImpl::ProcessName(proc) => {
                if let Some(proc_info) = &info.process_info {
                    if proc_info.name == *proc {
                        return Some(self.policy.clone());
                    }
                }
            }
        }
        None
    }
}
