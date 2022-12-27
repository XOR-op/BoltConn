use crate::dispatch::ruleset::{RuleSet, RuleSetBuilder};
use crate::dispatch::{ConnInfo, GeneralProxy, Proxy, ProxyGroup};
use crate::proxy::NetworkAddr;
use anyhow::anyhow;
use ipnet::IpNet;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug)]
pub enum RuleImpl {
    ProcessName(String),
    ProcessKeyword(String),
    ProcPathKeyword(String),
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr(IpNet),
    Port(u16),
    RuleSet(RuleSet),
}

pub(crate) struct RuleBuilder<'a> {
    proxies: &'a HashMap<String, Arc<Proxy>>,
    groups: &'a HashMap<String, Arc<ProxyGroup>>,
    rulesets: HashMap<String, RuleSetBuilder>,
    buffer: Vec<(String, String, GeneralProxy)>,
}

impl RuleBuilder<'_> {
    pub fn new<'a>(
        proxies: &'a HashMap<String, Arc<Proxy>>,
        groups: &'a HashMap<String, Arc<ProxyGroup>>,
        rulesets: HashMap<String, RuleSetBuilder>,
    ) -> RuleBuilder<'a> {
        RuleBuilder {
            proxies,
            groups,
            rulesets,
            buffer: vec![],
        }
    }

    pub fn append_literal(&mut self, s: &str) -> anyhow::Result<()> {
        let processed_str: String = s.chars().filter(|c| *c != ' ').collect();
        let list: Vec<&str> = processed_str.split(',').collect();
        // ignore IP-CIDR,#ip#,#out#,no-resolve
        if list.len() != 3
            && !(list.len() == 4
                && (*list.get(0).unwrap() == "IP-CIDR" || *list.get(0).unwrap() == "IP-CIDR6")
                && *list.get(3).unwrap() == "no-resolve")
        {
            return Err(anyhow!("Invalid length"));
        }
        let general = {
            if let Some(p) = self.proxies.get(*list.get(2).unwrap()) {
                GeneralProxy::Single(p.clone())
            } else if let Some(p) = self.groups.get(*list.get(2).unwrap()) {
                GeneralProxy::Group(p.clone())
            } else {
                return Err(anyhow!("Group not found"));
            }
        };
        let (prefix, content) = (
            String::from(*list.get(0).unwrap()),
            String::from(*list.get(1).unwrap()),
        );

        self.buffer.push((prefix, content, general));
        Ok(())
    }

    pub fn parse_ruleset(s: &str, general: GeneralProxy) -> Option<Rule> {
        let processed_str: String = s.chars().filter(|c| *c != ' ').collect();
        let list: Vec<&str> = processed_str.split(',').collect();
        // ignore no-resolve
        // if list.len() != 2
        //     && !(list.len() == 3
        //     && (*list.get(0).unwrap() == "IP-CIDR"
        //     || *list.get(0).unwrap() == "IP-CIDR6")
        //     && *list.get(2).unwrap() == "no-resolve")
        // {
        //     return None;
        // }
        // For compatibility with Clash, we cannot have strict syntax constraint on ruleset rules.
        if list.len() < 2 {
            return None;
        }
        let (prefix, content) = (
            String::from(*list.get(0).unwrap()),
            String::from(*list.get(1).unwrap()),
        );
        Self::parse(prefix, content, general)
    }

    fn parse(prefix: String, content: String, general: GeneralProxy) -> Option<Rule> {
        match prefix.as_str() {
            "DOMAIN-SUFFIX" => Some(Rule {
                rule: RuleImpl::DomainSuffix(content),
                policy: general,
            }),
            "DOMAIN-KEYWORD" => Some(Rule {
                rule: RuleImpl::DomainKeyword(content),
                policy: general,
            }),
            "DOMAIN" => Some(Rule {
                rule: RuleImpl::Domain(content),
                policy: general,
            }),
            "PROCESS-NAME" => Some(Rule {
                rule: RuleImpl::ProcessName(content),
                policy: general,
            }),
            "PROCESS-KEYWORD" => Some(Rule {
                rule: RuleImpl::ProcessKeyword(content),
                policy: general,
            }),
            "PROCPATH-KEYWORD" => Some(Rule {
                rule: RuleImpl::ProcPathKeyword(content),
                policy: general,
            }),
            "IP-CIDR" | "IP-CIDR6" => {
                if let Ok(cidr) = IpNet::from_str(content.as_str()) {
                    Some(Rule {
                        rule: RuleImpl::IpCidr(cidr),
                        policy: general,
                    })
                } else {
                    None
                }
            }
            "DST-PORT" => {
                if let Ok(port) = content.parse::<u16>() {
                    Some(Rule {
                        rule: RuleImpl::Port(port),
                        policy: general,
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn build(mut self) -> Option<Vec<Rule>> {
        let mut ret = Vec::new();
        // compress adjacent ruleset
        let mut compressed: Option<(RuleSetBuilder, GeneralProxy)> = None;
        for (prefix, content, target) in self.buffer {
            if prefix == "RULE-SET" {
                let Some(ruleset) = self.rulesets.remove(&content) else {
                    return None;
                };
                // determine if we can compress them
                compressed = match compressed {
                    None => Some((ruleset, target)),
                    Some((prev_ruleset, prev_target)) => {
                        if prev_target == target {
                            Some((prev_ruleset.merge(ruleset), prev_target))
                        } else {
                            // push old, leave new
                            ret.push(Rule {
                                rule: RuleImpl::RuleSet(prev_ruleset.build()),
                                policy: prev_target,
                            });
                            Some((ruleset, target))
                        }
                    }
                };
            } else {
                // not able to merge next, push
                if let Some((builder, dest)) = compressed.take() {
                    ret.push(Rule {
                        rule: RuleImpl::RuleSet(builder.build()),
                        policy: dest,
                    });
                }
                match Self::parse(prefix, content, target) {
                    None => return None,
                    Some(r) => ret.push(r),
                }
            }
        }
        // push remaining
        if let Some((builder, dest)) = compressed.take() {
            ret.push(Rule {
                rule: RuleImpl::RuleSet(builder.build()),
                policy: dest,
            });
        }
        Some(ret)
    }
}

pub struct Rule {
    rule: RuleImpl,
    policy: GeneralProxy,
}

impl Rule {
    pub fn matches(&self, info: &ConnInfo) -> Option<GeneralProxy> {
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
            RuleImpl::DomainKeyword(kw) => {
                if let NetworkAddr::DomainName { domain_name, .. } = &info.dst {
                    if domain_name.contains(kw) {
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
            RuleImpl::ProcessKeyword(proc) => {
                if let Some(proc_info) = &info.process_info {
                    if proc_info.name.contains(proc) {
                        return Some(self.policy.clone());
                    }
                }
            }
            RuleImpl::ProcPathKeyword(proc) => {
                if let Some(proc_info) = &info.process_info {
                    if proc_info.path.contains(proc) {
                        return Some(self.policy.clone());
                    }
                }
            }
            RuleImpl::RuleSet(rs) => {
                if rs.matches(info) {
                    return Some(self.policy.clone());
                }
            }
        }
        None
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
