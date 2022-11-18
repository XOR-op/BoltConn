use std::net::IpAddr;
use ipnet::IpNet;
use std::sync::Arc;
use crate::dispatch::{ConnInfo, GeneralProxy};
use crate::session::NetworkAddr;

pub enum RuleImpl {
    ProcessName(String),
    Domain(String),
    DomainSuffix(String),
    Ip(IpAddr),
    IpCidr(IpNet),
    Port(u16),
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
                    if addr.ip() == ip {
                        return Some(self.policy.clone());
                    }
                }
            }
            RuleImpl::IpCidr(net) => {
                if let NetworkAddr::Raw(addr) = &info.dst {
                    if net.contains(addr.ip()) {
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
                    if proc_info.name == proc {
                        return Some(self.policy.clone());
                    }
                }
            }
        }
        None
    }
}

