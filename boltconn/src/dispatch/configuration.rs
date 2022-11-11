use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use crate::adapter::Socks5Config;

/// Single proxy configuation.
pub struct Proxy {
    name: String,
    detail: ProxyImpl,
}

#[derive(Debug, Clone)]
pub enum ProxyImpl {
    Direct,
    Socks5(Arc<Socks5Config>),
}

/// A group of proxies
pub struct ProxyGroup {
    name: String,
    proxies: Vec<Arc<Proxy>>,
    selection: Arc<Proxy>,
}

pub enum GeneralProxy {
    Single(Arc<Proxy>),
    Group(Arc<ProxyGroup>),
}

pub enum RuleImpl {
    ProcessName(String),
    Domain(String),
    DomainSuffix(String),
    Ip(IpAddr),
    IpCidr(IpNet),
}

pub struct Rule {
    rule: RuleImpl,
    policy: Arc<Policy>,
}

pub struct Policy {
    name: String,
    option: GeneralProxy,
}
