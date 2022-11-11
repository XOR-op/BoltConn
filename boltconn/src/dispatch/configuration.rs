use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use ipnet::IpNet;

/// Single proxy configuation.
pub struct Proxy {
    name: String,
    detail: ProxyImpl,
}

pub(crate) enum ProxyImpl {
    Direct,
    Socks5 {
        server: SocketAddr,
        credential: fast_socks5::AuthenticationMethod,
    },
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