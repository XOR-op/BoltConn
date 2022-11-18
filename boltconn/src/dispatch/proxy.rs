use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use crate::adapter::Socks5Config;

/// Single proxy configuation.
pub struct Proxy {
    name: String,
    detail: ProxyImpl,
}

impl Proxy {
    pub fn get_impl(&self)->ProxyImpl{
        self.detail.clone()
    }
}

#[derive(Debug, Clone)]
pub enum ProxyImpl {
    Direct,
    Socks5(Arc<Socks5Config>),
}

/// A group of proxies
pub struct ProxyGroup {
    name: String,
    proxies: Vec<Arc<GeneralProxy>>,
    selection: Arc<GeneralProxy>,
}

impl ProxyGroup {
    pub fn get_selection(&self) -> Arc<Proxy> {
        match &self.selection {
            GeneralProxy::Single(p) => p.clone(),
            GeneralProxy::Group(g) => g.get_selection()
        }
    }
}

pub enum GeneralProxy {
    Single(Arc<Proxy>),
    Group(Arc<ProxyGroup>),
}
