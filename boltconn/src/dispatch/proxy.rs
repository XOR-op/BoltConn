use crate::adapter::Socks5Config;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Single proxy configuation.
pub struct Proxy {
    name: String,
    detail: ProxyImpl,
}

impl Proxy {
    pub fn new<S: Into<String>>(name: S, detail: ProxyImpl) -> Self {
        Self {
            name: name.into(),
            detail,
        }
    }

    pub fn get_impl(&self) -> ProxyImpl {
        self.detail.clone()
    }
}

#[derive(Debug)]
pub enum ProxyImpl {
    Direct,
    Drop,
    Socks5(Socks5Config),
}

/// A group of proxies
pub struct ProxyGroup {
    name: String,
    proxies: Vec<Arc<GeneralProxy>>,
    selection: Arc<GeneralProxy>,
}

impl ProxyGroup {
    pub fn new<S: Into<String>>(
        name: S,
        proxies: Vec<Arc<GeneralProxy>>,
        selection: Arc<GeneralProxy>,
    ) -> Self {
        Self {
            name: name.into(),
            proxies,
            selection,
        }
    }
    pub fn get_selection(&self) -> Arc<Proxy> {
        match self.selection.as_ref() {
            GeneralProxy::Single(p) => p.clone(),
            GeneralProxy::Group(g) => g.get_selection(),
        }
    }
}

pub enum GeneralProxy {
    Single(Arc<Proxy>),
    Group(Arc<ProxyGroup>),
}
