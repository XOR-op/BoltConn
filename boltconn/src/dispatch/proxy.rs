use crate::adapter::{HttpConfig, ShadowSocksConfig, Socks5Config};
use crate::transport::trojan::TrojanConfig;
use crate::transport::wireguard::WireguardConfig;
use anyhow::anyhow;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};

/// Single proxy configuation.
#[derive(Debug)]
pub struct Proxy {
    name: String,
    detail: Arc<ProxyImpl>,
}

impl Proxy {
    pub fn new<S: Into<String>>(name: S, detail: ProxyImpl) -> Self {
        Self {
            name: name.into(),
            detail: Arc::new(detail),
        }
    }
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_impl(&self) -> Arc<ProxyImpl> {
        self.detail.clone()
    }
}

#[derive(Debug)]
pub enum ProxyImpl {
    Direct,
    Reject,
    Http(HttpConfig),
    Socks5(Socks5Config),
    Shadowsocks(ShadowSocksConfig),
    Trojan(TrojanConfig),
    Wireguard(WireguardConfig),
}

impl ProxyImpl {
    pub fn support_udp(&self) -> bool {
        match self {
            ProxyImpl::Socks5(c) => c.udp,
            ProxyImpl::Shadowsocks(c) => c.udp,
            ProxyImpl::Trojan(c) => c.udp,
            _ => true,
        }
    }
}

/// A group of proxies
#[derive(Debug)]
pub struct ProxyGroup {
    name: String,
    proxies: Vec<GeneralProxy>,
    selection: RwLock<GeneralProxy>,
}

impl ProxyGroup {
    pub fn new<S: Into<String>>(
        name: S,
        proxies: Vec<GeneralProxy>,
        selection: GeneralProxy,
    ) -> Self {
        Self {
            name: name.into(),
            proxies,
            selection: RwLock::new(selection),
        }
    }

    pub fn get_proxy(&self) -> Arc<Proxy> {
        let selected = self.selection.read().unwrap();
        match *selected {
            GeneralProxy::Single(ref p) => p.clone(),
            GeneralProxy::Group(ref g) => g.get_proxy(),
        }
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_members(&self) -> &Vec<GeneralProxy> {
        &self.proxies
    }

    pub fn get_selection(&self) -> GeneralProxy {
        self.selection.read().unwrap().clone()
    }

    pub fn set_selection(&self, name: &str) -> anyhow::Result<()> {
        for p in &self.proxies {
            match p {
                GeneralProxy::Single(p) => {
                    if p.name == name {
                        *self.selection.write().unwrap() = GeneralProxy::Single(p.clone());
                        return Ok(());
                    }
                }
                GeneralProxy::Group(g) => {
                    if g.name == name {
                        *self.selection.write().unwrap() = GeneralProxy::Group(g.clone());
                        return Ok(());
                    }
                }
            }
        }
        Err(anyhow!("Proxy not found"))
    }
}

#[derive(Debug, Clone)]
pub enum GeneralProxy {
    Single(Arc<Proxy>),
    Group(Arc<ProxyGroup>),
}

impl Display for GeneralProxy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GeneralProxy::Single(s) => f.write_str(s.name.as_str()),
            GeneralProxy::Group(g) => write!(f, "{}<{}>", g.name, g.selection.read().unwrap()),
        }
    }
}

impl PartialEq for GeneralProxy {
    fn eq(&self, other: &Self) -> bool {
        match self {
            GeneralProxy::Single(s) => {
                if let GeneralProxy::Single(rhs) = other {
                    return s.name == rhs.name;
                }
            }
            GeneralProxy::Group(g) => {
                if let GeneralProxy::Group(rhs) = other {
                    return g.name == rhs.name;
                }
            }
        }
        false
    }
}
