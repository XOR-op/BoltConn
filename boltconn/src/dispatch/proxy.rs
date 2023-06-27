use crate::adapter::{HttpConfig, ShadowSocksConfig, Socks5Config};
use crate::proxy::NetworkAddr;
use crate::transport::trojan::TrojanConfig;
use crate::transport::wireguard::WireguardConfig;
use anyhow::anyhow;
use arc_swap::ArcSwap;
use shadowsocks::ServerAddr;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Latency {
    Unknown,
    Value(u32),
    Failed,
}

/// Single proxy configuation.
#[derive(Debug)]
pub struct Proxy {
    name: String,
    detail: Arc<ProxyImpl>,
    latency: Mutex<Latency>,
}

impl Proxy {
    pub fn new<S: Into<String>>(name: S, detail: ProxyImpl) -> Self {
        Self {
            name: name.into(),
            detail: Arc::new(detail),
            latency: Mutex::new(Latency::Unknown),
        }
    }
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_impl(&self) -> Arc<ProxyImpl> {
        self.detail.clone()
    }

    pub fn get_latency(&self) -> Latency {
        *self.latency.lock().unwrap()
    }

    pub fn set_latency(&self, latency: Latency) {
        *self.latency.lock().unwrap() = latency;
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
    Chain(Vec<GeneralProxy>),
}

impl ProxyImpl {
    pub fn support_udp(&self) -> bool {
        match self {
            ProxyImpl::Direct => true,
            ProxyImpl::Reject => true,
            ProxyImpl::Http(_) => false,
            ProxyImpl::Socks5(c) => c.udp,
            ProxyImpl::Shadowsocks(c) => c.udp,
            ProxyImpl::Trojan(c) => c.udp,
            ProxyImpl::Wireguard(_) => true,
            // since it's hard to determine, we just assume it true
            ProxyImpl::Chain(_) => true,
        }
    }

    pub fn simple_description(&self) -> String {
        match self {
            ProxyImpl::Direct => "direct",
            ProxyImpl::Reject => "reject",
            ProxyImpl::Http(_) => "http",
            ProxyImpl::Socks5(_) => "socks5",
            ProxyImpl::Shadowsocks(_) => "shadowsocks",
            ProxyImpl::Trojan(_) => "trojan",
            ProxyImpl::Wireguard(_) => "wireguard",
            ProxyImpl::Chain(_) => "chain",
        }
        .to_string()
    }

    pub fn server_addr(&self) -> Option<NetworkAddr> {
        match self {
            ProxyImpl::Direct | ProxyImpl::Reject | ProxyImpl::Chain(_) => None,
            ProxyImpl::Http(c) => Some(c.server_addr.clone()),
            ProxyImpl::Socks5(c) => Some(c.server_addr.clone()),
            ProxyImpl::Shadowsocks(c) => Some(match c.server_addr.clone() {
                ServerAddr::SocketAddr(s) => NetworkAddr::Raw(s),
                ServerAddr::DomainName(domain_name, port) => {
                    NetworkAddr::DomainName { domain_name, port }
                }
            }),
            ProxyImpl::Trojan(c) => Some(c.server_addr.clone()),
            ProxyImpl::Wireguard(c) => Some(c.endpoint.clone()),
        }
    }
}

/// A group of proxies
#[derive(Debug)]
pub struct ProxyGroup {
    name: String,
    proxies: Vec<GeneralProxy>,
    selection: ArcSwap<GeneralProxy>,
    interface: Option<String>,
}

impl ProxyGroup {
    pub fn new<S: Into<String>>(
        name: S,
        proxies: Vec<GeneralProxy>,
        selection: GeneralProxy,
        interface: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            proxies,
            selection: ArcSwap::new(Arc::new(selection)),
            interface,
        }
    }

    pub fn get_proxy(&self) -> Arc<Proxy> {
        match self.selection.load().as_ref() {
            GeneralProxy::Single(p) => p.clone(),
            GeneralProxy::Group(g) => g.get_proxy(),
        }
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_members(&self) -> &Vec<GeneralProxy> {
        &self.proxies
    }

    pub fn get_selection(&self) -> Arc<GeneralProxy> {
        self.selection.load_full()
    }

    pub fn get_direct_interface(&self) -> Option<String> {
        self.interface.clone()
    }

    pub fn get_proxy_and_interface(&self) -> (Arc<Proxy>, Option<String>) {
        match self.selection.load().as_ref() {
            GeneralProxy::Single(ref p) => (p.clone(), self.get_direct_interface()),
            GeneralProxy::Group(ref g) => g.get_proxy_and_interface(),
        }
    }

    pub fn set_selection(&self, name: &str) -> anyhow::Result<()> {
        for p in &self.proxies {
            match p {
                GeneralProxy::Single(p) => {
                    if p.name == name {
                        self.selection
                            .store(Arc::new(GeneralProxy::Single(p.clone())));
                        return Ok(());
                    }
                }
                GeneralProxy::Group(g) => {
                    if g.name == name {
                        self.selection
                            .store(Arc::new(GeneralProxy::Group(g.clone())));
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
            GeneralProxy::Group(g) => write!(f, "{}<{}>", g.name, g.selection.load()),
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
