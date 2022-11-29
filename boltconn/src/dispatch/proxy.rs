use crate::adapter::Socks5Config;
use anyhow::anyhow;
use shadowsocks::ServerConfig;
use std::sync::{Arc, Mutex};

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
    Drop,
    Socks5(Socks5Config),
    Shadowsocks(ServerConfig),
}

/// A group of proxies

#[derive(Debug)]
pub struct ProxyGroup {
    name: String,
    proxies: Vec<GeneralProxy>,
    selection: Mutex<GeneralProxy>,
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
            selection: Mutex::new(selection),
        }
    }

    pub fn get_proxy(&self) -> Arc<Proxy> {
        let selected = self.selection.lock().unwrap();
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
        self.selection.lock().unwrap().clone()
    }

    pub fn set_selection(&self, name: &str) -> anyhow::Result<()> {
        for p in &self.proxies {
            match p {
                GeneralProxy::Single(p) => {
                    if p.name == name {
                        *self.selection.lock().unwrap() = GeneralProxy::Single(p.clone());
                        return Ok(());
                    }
                }
                GeneralProxy::Group(g) => {
                    if g.name == name {
                        *self.selection.lock().unwrap() = GeneralProxy::Group(g.clone());
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
