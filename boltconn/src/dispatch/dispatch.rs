use crate::adapter::{OutboundType, Socks5Config};
use crate::config::{RawRootCfg, RawState};
use crate::dispatch::proxy::ProxyImpl;
use crate::dispatch::rule::Rule;
use crate::dispatch::{GeneralProxy, Proxy, ProxyGroup};
use crate::platform::process::{NetworkType, ProcessInfo};
use crate::session::NetworkAddr;
use anyhow::anyhow;
use fast_socks5::AuthenticationMethod;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct ConnInfo {
    pub src: SocketAddr,
    pub dst: NetworkAddr,
    pub connection_type: NetworkType,
    pub process_info: Option<ProcessInfo>,
}

pub struct Dispatching {
    proxies: HashMap<String, Arc<Proxy>>,
    groups: HashMap<String, Arc<ProxyGroup>>,
    rules: Vec<Rule>,
    fallback: GeneralProxy,
}

impl Dispatching {
    pub fn matches(&self, info: &ConnInfo) -> ProxyImpl {
        for v in &self.rules {
            if let Some(proxy) = v.matches(&info) {
                return match proxy.as_ref() {
                    GeneralProxy::Single(p) => p.get_impl(),
                    GeneralProxy::Group(g) => g.get_selection().get_impl(),
                };
            }
        }
        match &self.fallback {
            GeneralProxy::Single(p) => p.get_impl(),
            GeneralProxy::Group(g) => g.get_selection().get_impl(),
        }
    }
}

pub struct DispatchingBuilder {
    proxies: HashMap<String, Arc<Proxy>>,
    groups: HashMap<String, Arc<ProxyGroup>>,
    rules: Vec<Rule>,
    fallback: Option<GeneralProxy>,
}

impl DispatchingBuilder {
    pub fn new() -> Self {
        Self {
            proxies: HashMap::new(),
            groups: Default::default(),
            rules: vec![],
            fallback: None,
        }
    }
    pub fn add_proxy<S: Into<String>>(&mut self, name: S, cfg: ProxyImpl) -> &mut Self {
        self.proxies.insert(name.into(), cfg);
        self
    }
    pub fn add_rule(&mut self, cfg: Rule) -> &mut Self {
        self.rules.push(cfg);
        self
    }
    pub fn add_fallback(&mut self, cfg: GeneralProxy) -> &mut Self {
        self.fallback = Some(cfg);
        self
    }

    pub fn build(self) -> Dispatching {
        Dispatching {
            proxies: self.proxies,
            groups: self.groups,
            rules: self.rules,
            fallback: self
                .fallback
                .unwrap_or(GeneralProxy::Single(Arc::new(Proxy::new(
                    "Direct",
                    ProxyImpl::Direct,
                )))),
        }
    }
}

impl DispatchingBuilder {
    pub fn new_from_config(cfg: &RawRootCfg, state: &RawState) -> anyhow::Result<Self> {
        let mut builder = Self::new();
        builder.proxies.insert(
            "DIRECT".into(),
            Arc::new(Proxy::new("DIRECT", ProxyImpl::Direct)),
        );
        builder
            .proxies
            .insert("DROP".into(), Arc::new(Proxy::new("DROP", ProxyImpl::Drop)));
        // read all proxies
        for (name, proxy) in &cfg.proxy_local {
            // avoid duplication
            match builder.proxies.entry(name.clone()) {
                Entry::Occupied(_) => {
                    return Err(anyhow!("Duplicate proxy name:{}", *name));
                }
                Entry::Vacant(e) => match proxy.proto.as_str() {
                    "socks5" => {
                        if proxy.password.is_some() && proxy.username.is_none() {
                            return Err(anyhow!(
                                "Bad Socks5 {}: empty username but non-empty password",
                                *name
                            ));
                        }
                        let auth = if proxy.username.is_some() || proxy.password.is_some() {
                            AuthenticationMethod::Password {
                                username: proxy.username.as_ref().unwrap().clone(),
                                password: proxy.password.as_ref().unwrap_or(&String::new()).clone(),
                            }
                        } else {
                            AuthenticationMethod::None
                        };
                        e.insert(Arc::new(Proxy::new(
                            name.clone(),
                            ProxyImpl::Socks5(Socks5Config {
                                server_addr: SocketAddr::new(proxy.ip, proxy.port),
                                auth,
                            }),
                        )));
                    }
                    _ => unimplemented!(),
                },
            }
        }
        // read proxy groups
        for (name, group) in &cfg.proxy_group {
            let mut arr = Vec::new();
            let mut selection = None;
            for p in group {
                let content = Arc::new(GeneralProxy::Single(
                    builder
                        .proxies
                        .get(p)
                        .ok_or_else(|| {
                            anyhow!(
                                "Unrecognized name {:?}; nested group is unimplemented now",
                                p.clone()
                            )
                        })?
                        .clone(),
                ));
                if p == state.group.get(name).unwrap_or(&String::new()) {
                    selection = Some(content.clone());
                }
                arr.push(content);
            }
            // todo: add some check
            let first = arr.first().unwrap().clone();
            builder.groups.insert(
                name.clone(),
                Arc::new(ProxyGroup::new(
                    name.clone(),
                    arr,
                    selection.unwrap_or(first),
                )),
            );
        }
        // read rules
        for r in &cfg.rule_local {}
        Ok(builder)
    }
}
