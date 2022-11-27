use crate::adapter::{OutboundType, Socks5Config};
use crate::config::{RawProxyLocalCfg, RawRootCfg, RawServerAddr, RawState};
use crate::dispatch::proxy::ProxyImpl;
use crate::dispatch::rule::{Rule, RuleBuilder};
use crate::dispatch::{GeneralProxy, Proxy, ProxyGroup};
use crate::platform::process::{NetworkType, ProcessInfo};
use crate::session::NetworkAddr;
use anyhow::anyhow;
use fast_socks5::AuthenticationMethod;
use shadowsocks::crypto::v1::CipherKind;
use shadowsocks::{ServerAddr, ServerConfig};
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
    pub fn matches(&self, info: &ConnInfo) -> Arc<ProxyImpl> {
        for v in &self.rules {
            if let Some(proxy) = v.matches(&info) {
                tracing::trace!("Matches policy {:?}", v);
                return match proxy.as_ref() {
                    GeneralProxy::Single(p) => p.get_impl(),
                    GeneralProxy::Group(g) => g.get_selection().get_impl(),
                };
            }
        }
        tracing::trace!("Fallback policy");
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
    pub fn add_proxy<S: Into<String>>(&mut self, name: S, cfg: Arc<Proxy>) -> &mut Self {
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
                Entry::Vacant(e) => match proxy {
                    RawProxyLocalCfg::Socks5 {
                        server,
                        port,
                        username,
                        password,
                    } => {
                        let auth = {
                            if let (Some(username), Some(passwd)) = (username, password) {
                                Some((username.clone(), passwd.clone()))
                            } else if let (None, None) = (username, password) {
                                None
                            } else {
                                return Err(anyhow!("Bad Socks5 {}: invalid configuration", *name));
                            }
                        };

                        e.insert(Arc::new(Proxy::new(
                            name.clone(),
                            ProxyImpl::Socks5(Socks5Config {
                                server_addr: NetworkAddr::from(server, *port),
                                auth,
                            }),
                        )));
                    }
                    RawProxyLocalCfg::Shadowsocks {
                        server,
                        port,
                        password,
                        cipher,
                    } => {
                        let cipher_kind = match cipher.as_str() {
                            "chacha20-ietf-poly1305" => CipherKind::CHACHA20_POLY1305,
                            "aes-256-gcm" => CipherKind::AES_256_GCM,
                            "aes-128-gcm" => CipherKind::AES_128_GCM,
                            _ => {
                                return Err(anyhow!(
                                    "Bad Shadowsocks {}: unsupported cipher",
                                    *name
                                ));
                            }
                        };
                        let addr = match server {
                            RawServerAddr::IpAddr(ip) => {
                                ServerAddr::SocketAddr(SocketAddr::new(ip.clone(), *port))
                            }
                            RawServerAddr::DomainName(dn) => {
                                ServerAddr::DomainName(dn.clone(), *port)
                            }
                        };
                        e.insert(Arc::new(Proxy::new(
                            name.clone(),
                            ProxyImpl::Shadowsocks(ServerConfig::new(
                                addr,
                                password.clone(),
                                cipher_kind,
                            )),
                        )));
                    }
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
                if p == state.group_selection.get(name).unwrap_or(&String::new()) {
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
        let rule_builder = RuleBuilder {
            proxies: &builder.proxies,
            groups: &builder.groups,
        };
        for r in &cfg.rule_local {
            let Some(rule) = rule_builder.parse_literal(r.as_str()) else {
                return Err(anyhow!("Failed to parse rule:{}",r));
            };
            builder.rules.push(rule);
        }
        tracing::info!("Loaded config successfully");
        Ok(builder)
    }
}
