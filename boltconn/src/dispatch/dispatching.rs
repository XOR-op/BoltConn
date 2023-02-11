use crate::adapter::{ShadowSocksConfig, Socks5Config};
use crate::config::{
    ProxySchema, RawProxyLocalCfg, RawRootCfg, RawServerAddr, RawServerSockAddr, RawState,
    RuleSchema,
};
use crate::dispatch::proxy::ProxyImpl;
use crate::dispatch::rule::{Rule, RuleBuilder, RuleImpl};
use crate::dispatch::ruleset::RuleSetBuilder;
use crate::dispatch::{GeneralProxy, Proxy, ProxyGroup};
use crate::platform::process::{NetworkType, ProcessInfo};
use crate::proxy::NetworkAddr;
use crate::transport::trojan::TrojanConfig;
use crate::transport::wireguard::WireguardConfig;
use anyhow::anyhow;
use base64::Engine;
use shadowsocks::crypto::CipherKind;
use shadowsocks::ServerAddr;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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
            if let Some(proxy) = v.matches(info) {
                let proxy_impl = match &proxy {
                    GeneralProxy::Single(p) => p.get_impl(),
                    GeneralProxy::Group(g) => g.get_proxy().get_impl(),
                };
                if !proxy_impl.support_udp() && info.connection_type == NetworkType::Udp {
                    tracing::info!("[{:?}] {} => {} failed: UDP disabled", v, info.dst, proxy);
                    return Arc::new(ProxyImpl::Reject);
                }
                tracing::info!("[{:?}] {} => {}", v, info.dst, proxy);
                return proxy_impl;
            }
        }

        // fallback proxy
        let proxy_impl = match &self.fallback {
            GeneralProxy::Single(p) => p.get_impl(),
            GeneralProxy::Group(g) => g.get_proxy().get_impl(),
        };
        if !proxy_impl.support_udp() && info.connection_type == NetworkType::Udp {
            tracing::info!(
                "[Fallback] {} => {} failed: UDP disabled",
                info.dst,
                self.fallback
            );
            return Arc::new(ProxyImpl::Reject);
        }
        tracing::info!("[Fallback] {} => {}", info.dst, self.fallback);
        proxy_impl
    }

    pub fn set_group_selection(&self, group: &str, proxy: &str) -> anyhow::Result<()> {
        for (name, g) in self.groups.iter() {
            if name == group {
                return g.set_selection(proxy);
            }
        }
        Err(anyhow!("Group not found"))
    }

    pub fn get_group_list(&self) -> Vec<Arc<ProxyGroup>> {
        self.groups.values().cloned().collect()
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

    pub fn build(self) -> anyhow::Result<Dispatching> {
        if self.fallback.is_none() {
            return Err(anyhow!("Bad rules: missing fallback"));
        }
        Ok(Dispatching {
            proxies: self.proxies,
            groups: self.groups,
            rules: self.rules,
            fallback: self.fallback.unwrap(),
        })
    }
}

impl DispatchingBuilder {
    fn parse_proxies<'a, I: Iterator<Item = (&'a String, &'a RawProxyLocalCfg)>>(
        &mut self,
        proxies: I,
    ) -> anyhow::Result<()> {
        for (name, proxy) in proxies {
            // avoid duplication
            if self.proxies.contains_key(name) || self.groups.contains_key(name) {
                return Err(anyhow!("Duplicate proxy name:{}", *name));
            }
            let p = match proxy {
                RawProxyLocalCfg::Socks5 {
                    server,
                    port,
                    username,
                    password,
                    udp,
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

                    Arc::new(Proxy::new(
                        name.clone(),
                        ProxyImpl::Socks5(Socks5Config {
                            server_addr: NetworkAddr::from(server, *port),
                            auth,
                            udp: *udp,
                        }),
                    ))
                }
                RawProxyLocalCfg::Shadowsocks {
                    server,
                    port,
                    password,
                    cipher,
                    udp,
                } => {
                    let cipher_kind = match cipher.as_str() {
                        "chacha20-ietf-poly1305" => CipherKind::CHACHA20_POLY1305,
                        "aes-256-gcm" => CipherKind::AES_256_GCM,
                        "aes-128-gcm" => CipherKind::AES_128_GCM,
                        _ => {
                            return Err(anyhow!("Bad Shadowsocks {}: unsupported cipher", *name));
                        }
                    };
                    let addr = match server {
                        RawServerAddr::IpAddr(ip) => {
                            ServerAddr::SocketAddr(SocketAddr::new(*ip, *port))
                        }
                        RawServerAddr::DomainName(dn) => ServerAddr::DomainName(dn.clone(), *port),
                    };
                    Arc::new(Proxy::new(
                        name.clone(),
                        ProxyImpl::Shadowsocks(ShadowSocksConfig {
                            server_addr: addr,
                            password: password.clone(),
                            cipher_kind,
                            udp: *udp,
                        }),
                    ))
                }
                RawProxyLocalCfg::Trojan {
                    server,
                    port,
                    sni,
                    password,
                    skip_cert_verify,
                    websocket_path,
                    udp,
                } => {
                    let addr = match server {
                        RawServerAddr::IpAddr(ip) => NetworkAddr::Raw(SocketAddr::new(*ip, *port)),
                        RawServerAddr::DomainName(dn) => NetworkAddr::DomainName {
                            domain_name: dn.clone(),
                            port: *port,
                        },
                    };
                    Arc::new(Proxy::new(
                        name.clone(),
                        ProxyImpl::Trojan(TrojanConfig {
                            server_addr: addr,
                            password: password.clone(),
                            sni: sni.clone(),
                            skip_cert_verify: *skip_cert_verify,
                            websocket_path: websocket_path.clone(),
                            udp: *udp,
                        }),
                    ))
                }
                RawProxyLocalCfg::Wireguard {
                    local_addr,
                    private_key,
                    public_key,
                    endpoint,
                    mtu,
                    preshared_key,
                    keepalive,
                } => {
                    let endpoint = match endpoint {
                        RawServerSockAddr::Ip(addr) => NetworkAddr::Raw(*addr),
                        RawServerSockAddr::Domain(a) => {
                            let parts = a.split(':').collect::<Vec<&str>>();
                            let Some(port_str) = parts.get(1)else {
                                return Err(anyhow!("No port"));
                            };
                            let port = port_str.parse::<u16>()?;
                            #[allow(clippy::get_first)]
                            NetworkAddr::DomainName {
                                domain_name: parts.get(0).unwrap().to_string(),
                                port,
                            }
                        }
                    };
                    // parse key
                    let b64decoder = base64::engine::general_purpose::STANDARD;
                    let private_key = {
                        let val = b64decoder.decode(private_key)?;
                        let val: [u8; 32] =
                            val.try_into().map_err(|_| anyhow!("Decode private key"))?;
                        x25519_dalek::StaticSecret::from(val)
                    };
                    let public_key = {
                        let val = b64decoder.decode(public_key)?;
                        let val: [u8; 32] =
                            val.try_into().map_err(|_| anyhow!("Decode public key"))?;
                        x25519_dalek::PublicKey::from(val)
                    };
                    let preshared_key = if let Some(v) = preshared_key {
                        let val = b64decoder.decode(v)?;
                        let val: [u8; 32] = val.try_into().map_err(|_| anyhow!("Decode PSK"))?;
                        Some(val)
                    } else {
                        None
                    };

                    Arc::new(Proxy::new(
                        name.clone(),
                        ProxyImpl::Wireguard(WireguardConfig {
                            ip_addr: *local_addr,
                            private_key,
                            public_key,
                            endpoint,
                            mtu: *mtu,
                            preshared_key,
                            keepalive: *keepalive,
                        }),
                    ))
                }
            };
            self.proxies.insert(name.to_string(), p);
        }
        Ok(())
    }

    fn parse_group<'a, I: Iterator<Item = &'a String>>(
        &mut self,
        name: &str,
        state: &RawState,
        proxies: I,
    ) -> anyhow::Result<()> {
        if self.groups.contains_key(name) || self.proxies.contains_key(name) {
            return Err(anyhow!("Duplicate group name {}", name));
        }
        let mut arr = Vec::new();
        let mut selection = None;
        for p in proxies {
            let content = GeneralProxy::Single(
                self.proxies
                    .get(p)
                    .ok_or_else(|| {
                        anyhow!(
                            "Unrecognized name {:?}; nested group is unimplemented now",
                            p.clone()
                        )
                    })?
                    .clone(),
            );

            if p == state.group_selection.get(name).unwrap_or(&String::new()) {
                selection = Some(content.clone());
            }
            arr.push(content);
        }
        let first = arr.first().unwrap().clone();
        // If there is no selection now, select the first.
        self.groups.insert(
            name.to_string(),
            Arc::new(ProxyGroup::new(
                name.to_string(),
                arr,
                selection.unwrap_or(first),
            )),
        );
        Ok(())
    }

    pub fn new_from_config(
        cfg: &RawRootCfg,
        state: &RawState,
        rule_schema: HashMap<String, RuleSchema>,
        proxy_schema: HashMap<String, ProxySchema>,
    ) -> anyhow::Result<Self> {
        let mut builder = Self::new();
        builder.proxies.insert(
            "DIRECT".into(),
            Arc::new(Proxy::new("DIRECT", ProxyImpl::Direct)),
        );
        builder.proxies.insert(
            "REJECT".into(),
            Arc::new(Proxy::new("REJECT", ProxyImpl::Reject)),
        );
        // read all proxies
        builder.parse_proxies(cfg.proxy_local.iter())?;
        for proxies in proxy_schema.values() {
            builder.parse_proxies(proxies.proxies.iter().map(|c| (&c.name, &c.cfg)))?;
        }

        // read proxy groups
        for (name, group) in &cfg.proxy_group {
            builder.parse_group(name, state, group.iter())?;
        }
        for (name, schema) in &proxy_schema {
            builder.parse_group(name, state, schema.proxies.iter().map(|c| &c.name))?;
        }

        // read rules
        let mut ruleset = HashMap::new();
        for (name, schema) in rule_schema {
            let Some(builder) = RuleSetBuilder::new(name.as_str(),schema)else {
                return Err(anyhow!("Failed to parse provider {}",name));
            };
            ruleset.insert(name, builder);
        }
        let mut rule_builder = RuleBuilder::new(&builder.proxies, &builder.groups, ruleset);
        for (idx, r) in cfg.rule_local.iter().enumerate() {
            if idx != cfg.rule_local.len() - 1 {
                rule_builder.append_literal(r.as_str())?;
            } else {
                // check Fallback
                builder.fallback = Some(rule_builder.parse_fallback(r.as_str())?);
            }
        }
        builder.rules = rule_builder
            .build()
            .ok_or_else(|| anyhow!("Fail to build rules"))?;
        tracing::info!("Loaded config successfully");
        Ok(builder)
    }

    pub fn direct_prioritize(&mut self, name: &str, prioritized: Vec<IpAddr>) {
        let ruleset = RuleSetBuilder::from_ipaddrs(name, prioritized).build();
        let mut new_rules = vec![Rule::new(
            RuleImpl::RuleSet(ruleset),
            GeneralProxy::Single(Arc::new(Proxy::new("Direct", ProxyImpl::Direct))),
        )];
        new_rules.append(&mut self.rules);
        self.rules = new_rules
    }
}
