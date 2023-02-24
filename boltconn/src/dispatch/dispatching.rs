use crate::adapter::{HttpConfig, ShadowSocksConfig, Socks5Config};
use crate::config::{
    ProxySchema, RawProxyLocalCfg, RawProxyProviderCfg, RawRootCfg, RawServerAddr,
    RawServerSockAddr, RawState, RuleSchema,
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
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub struct ConnInfo {
    pub src: SocketAddr,
    pub dst: NetworkAddr,
    pub connection_type: NetworkType,
    pub process_info: Option<ProcessInfo>,
}

pub struct Dispatching {
    verbose: bool,
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
                    if self.verbose {
                        tracing::info!("[{:?}] {} => {} failed: UDP disabled", v, info.dst, proxy);
                    }
                    return Arc::new(ProxyImpl::Reject);
                }
                if self.verbose {
                    tracing::info!("[{:?}] {} => {}", v, info.dst, proxy);
                }
                return proxy_impl;
            }
        }

        // fallback proxy
        let proxy_impl = match &self.fallback {
            GeneralProxy::Single(p) => p.get_impl(),
            GeneralProxy::Group(g) => g.get_proxy().get_impl(),
        };
        if !proxy_impl.support_udp() && info.connection_type == NetworkType::Udp {
            if self.verbose {
                tracing::info!(
                    "[Fallback] {} => {} failed: UDP disabled",
                    info.dst,
                    self.fallback
                );
            }
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
    verbose: bool,
    proxies: HashMap<String, Arc<Proxy>>,
    groups: HashMap<String, Arc<ProxyGroup>>,
    rules: Vec<Rule>,
    fallback: Option<GeneralProxy>,
}

impl DispatchingBuilder {
    pub fn new(verbose: bool) -> Self {
        let mut r = Self {
            verbose,
            proxies: Default::default(),
            groups: Default::default(),
            rules: vec![],
            fallback: None,
        };
        r.proxies.insert(
            "DIRECT".into(),
            Arc::new(Proxy::new("DIRECT", ProxyImpl::Direct)),
        );
        r.proxies.insert(
            "REJECT".into(),
            Arc::new(Proxy::new("REJECT", ProxyImpl::Reject)),
        );
        r
    }

    pub fn build(
        mut self,
        cfg: &RawRootCfg,
        state: &RawState,
        rule_schema: &HashMap<String, RuleSchema>,
        proxy_schema: &HashMap<String, ProxySchema>,
    ) -> anyhow::Result<Dispatching> {
        // read all proxies
        self.parse_proxies(cfg.proxy_local.iter())?;
        for proxies in proxy_schema.values() {
            self.parse_proxies(proxies.proxies.iter().map(|c| (&c.name, &c.cfg)))?;
        }

        // read proxy groups
        let mut queued_groups = HashSet::new();
        for (name, group) in &cfg.proxy_group {
            self.parse_group(
                name,
                state,
                group.iter(),
                &cfg.proxy_group,
                proxy_schema,
                &mut queued_groups,
                false,
            )?;
        }
        for (name, schema) in proxy_schema {
            self.parse_group(
                name,
                state,
                schema.proxies.iter().map(RawProxyProviderCfg::get_name),
                &cfg.proxy_group,
                proxy_schema,
                &mut queued_groups,
                false,
            )?;
        }

        // read rules
        let mut ruleset = HashMap::new();
        for (name, schema) in rule_schema {
            let Some(builder) = RuleSetBuilder::new(name.as_str(),schema)else {
                return Err(anyhow!("Failed to parse provider {}",name));
            };
            ruleset.insert(name.clone(), Arc::new(builder.build()));
        }
        let mut rule_builder = RuleBuilder::new(&self.proxies, &self.groups, ruleset);
        for (idx, r) in cfg.rule_local.iter().enumerate() {
            if idx != cfg.rule_local.len() - 1 {
                rule_builder
                    .append_literal(r.as_str())
                    .map_err(|e| anyhow!("{} ({:?})", r, e))?;
            } else {
                // check Fallback
                self.fallback = Some(rule_builder.parse_fallback(r.as_str())?);
            }
        }
        self.rules.extend(rule_builder.build());
        if self.fallback.is_none() {
            return Err(anyhow!("Bad rules: missing fallback"));
        }
        tracing::info!("Loaded config successfully");
        Ok(Dispatching {
            verbose: self.verbose,
            proxies: self.proxies,
            groups: self.groups,
            rules: self.rules,
            fallback: self.fallback.unwrap(),
        })
    }

    /// Build a filter dispatching: for all encountered rule, return DIRECT; otherwise REJECT
    pub fn build_filter(
        mut self,
        rules: &[String],
        rule_schema: &HashMap<String, RuleSchema>,
    ) -> anyhow::Result<Dispatching> {
        let mut ruleset = HashMap::new();
        for (name, schema) in rule_schema {
            let Some(builder) = RuleSetBuilder::new(name.as_str(),schema)else {
                return Err(anyhow!("Filter: failed to parse provider {}",name));
            };
            ruleset.insert(name.clone(), Arc::new(builder.build()));
        }
        let mut rule_builder = RuleBuilder::new(&self.proxies, &self.groups, ruleset);
        for r in rules.iter() {
            rule_builder.append_literal((r.clone() + ", DIRECT").as_str())?;
        }
        self.rules.extend(rule_builder.build());
        self.fallback = Some(GeneralProxy::Single(Arc::new(Proxy::new(
            "REJECT",
            ProxyImpl::Reject,
        ))));
        Ok(Dispatching {
            verbose: self.verbose,
            proxies: self.proxies,
            groups: self.groups,
            rules: self.rules,
            fallback: self.fallback.unwrap(),
        })
    }

    pub fn direct_prioritize(&mut self, name: &str, prioritized: Vec<IpAddr>) {
        let ruleset = Arc::new(RuleSetBuilder::from_ipaddrs(name, prioritized).build());
        let mut new_rules = vec![Rule::new(
            RuleImpl::RuleSet(ruleset),
            GeneralProxy::Single(Arc::new(Proxy::new("Direct", ProxyImpl::Direct))),
        )];
        new_rules.append(&mut self.rules);
        self.rules = new_rules
    }

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
                RawProxyLocalCfg::Http {
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
                            return Err(anyhow!("Bad Http {}: invalid configuration", *name));
                        }
                    };

                    Arc::new(Proxy::new(
                        name.clone(),
                        ProxyImpl::Http(HttpConfig {
                            server_addr: NetworkAddr::from(server, *port),
                            auth,
                        }),
                    ))
                }
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

    #[allow(clippy::too_many_arguments)]
    // recursion for topological order
    fn parse_group<'a, I: Iterator<Item = &'a String>>(
        &mut self,
        name: &str,
        state: &RawState,
        proxies: I,
        proxy_group: &HashMap<String, Vec<String>>,
        proxy_schema: &HashMap<String, ProxySchema>,
        queued_groups: &mut HashSet<String>,
        dup_as_error: bool,
    ) -> anyhow::Result<()> {
        if self.groups.contains_key(name)
            || self.proxies.contains_key(name)
            || queued_groups.contains(name)
        {
            return if dup_as_error {
                Err(anyhow!("Duplicate group name {}", name))
            } else {
                // has been processed, just skip
                Ok(())
            };
        }
        let mut arr = Vec::new();
        let mut selection = None;
        for p in proxies {
            let content = if let Some(single) = self.proxies.get(p) {
                GeneralProxy::Single(single.clone())
            } else if let Some(group) = self.groups.get(p) {
                GeneralProxy::Group(group.clone())
            } else {
                // toposort
                queued_groups.insert(name.to_string());

                if let Some(sub) = proxy_group.get(p) {
                    self.parse_group(
                        p,
                        state,
                        sub.iter(),
                        proxy_group,
                        proxy_schema,
                        queued_groups,
                        true,
                    )?;
                } else if let Some(schema) = proxy_schema.get(p) {
                    self.parse_group(
                        p,
                        state,
                        schema.proxies.iter().map(RawProxyProviderCfg::get_name),
                        proxy_group,
                        proxy_schema,
                        queued_groups,
                        true,
                    )?;
                } else {
                    return Err(anyhow!("No [{}] in group [{}]", p, name));
                }

                queued_groups.remove(name);
                GeneralProxy::Group(self.groups.get(p).unwrap().clone())
            };

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
}
