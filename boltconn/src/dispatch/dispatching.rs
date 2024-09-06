use crate::adapter::{HttpConfig, ShadowSocksConfig, Socks5Config};
use crate::config::{
    ConfigError, LoadedConfig, ProviderError, ProxyError, ProxySchema, RawProxyGroupCfg,
    RawProxyLocalCfg, RawProxyProviderOption, RawServerAddr, RawServerSockAddr, RawState,
    RuleAction, RuleConfigLine, RuleError,
};
use crate::dispatch::action::{Action, SubDispatch};
use crate::dispatch::proxy::ProxyImpl;
use crate::dispatch::rule::{RuleBuilder, RuleOrAction};
use crate::dispatch::ruleset::RuleSet;
use crate::dispatch::temporary::TemporaryList;
use crate::dispatch::{GeneralProxy, InboundInfo, Proxy, ProxyGroup, RuleSetTable};
use crate::external::MmdbReader;
use crate::instrument::action::InstrumentAction;
use crate::instrument::bus::MessageBus;
use crate::network::dns::Dns;
use crate::platform::process::{NetworkType, ProcessInfo};
use crate::proxy::NetworkAddr;
use crate::transport::ssh::{SshAuthentication, SshConfig};
use crate::transport::trojan::TrojanConfig;
use crate::transport::wireguard::WireguardConfig;
use arc_swap::ArcSwap;
use base64::Engine;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig};
use linked_hash_map::LinkedHashMap;
use regex::Regex;
use shadowsocks::crypto::CipherKind;
use shadowsocks::ServerAddr;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct ConnInfo {
    pub src: SocketAddr,
    pub dst: NetworkAddr,
    pub local_ip: Option<IpAddr>,
    pub inbound: InboundInfo,
    pub resolved_dst: Option<SocketAddr>,
    pub connection_type: NetworkType,
    pub process_info: Option<ProcessInfo>,
}

impl ConnInfo {
    pub fn dst_addr(&self) -> Option<&SocketAddr> {
        if let NetworkAddr::Raw(s) = &self.dst {
            Some(s)
        } else {
            self.resolved_dst.as_ref()
        }
    }
}

pub struct Dispatching {
    temporary_list: ArcSwap<TemporaryList>,
    templist_builder: DispatchingBuilder,
    proxies: HashMap<String, Arc<Proxy>>,
    groups: LinkedHashMap<String, Arc<ProxyGroup>>,
    snippet: DispatchingSnippet,
}

impl Dispatching {
    pub async fn matches(
        &self,
        info: &mut ConnInfo,
        verbose: bool,
    ) -> (String, Arc<ProxyImpl>, Option<String>) {
        if let Some(r) = self.temporary_list.load().matches(info, verbose).await {
            r
        } else {
            self.snippet.matches(info, verbose).await
        }
    }

    pub fn update_temporary_list(&self, list: &[RuleConfigLine]) -> Result<(), ConfigError> {
        let list = self.templist_builder.build_temporary_list(list)?;
        self.temporary_list.store(Arc::new(list));
        Ok(())
    }

    pub fn set_group_selection(&self, group: &str, proxy: &str) -> Result<(), ConfigError> {
        for (name, g) in self.groups.iter() {
            if name == group {
                return Ok(g.set_selection(proxy)?);
            }
        }
        Err(ProxyError::MissingGroup(group.to_string()).into())
    }

    pub fn get_group_list(&self) -> Vec<Arc<ProxyGroup>> {
        self.groups.values().cloned().collect()
    }
}

fn stringfy_process(info: &ConnInfo) -> &str {
    match &info.process_info {
        None => "UNKNOWN",
        Some(s) => s.name.as_str(),
    }
}

#[derive(Clone)]
pub struct DispatchingBuilder {
    config_path: PathBuf,
    proxies: HashMap<String, Arc<Proxy>>,
    groups: HashMap<String, Arc<ProxyGroup>>,
    rulesets: HashMap<String, Arc<RuleSet>>,
    group_order: Vec<String>,
    dns: Arc<Dns>,
    mmdb: Option<Arc<MmdbReader>>,
    msg_bus: Arc<MessageBus>,
}

impl DispatchingBuilder {
    pub fn empty(
        config_path: &Path,
        dns: Arc<Dns>,
        mmdb: Option<Arc<MmdbReader>>,
        msg_bus: Arc<MessageBus>,
    ) -> Self {
        let mut builder = Self {
            config_path: config_path.to_path_buf(),
            proxies: Default::default(),
            groups: Default::default(),
            rulesets: Default::default(),
            group_order: Default::default(),
            dns,
            mmdb,
            msg_bus,
        };
        builder.proxies.insert(
            "DIRECT".into(),
            Arc::new(Proxy::new("DIRECT", ProxyImpl::Direct)),
        );
        builder.proxies.insert(
            "REJECT".into(),
            Arc::new(Proxy::new("REJECT", ProxyImpl::Reject)),
        );
        builder.proxies.insert(
            "BLACKHOLE".into(),
            Arc::new(Proxy::new("BLACKHOLE", ProxyImpl::BlackHole)),
        );
        builder
    }

    pub fn new(
        config_path: &Path,
        dns: Arc<Dns>,
        mmdb: Option<Arc<MmdbReader>>,
        loaded_config: &LoadedConfig,
        ruleset: &RuleSetTable,
        msg_bus: Arc<MessageBus>,
    ) -> Result<Self, ConfigError> {
        let mut builder = Self::empty(config_path, dns, mmdb, msg_bus);
        // start init
        let LoadedConfig {
            config,
            state,
            proxy_schema,
            ..
        } = loaded_config;
        // read all proxies
        builder.parse_proxies(config.proxy_local.iter())?;
        for proxies in proxy_schema.values() {
            builder.parse_proxies(proxies.proxies.iter().map(|c| (&c.name, &c.cfg)))?;
        }

        // read proxy groups
        let mut wg_history = HashMap::new();
        let mut queued_groups = HashSet::new();
        builder.group_order = loaded_config.config.proxy_group.keys().cloned().collect();
        for (name, group) in &config.proxy_group {
            builder.parse_group(
                name,
                state,
                group,
                &config.proxy_group,
                proxy_schema,
                &mut queued_groups,
                &mut wg_history,
                false,
            )?;
        }
        builder.rulesets.clone_from(ruleset);
        Ok(builder)
    }

    pub fn build_temporary_list(
        &self,
        list: &[RuleConfigLine],
    ) -> Result<TemporaryList, ConfigError> {
        let (list, fallback) = self.build_rules_loosely(list)?;
        if fallback.is_none() {
            Ok(TemporaryList::new(list))
        } else {
            Err(ProxyError::Invalid("Fallback in temporary list".to_string()).into())
        }
    }

    pub fn build(self, loaded_config: &LoadedConfig) -> Result<Dispatching, ConfigError> {
        let (rules, fallback) = self.build_rules(loaded_config.config.rule_local.as_slice())?;

        let groups = {
            let mut g = LinkedHashMap::new();
            for name in &self.group_order {
                // Chain will not be included
                if let Some(val) = self.groups.get(name) {
                    g.insert(name.clone(), val.clone());
                }
            }
            g
        };
        let temporary_list = if let Some(list) = &loaded_config.state.temporary_list {
            self.build_temporary_list(list)?
        } else {
            TemporaryList::empty()
        };
        let proxies = self.proxies.clone();
        Ok(Dispatching {
            temporary_list: ArcSwap::new(Arc::new(temporary_list)),
            templist_builder: self,
            proxies,
            groups,
            snippet: DispatchingSnippet { rules, fallback },
        })
    }

    fn build_rules_loosely(
        &self,
        rules: &[RuleConfigLine],
    ) -> Result<(Vec<RuleOrAction>, Option<GeneralProxy>), ConfigError> {
        let mut rule_builder = RuleBuilder::new(
            self.dns.clone(),
            self.mmdb.clone(),
            &self.proxies,
            &self.groups,
            &self.rulesets,
        );
        for (idx, line) in rules.iter().enumerate() {
            match line {
                RuleConfigLine::Complex(action) => match action {
                    RuleAction::LocalResolve => rule_builder.append_local_resolve(),
                    RuleAction::SubDispatch(sub) => {
                        let matches = rule_builder.parse_incomplete(sub.matches.as_str())?;
                        let (sub_rules, sub_fallback) =
                            self.build_rules(sub.subrules.as_slice())?;
                        rule_builder.append(RuleOrAction::Action(Action::SubDispatch(
                            SubDispatch::new(
                                matches,
                                DispatchingSnippet {
                                    rules: sub_rules,
                                    fallback: sub_fallback,
                                },
                            ),
                        )))
                    }
                    RuleAction::Instrument(ins) => {
                        let matches = rule_builder.parse_incomplete(ins.matches.as_str())?;
                        rule_builder.append(RuleOrAction::Action(Action::Instrument(
                            InstrumentAction::new(
                                matches,
                                ins.id,
                                ins.message.clone(),
                                self.msg_bus.create_publisher(ins.id),
                            )?,
                        )))
                    }
                },
                RuleConfigLine::Simple(r) => {
                    if idx == rules.len() - 1 {
                        // check Fallback
                        if let Ok(fallback) = rule_builder.parse_fallback(r.as_str()) {
                            return Ok((rule_builder.emit_all(), Some(fallback)));
                        }
                    }
                    rule_builder.append_literal(r.as_str())?;
                }
            }
        }
        Ok((rule_builder.emit_all(), None))
    }

    fn build_rules(
        &self,
        rules: &[RuleConfigLine],
    ) -> Result<(Vec<RuleOrAction>, GeneralProxy), ConfigError> {
        let (list, fallback) = self.build_rules_loosely(rules)?;
        if let Some(fallback) = fallback {
            Ok((list, fallback))
        } else {
            Err(RuleError::MissingFallback.into())
        }
    }

    /// Build a filter dispatching: for all encountered rule, return DIRECT; otherwise REJECT
    pub fn build_filter(
        self,
        rules: &[String],
        ruleset: &RuleSetTable,
    ) -> Result<Dispatching, ConfigError> {
        let mut rule_builder = RuleBuilder::new(
            self.dns.clone(),
            self.mmdb.clone(),
            &self.proxies,
            &self.groups,
            ruleset,
        );
        for r in rules.iter() {
            rule_builder.append_literal((r.clone() + ", DIRECT").as_str())?;
        }
        let rules = rule_builder.emit_all();
        let groups = self
            .groups
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let proxies = self.proxies.clone();
        Ok(Dispatching {
            temporary_list: ArcSwap::new(Arc::new(TemporaryList::empty())),
            templist_builder: self,
            proxies,
            groups,
            snippet: DispatchingSnippet {
                rules,
                fallback: GeneralProxy::Single(Arc::new(Proxy::new("REJECT", ProxyImpl::Reject))),
            },
        })
    }

    fn parse_proxies<'a, I: Iterator<Item = (&'a String, &'a RawProxyLocalCfg)>>(
        &mut self,
        proxies: I,
    ) -> Result<(), ConfigError> {
        for (name, proxy) in proxies {
            // avoid duplication
            if self.proxies.contains_key(name) || self.groups.contains_key(name) {
                return Err(ProxyError::DuplicateProxy(name.to_string()).into());
            }
            let p = match proxy {
                RawProxyLocalCfg::Http { server, port, auth } => Arc::new(Proxy::new(
                    name.clone(),
                    ProxyImpl::Http(HttpConfig {
                        server_addr: NetworkAddr::from(server, *port),
                        auth: auth.clone(),
                    }),
                )),
                RawProxyLocalCfg::Socks5 {
                    server,
                    port,
                    auth,
                    udp,
                } => Arc::new(Proxy::new(
                    name.clone(),
                    ProxyImpl::Socks5(Socks5Config {
                        server_addr: NetworkAddr::from(server, *port),
                        auth: auth.clone(),
                        udp: *udp,
                    }),
                )),
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
                            return Err(ProxyError::ProxyFieldError(
                                name.clone(),
                                "Unknown cipher kind in Shadowsocks proxy",
                            )
                            .into());
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
                    local_addr_v6,
                    private_key,
                    public_key,
                    endpoint,
                    mtu,
                    preshared_key,
                    keepalive,
                    dns,
                    dns_preference,
                    reserved,
                    over_tcp,
                } => {
                    if local_addr.is_none() && local_addr_v6.is_none() {
                        return Err(ProxyError::ProxyFieldError(
                            name.clone(),
                            "No local address configured for the WireGuard outbound",
                        )
                        .into());
                    }
                    let endpoint = match endpoint {
                        RawServerSockAddr::Ip(addr) => NetworkAddr::Raw(*addr),
                        RawServerSockAddr::Domain(a) => {
                            let parts = a.split(':').collect::<Vec<&str>>();
                            let Some(port_str) = parts.get(1) else {
                                return Err(ProxyError::ProxyFieldError(
                                    name.clone(),
                                    "No port configured for the WireGuard outbound",
                                )
                                .into());
                            };
                            let port = port_str.parse::<u16>().map_err(|_| {
                                ProxyError::ProxyFieldError(name.clone(), "Invalid port")
                            })?;
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
                        let val = b64decoder.decode(private_key).map_err(|_| {
                            ProxyError::ProxyFieldError(
                                name.clone(),
                                "Decode private key in base64 format",
                            )
                        })?;
                        let val: [u8; 32] = val.try_into().map_err(|_| {
                            ProxyError::ProxyFieldError(name.clone(), "Invalid private key")
                        })?;
                        x25519_dalek::StaticSecret::from(val)
                    };
                    let public_key = {
                        let val = b64decoder.decode(public_key).map_err(|_| {
                            ProxyError::ProxyFieldError(
                                name.clone(),
                                "Decode public key in base64 format",
                            )
                        })?;
                        let val: [u8; 32] = val.try_into().map_err(|_| {
                            ProxyError::ProxyFieldError(name.clone(), "Invalid public key")
                        })?;
                        x25519_dalek::PublicKey::from(val)
                    };
                    let preshared_key = if let Some(v) = preshared_key {
                        let val = b64decoder.decode(v).map_err(|_| {
                            ProxyError::ProxyFieldError(name.clone(), "Decode PSK in base64 format")
                        })?;
                        let val: [u8; 32] = val.try_into().map_err(|_| {
                            ProxyError::ProxyFieldError(name.clone(), "Invalid PSK")
                        })?;
                        Some(val)
                    } else {
                        None
                    };
                    let dns = {
                        let list = String::from("[") + dns.as_str() + "]";
                        let list: Vec<IpAddr> =
                            serde_yaml::from_str(list.as_str()).map_err(|_| {
                                ProxyError::ProxyFieldError(name.clone(), "Invalid DNS")
                            })?;
                        let group: Vec<NameServerConfig> = list
                            .into_iter()
                            .map(|i| NameServerConfig::new(SocketAddr::new(i, 53), Protocol::Udp))
                            .collect();
                        ResolverConfig::from_parts(None, vec![], group)
                    };

                    Arc::new(Proxy::new(
                        name.clone(),
                        ProxyImpl::Wireguard(WireguardConfig {
                            name: name.clone(),
                            ip_addr: *local_addr,
                            ip_addr6: *local_addr_v6,
                            private_key,
                            public_key,
                            endpoint,
                            mtu: *mtu,
                            preshared_key,
                            keepalive: *keepalive,
                            dns,
                            dns_preference: *dns_preference,
                            reserved: *reserved,
                            over_tcp: *over_tcp,
                        }),
                    ))
                }
                RawProxyLocalCfg::Ssh {
                    server,
                    port,
                    user,
                    password,
                    private_key,
                    key_passphrase,
                    host_pubkey,
                } => {
                    // construct authentication data
                    let auth = if let Some(key_path) = private_key {
                        let key_content = russh::keys::load_secret_key(
                            get_file_path(self.config_path.as_path(), key_path).ok_or_else(
                                || {
                                    ProxyError::ProxyFieldError(
                                        name.clone(),
                                        "Invalid private key path",
                                    )
                                },
                            )?,
                            key_passphrase.as_ref().map(|s| s.as_str()),
                        )
                        .map_err(|_| {
                            ProxyError::ProxyFieldError(name.clone(), "Load private key file")
                        })?;
                        SshAuthentication::PrivateKey(Arc::new(key_content))
                    } else if let Some(passwd) = password {
                        SshAuthentication::Password(passwd.clone())
                    } else {
                        return Err(ProxyError::ProxyFieldError(
                            name.clone(),
                            "No authentication method configured for the SSH outbound",
                        )
                        .into());
                    };
                    // validate server's identity
                    let host_pubkey = if let Some(pubkey) = host_pubkey {
                        let (key_type, content) = pubkey.split_once(' ').ok_or_else(|| {
                            ProxyError::ProxyFieldError(
                                name.clone(),
                                "Invalid host public key format; expect '<key-type> <base64-data>'",
                            )
                        })?;
                        Some((
                            key_type.to_string(),
                            russh::keys::parse_public_key_base64(content).map_err(|_| {
                                ProxyError::ProxyFieldError(
                                name.clone(),
                                "Invalid host public key format; expect '<key-type> <base64-data>'",
                            )
                            })?,
                        ))
                    } else {
                        None
                    };
                    Arc::new(Proxy::new(
                        name.clone(),
                        ProxyImpl::Ssh(SshConfig {
                            server: NetworkAddr::from(server, *port),
                            user: user.clone(),
                            auth,
                            host_pubkey,
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
    fn parse_group(
        &mut self,
        name: &str,
        state: &RawState,
        proxy_group: &RawProxyGroupCfg,
        proxy_group_list: &LinkedHashMap<String, RawProxyGroupCfg>,
        proxy_schema: &HashMap<String, ProxySchema>,
        queued_groups: &mut HashSet<String>,
        wg_history: &mut HashMap<String, bool>,
        dup_as_error: bool,
    ) -> Result<(), ConfigError> {
        if self.groups.contains_key(name)
            || self.proxies.contains_key(name)
            || queued_groups.contains(name)
        {
            return if dup_as_error {
                Err(ProxyError::DuplicateProxy(name.to_string()).into())
            } else {
                // has been processed, just skip
                Ok(())
            };
        }
        if !proxy_group.roughly_validate() {
            return Err(ProxyError::Invalid(name.to_string()).into());
        }
        if let Some(chains) = &proxy_group.chains {
            // not proxy group, just chains
            let mut contents = vec![];
            for p in chains.iter().rev() {
                let proxy = self.parse_one_proxy(
                    p,
                    name,
                    state,
                    proxy_group_list,
                    proxy_schema,
                    queued_groups,
                    wg_history,
                )?;
                if let GeneralProxy::Single(px) = &proxy {
                    if px.get_impl().simple_description() == "wireguard"
                        && wg_history.insert(p.clone(), true).is_some()
                    {
                        tracing::warn!("WireGuard {} should not appear in different chains", p);
                    }
                }
                contents.push(proxy);
            }
            self.proxies.insert(
                name.to_string(),
                Arc::new(Proxy::new(name.to_string(), ProxyImpl::Chain(contents))),
            );
            Ok(())
        } else {
            // Genuine proxy group, including only proxies and providers
            let mut arr = Vec::new();
            let mut selection = None;
            // proxies
            for p in proxy_group.proxies.as_ref().unwrap_or(&vec![]) {
                let content = self.parse_one_proxy(
                    p,
                    name,
                    state,
                    proxy_group_list,
                    proxy_schema,
                    queued_groups,
                    wg_history,
                )?;
                if let GeneralProxy::Single(px) = &content {
                    if px.get_impl().simple_description() == "wireguard"
                        && wg_history.insert(p.clone(), false) == Some(true)
                    {
                        tracing::warn!("WireGuard {} should not appear in different chains", p);
                    }
                }
                if p == state.group_selection.get(name).unwrap_or(&String::new()) {
                    selection = Some(content.clone());
                }
                arr.push(content);
            }

            // used providers
            for p in proxy_group.providers.as_ref().unwrap_or(&vec![]) {
                let valid_proxies: Vec<&str> = match p {
                    RawProxyProviderOption::Name(name) => proxy_schema
                        .get(name)
                        .ok_or_else(|| ProviderError::Missing(name.clone()))?
                        .proxies
                        .iter()
                        .map(|entry| entry.name.as_str())
                        .collect(),
                    RawProxyProviderOption::Filter { name, filter } => {
                        let regex = Regex::new(filter)
                            .map_err(|_| ProviderError::BadFilter(name.clone(), filter.clone()))?;
                        proxy_schema
                            .get(name)
                            .ok_or_else(|| ProviderError::Missing(name.clone()))?
                            .proxies
                            .iter()
                            .filter_map(|entry| {
                                if regex.is_match(entry.name.as_str()) {
                                    Some(entry.name.as_str())
                                } else {
                                    None
                                }
                            })
                            .collect()
                    }
                };
                for p in valid_proxies {
                    let content = if let Some(single) = self.proxies.get(p) {
                        GeneralProxy::Single(single.clone())
                    } else {
                        return Err(ProxyError::UnknownProxyInGroup {
                            group: name.to_string(),
                            proxy: p.to_string(),
                        }
                        .into());
                    };
                    if p == state.group_selection.get(name).unwrap_or(&String::new()) {
                        selection = Some(content.clone());
                    }
                    arr.push(content);
                }
            }
            if arr.is_empty() {
                // No available proxies, skip
                return Ok(());
            }

            let first = arr.first().unwrap().clone();
            // If there is no selection now, select the first.
            self.groups.insert(
                name.to_string(),
                Arc::new(ProxyGroup::new(
                    name.to_string(),
                    arr,
                    selection.unwrap_or(first),
                    proxy_group.interface.clone(),
                )),
            );
            Ok(())
        }
    }

    // Just to avoid code duplication
    #[allow(clippy::too_many_arguments)]
    fn parse_one_proxy(
        &mut self,
        p: &str,
        name: &str,
        state: &RawState,
        proxy_group_list: &LinkedHashMap<String, RawProxyGroupCfg>,
        proxy_schema: &HashMap<String, ProxySchema>,
        queued_groups: &mut HashSet<String>,
        wg_history: &mut HashMap<String, bool>,
    ) -> Result<GeneralProxy, ConfigError> {
        Ok(if let Some(single) = self.proxies.get(p) {
            GeneralProxy::Single(single.clone())
        } else if let Some(group) = self.groups.get(p) {
            GeneralProxy::Group(group.clone())
        } else {
            // toposort
            queued_groups.insert(name.to_string());

            if let Some(sub) = proxy_group_list.get(p) {
                self.parse_group(
                    p,
                    state,
                    sub,
                    proxy_group_list,
                    proxy_schema,
                    queued_groups,
                    wg_history,
                    true,
                )?;
            } else {
                return Err(ProxyError::UnknownProxyInGroup {
                    group: name.to_string(),
                    proxy: p.to_string(),
                }
                .into());
            }

            queued_groups.remove(name);
            if let Some(group) = self.groups.get(p) {
                GeneralProxy::Group(group.clone())
            } else {
                GeneralProxy::Single(self.proxies.get(p).unwrap().clone())
            }
        })
    }
}

pub struct DispatchingSnippet {
    rules: Vec<RuleOrAction>,
    fallback: GeneralProxy,
}

impl DispatchingSnippet {
    pub async fn matches(
        &self,
        info: &mut ConnInfo,
        verbose: bool,
    ) -> (String, Arc<ProxyImpl>, Option<String>) {
        for v in &self.rules {
            match v {
                RuleOrAction::Rule(v) => {
                    if let Some(proxy) = v.matches(info) {
                        return Self::proxy_filtering(
                            &proxy,
                            info,
                            v.to_string().as_str(),
                            verbose,
                        );
                    }
                }
                RuleOrAction::Action(a) => match a {
                    Action::LocalResolve(r) => r.resolve_to(info).await,
                    Action::SubDispatch(sub) => {
                        if let Some(r) = sub.matches(info, verbose).await {
                            return r;
                        }
                    }
                    Action::Instrument(r) => r.execute(info).await,
                },
            }
        }
        Self::proxy_filtering(&self.fallback, info, "Fallback", verbose)
    }

    pub fn proxy_filtering(
        proxy: &GeneralProxy,
        info: &ConnInfo,
        rule_str: &str,
        verbose: bool,
    ) -> (String, Arc<ProxyImpl>, Option<String>) {
        let (proxy_impl, iface) = proxy.get_impl();
        let name = proxy.selected_instance_name();
        if !proxy_impl.support_udp() && info.connection_type == NetworkType::Udp {
            if verbose {
                tracing::info!(
                    "[{}]({},{}) {} => {}: Failed(UDP disabled)",
                    rule_str,
                    stringfy_process(info),
                    info.inbound,
                    info.dst,
                    proxy,
                );
            }
            return (name, Arc::new(ProxyImpl::Reject), None);
        }
        if verbose {
            tracing::info!(
                "[{}]({},{}) {} => {}",
                rule_str,
                stringfy_process(info),
                info.inbound,
                info.dst,
                proxy,
            );
        }
        (name, proxy_impl, iface)
    }
}

fn get_file_path(config_path: &Path, path: &Path) -> Option<PathBuf> {
    Some(if path.is_absolute() {
        path.to_path_buf()
    } else if path.to_string_lossy().starts_with("~/") {
        let home = PathBuf::from(std::env::var("HOME").ok()?);
        home.join(path.to_string_lossy().strip_prefix("~/")?)
    } else {
        config_path.join(path)
    })
}
