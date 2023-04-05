use crate::config::proxy_group::RawProxyGroupCfg;
use crate::config::{ModuleConfig, ProxyProvider, RuleProvider};
use linked_hash_map::LinkedHashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawRootCfg {
    pub interface: String,
    #[serde(alias = "api-port")]
    pub api_port: u16,
    #[serde(alias = "api-key")]
    pub api_key: Option<String>,
    #[serde(alias = "http-port")]
    pub http_port: Option<u16>,
    #[serde(alias = "socks5-port")]
    pub socks5_port: Option<u16>,
    pub dns: RawDnsConfig,
    #[serde(alias = "proxy-local", default = "default_local_proxy")]
    pub proxy_local: HashMap<String, RawProxyLocalCfg>,
    #[serde(alias = "proxy-provider", default = "default_proxy_provider")]
    pub proxy_provider: HashMap<String, ProxyProvider>,
    #[serde(alias = "proxy-group")]
    pub proxy_group: LinkedHashMap<String, RawProxyGroupCfg>,
    #[serde(alias = "rule-local")]
    pub rule_local: Vec<String>,
    #[serde(alias = "rule-provider", default = "default_rule_provider")]
    pub rule_provider: HashMap<String, RuleProvider>,
    #[serde(alias = "intercept-rule", default = "default_str_vec")]
    pub intercept_rule: Vec<String>,
    #[serde(alias = "rewrite-rule", default = "default_str_vec")]
    pub rewrite: Vec<String>,
    #[serde(default = "default_module")]
    pub module: Vec<ModuleConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawServerAddr {
    IpAddr(IpAddr),
    DomainName(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawServerSockAddr {
    Ip(SocketAddr),
    Domain(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawDnsConfig {
    #[serde(alias = "force-direct-dns")]
    pub force_direct_dns: bool,
    pub bootstrap: Vec<IpAddr>,
    pub nameserver: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, tag = "type")]
pub enum RawProxyLocalCfg {
    #[serde(alias = "http")]
    Http {
        server: RawServerAddr,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    #[serde(alias = "socks5")]
    Socks5 {
        server: RawServerAddr,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        #[serde(default = "default_true")]
        udp: bool,
    },
    #[serde(alias = "ss")]
    Shadowsocks {
        server: RawServerAddr,
        port: u16,
        password: String,
        cipher: String,
        #[serde(default = "default_true")]
        udp: bool,
    },
    #[serde(alias = "trojan")]
    Trojan {
        server: RawServerAddr,
        port: u16,
        password: String,
        sni: String,
        #[serde(alias = "skip-cert-verify", default = "default_true")]
        skip_cert_verify: bool,
        #[serde(alias = "websocket-path")]
        websocket_path: Option<String>,
        #[serde(default = "default_true")]
        udp: bool,
    },
    #[serde(alias = "wireguard")]
    Wireguard {
        #[serde(alias = "local-addr")]
        local_addr: IpAddr,
        #[serde(alias = "private-key")]
        private_key: String,
        #[serde(alias = "public-key")]
        public_key: String,
        endpoint: RawServerSockAddr,
        mtu: usize,
        #[serde(alias = "public-key")]
        preshared_key: Option<String>,
        keepalive: Option<u16>,
    },
}

// Used for serde
fn default_true() -> bool {
    true
}

fn default_local_proxy() -> HashMap<String, RawProxyLocalCfg> {
    Default::default()
}

fn default_proxy_provider() -> HashMap<String, ProxyProvider> {
    Default::default()
}

pub(super) fn default_rule_provider() -> HashMap<String, RuleProvider> {
    Default::default()
}

fn default_module() -> Vec<ModuleConfig> {
    Default::default()
}

pub(super) fn default_str_vec() -> Vec<String> {
    Default::default()
}

#[ignore]
#[test]
fn test_raw_root_cfg() {
    let config_text = std::fs::read_to_string("../_private/config/config.yml").unwrap();
    let deserialized: RawRootCfg = serde_yaml::from_str(&config_text).unwrap();
    println!("{:?}", deserialized)
}
