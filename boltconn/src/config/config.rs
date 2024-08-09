use crate::config::inbound::RawInboundConfig;
use crate::config::interception::InterceptionConfig;
use crate::config::proxy_group::RawProxyGroupCfg;
use crate::config::{
    AuthData, ModuleConfig, PortOrSocketAddr, ProxyProvider, RuleConfigLine, RuleProvider,
};
use linked_hash_map::LinkedHashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawRootCfg {
    pub interface: String,
    #[serde(default = "default_inbound_config")]
    pub inbound: RawInboundConfig,
    #[serde(alias = "web-controller")]
    pub web_controller: Option<RawWebControllerConfig>,
    #[serde(alias = "instrument")]
    pub instrument: Option<RawInstrumentConfig>,
    #[serde(default = "default_false")]
    pub enable_dump: bool,
    // From now on, all the configs should be reloaded properly
    #[serde(alias = "speedtest-url", default = "default_speedtest_url")]
    pub speedtest_url: String,
    #[serde(alias = "geoip-db")]
    pub geoip_db: Option<String>,
    pub dns: RawDnsConfig,
    #[serde(alias = "proxy-local", default = "default_local_proxy")]
    pub proxy_local: HashMap<String, RawProxyLocalCfg>,
    #[serde(alias = "proxy-provider", default = "default_proxy_provider")]
    pub proxy_provider: HashMap<String, ProxyProvider>,
    #[serde(alias = "proxy-group")]
    pub proxy_group: LinkedHashMap<String, RawProxyGroupCfg>,
    #[serde(alias = "rule-local")]
    pub rule_local: Vec<RuleConfigLine>,
    #[serde(alias = "rule-provider", default = "default_rule_provider")]
    pub rule_provider: HashMap<String, RuleProvider>,
    #[serde(default = "default_interception_vec")]
    pub interception: Vec<InterceptionConfig>,
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

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub enum DnsPreference {
    #[serde(alias = "ipv4-only")]
    Ipv4Only,
    #[serde(alias = "ipv6-only")]
    Ipv6Only,
    #[serde(alias = "prefer-ipv4")]
    PreferIpv4,
    #[serde(alias = "prefer-ipv6")]
    PreferIpv6,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawDnsConfig {
    #[serde(default = "default_dns_pref")]
    pub preference: DnsPreference,
    pub bootstrap: Vec<IpAddr>,
    pub nameserver: Vec<String>,
    #[serde(default = "default_hosts")]
    pub hosts: HashMap<String, IpAddr>,
    #[serde(alias = "nameserver-policy", default = "default_str_str_mapping")]
    pub nameserver_policy: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawWebControllerConfig {
    #[serde(alias = "api-port", alias = "api-addr")]
    pub api_addr: PortOrSocketAddr,
    #[serde(alias = "api-key")]
    pub api_key: Option<String>,
    #[serde(alias = "cors-allowed-list", default = "default_str_vec")]
    pub cors_allowed_list: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawInstrumentConfig {
    #[serde(alias = "api-port", alias = "api-addr")]
    pub api_addr: PortOrSocketAddr,
    #[serde(alias = "api-key")]
    pub api_key: Option<String>,
    #[serde(alias = "cors-allowed-list", default = "default_str_vec")]
    pub cors_allowed_list: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, tag = "type")]
pub enum RawProxyLocalCfg {
    #[serde(alias = "http")]
    Http {
        server: RawServerAddr,
        port: u16,
        auth: Option<AuthData>,
    },
    #[serde(alias = "socks5")]
    Socks5 {
        server: RawServerAddr,
        port: u16,
        auth: Option<AuthData>,
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
        local_addr: Option<Ipv4Addr>,
        #[serde(alias = "local-addr6")]
        local_addr_v6: Option<Ipv6Addr>,
        #[serde(alias = "private-key")]
        private_key: String,
        #[serde(alias = "public-key")]
        public_key: String,
        endpoint: RawServerSockAddr,
        dns: String,
        #[serde(alias = "dns-preference", default = "default_dns_pref")]
        dns_preference: DnsPreference,
        mtu: usize,
        #[serde(alias = "preshared-key")]
        preshared_key: Option<String>,
        keepalive: Option<u16>,
        reserved: Option<[u8; 3]>,
        #[serde(alias = "over-tcp", default = "default_false")]
        over_tcp: bool,
    },
}

// Used for serde
pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_false() -> bool {
    false
}

fn default_local_proxy() -> HashMap<String, RawProxyLocalCfg> {
    Default::default()
}

fn default_proxy_provider() -> HashMap<String, ProxyProvider> {
    Default::default()
}

fn default_speedtest_url() -> String {
    "http://www.gstatic.com/generate_204".to_string()
}

fn default_inbound_config() -> RawInboundConfig {
    RawInboundConfig {
        enable_tun: true,
        http: None,
        socks5: None,
    }
}

pub(super) fn default_rule_provider() -> HashMap<String, RuleProvider> {
    Default::default()
}

fn default_module() -> Vec<ModuleConfig> {
    Default::default()
}

fn default_hosts() -> HashMap<String, IpAddr> {
    Default::default()
}

pub(super) fn default_str_str_mapping() -> HashMap<String, String> {
    Default::default()
}

fn default_dns_pref() -> DnsPreference {
    DnsPreference::PreferIpv4
}

pub(super) fn default_str_vec() -> Vec<String> {
    Default::default()
}

pub(super) fn default_interception_vec() -> Vec<InterceptionConfig> {
    Default::default()
}

#[ignore]
#[test]
fn test_raw_root_cfg() {
    let config_text = std::fs::read_to_string("../_private/config/config.yml").unwrap();
    let deserialized: RawRootCfg = serde_yaml::from_str(&config_text).unwrap();
    println!("{:?}", deserialized)
}
