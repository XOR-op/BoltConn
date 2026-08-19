use crate::config::inbound::RawInboundConfig;
use crate::config::interception::InterceptionConfig;
use crate::config::proxy_chain::RawProxyChainCfg;
use crate::config::proxy_group::RawProxyGroupCfg;
use crate::config::{
    AuthData, ModuleLocation, PortOrSocketAddr, ProxyProvider, RootSequenceEntry, RuleConfigLine,
    RuleProvider, SingleOrVec, Sourced,
};
use crate::platform::process::ProcessInfoDepth;
use linked_hash_map::LinkedHashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RawRootCfg {
    pub interface: String,
    #[serde(default = "default_inbound_config")]
    pub inbound: RawInboundConfig,
    pub web_controller: Option<RawWebControllerConfig>,
    pub instrument: Option<RawInstrumentConfig>,
    pub dispatching: Option<DispatchingConfig>,
    // From now on, all the configs should be reloaded properly
    #[serde(default = "default_speedtest_url")]
    pub speedtest_url: String,
    pub dns: RawDnsConfig,
    #[serde(default = "default_local_proxy")]
    pub proxy_local: HashMap<String, RawProxyLocalCfg>,
    #[serde(default = "default_proxy_provider")]
    pub proxy_provider: HashMap<String, ProxyProvider>,
    #[serde(default = "default_proxy_chain")]
    pub proxy_chain: LinkedHashMap<String, RawProxyChainCfg>,
    pub proxy_group: LinkedHashMap<String, RawProxyGroupCfg>,
    pub rules: Vec<RootSequenceEntry<RuleConfigLine>>,
    #[serde(default = "default_rule_provider")]
    pub rule_providers: HashMap<String, RuleProvider>,
    #[serde(default)]
    pub interception: Vec<RootSequenceEntry<InterceptionConfig>>,
    #[serde(default = "default_module")]
    pub modules: HashMap<String, ModuleLocation>,
}

/// Runtime configuration after modules and includes have been fully resolved.
#[derive(Debug, Clone)]
pub struct ResolvedRootCfg {
    pub interface: String,
    pub inbound: RawInboundConfig,
    pub web_controller: Option<RawWebControllerConfig>,
    pub instrument: Option<RawInstrumentConfig>,
    pub dispatching: Option<DispatchingConfig>,
    pub speedtest_url: String,
    pub dns: RawDnsConfig,
    pub proxy_local: HashMap<String, RawProxyLocalCfg>,
    pub proxy_provider: HashMap<String, ProxyProvider>,
    pub proxy_chain: LinkedHashMap<String, RawProxyChainCfg>,
    pub proxy_group: LinkedHashMap<String, RawProxyGroupCfg>,
    pub rules: Vec<Sourced<RuleConfigLine>>,
    pub rule_providers: HashMap<String, RuleProvider>,
    pub interception: Vec<Sourced<InterceptionConfig>>,
}

impl RawRootCfg {
    pub(crate) fn into_resolved(
        self,
        rules: Vec<Sourced<RuleConfigLine>>,
        rule_providers: HashMap<String, RuleProvider>,
        interception: Vec<Sourced<InterceptionConfig>>,
    ) -> ResolvedRootCfg {
        ResolvedRootCfg {
            interface: self.interface,
            inbound: self.inbound,
            web_controller: self.web_controller,
            instrument: self.instrument,
            dispatching: self.dispatching,
            speedtest_url: self.speedtest_url,
            dns: self.dns,
            proxy_local: self.proxy_local,
            proxy_provider: self.proxy_provider,
            proxy_chain: self.proxy_chain,
            proxy_group: self.proxy_group,
            rules,
            rule_providers,
            interception,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DispatchingConfig {
    #[serde(default = "default_false")]
    pub sni_sniff: bool,
    pub geoip_db: Option<String>,
    #[serde(default = "default_process_info_depth")]
    pub process_info_depth: ProcessInfoDepth,
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

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsPreference {
    Ipv4Only,
    Ipv6Only,
    PreferIpv4,
    PreferIpv6,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RawDnsConfig {
    #[serde(default = "default_dns_pref")]
    pub preference: DnsPreference,
    pub bootstrap: Vec<IpAddr>,
    pub nameserver: Vec<String>,
    #[serde(default = "default_hosts")]
    pub hosts: HashMap<String, IpAddr>,
    #[serde(default = "default_str_str_mapping")]
    pub nameserver_policy: HashMap<String, String>,
    pub tun_hijack_list: Option<Vec<PortOrSocketAddr>>,
    pub tun_bypass_list: Option<Vec<PortOrSocketAddr>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RawWebControllerConfig {
    pub api_addr: PortOrSocketAddr,
    pub api_key: Option<String>,
    #[serde(default = "default_str_vec")]
    pub cors_allowed_list: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RawInstrumentConfig {
    #[serde(alias = "api-port")]
    pub api_addr: PortOrSocketAddr,
    pub secret: Option<String>,
    #[serde(default = "default_str_vec")]
    pub cors_allowed_list: Vec<String>,
}

/// TLS certificate verification policy for AnyTLS.
///
/// Deserializes from either a boolean (`true` = verify, `false` = skip) or a
/// string pointing at a certificate to pin (a file path or inline PEM).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawCertVerify {
    Toggle(bool),
    Certificate(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    rename_all = "lowercase",
    rename_all_fields = "kebab-case"
)]
pub enum RawProxyLocalCfg {
    Http {
        server: RawServerAddr,
        port: u16,
        auth: Option<AuthData>,
    },
    Socks5 {
        server: RawServerAddr,
        port: u16,
        auth: Option<AuthData>,
        #[serde(default = "default_true")]
        udp: bool,
    },
    #[serde(rename = "ss")]
    Shadowsocks {
        server: RawServerAddr,
        port: u16,
        password: String,
        cipher: String,
        #[serde(default = "default_true")]
        udp: bool,
    },
    Trojan {
        server: RawServerAddr,
        port: u16,
        password: String,
        sni: String,
        #[serde(default = "default_true")]
        skip_cert_verify: bool,
        websocket_path: Option<String>,
        #[serde(default = "default_true")]
        udp: bool,
    },
    Anytls {
        server: RawServerAddr,
        port: u16,
        password: String,
        sni: String,
        // Mandatory: `true` to verify, `false` to skip, or a certificate
        // (path or inline PEM) to pin against.
        cert_verify: RawCertVerify,
        #[serde(default = "default_true")]
        reuse_session: bool,
        #[serde(default = "default_true")]
        udp: bool,
    },
    Wireguard {
        local_addr: Option<Ipv4Addr>,
        #[serde(alias = "local-addr6")]
        local_addr_v6: Option<Ipv6Addr>,
        private_key: String,
        public_key: String,
        endpoint: RawServerSockAddr,
        dns: String,
        #[serde(default = "default_dns_pref")]
        dns_preference: DnsPreference,
        mtu: usize,
        preshared_key: Option<String>,
        keepalive: Option<u16>,
        reserved: Option<[u8; 3]>,
        #[serde(default = "default_false")]
        over_tcp: bool,
    },
    Ssh {
        server: RawServerAddr,
        port: u16,
        user: String,
        password: Option<String>,
        private_key: Option<PathBuf>,
        key_passphrase: Option<String>,
        host_pubkey: Option<SingleOrVec<String>>,
    },
}

// Used for serde
pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_false() -> bool {
    false
}

pub fn default_process_info_depth() -> ProcessInfoDepth {
    ProcessInfoDepth::Unlimited
}

fn default_local_proxy() -> HashMap<String, RawProxyLocalCfg> {
    Default::default()
}

fn default_proxy_provider() -> HashMap<String, ProxyProvider> {
    Default::default()
}

fn default_proxy_chain() -> LinkedHashMap<String, RawProxyChainCfg> {
    Default::default()
}

fn default_speedtest_url() -> String {
    "http://www.gstatic.com/generate_204".to_string()
}

fn default_inbound_config() -> RawInboundConfig {
    RawInboundConfig {
        enable_tun: true,
        enable_icmp_proxy: true,
        http: None,
        socks5: None,
        firewall: Default::default(),
    }
}

pub(super) fn default_rule_provider() -> HashMap<String, RuleProvider> {
    Default::default()
}

fn default_module() -> HashMap<String, ModuleLocation> {
    Default::default()
}

fn default_hosts() -> HashMap<String, IpAddr> {
    Default::default()
}

fn default_str_str_mapping() -> HashMap<String, String> {
    Default::default()
}

fn default_dns_pref() -> DnsPreference {
    DnsPreference::PreferIpv4
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

#[test]
fn embedded_default_config_uses_the_current_schema() {
    let config: RawRootCfg = serde_yaml::from_str(include_str!("default/config.yml"))
        .expect("generated default config must use the canonical schema");
    assert_eq!(config.rules.len(), 1);
}

#[test]
fn test_dispatching_config_process_info_depth_defaults_to_unlimited() {
    let config: DispatchingConfig = serde_yaml::from_str("{}").unwrap();
    assert_eq!(config.process_info_depth, ProcessInfoDepth::Unlimited);
}

#[test]
fn test_dispatching_config_process_info_depth_accepts_numeric_depth() {
    let config: DispatchingConfig = serde_yaml::from_str("process-info-depth: 3").unwrap();
    assert_eq!(config.process_info_depth, ProcessInfoDepth::Limited(3));
}

#[test]
fn test_dispatching_config_process_info_depth_accepts_unlimited() {
    let config: DispatchingConfig = serde_yaml::from_str("process-info-depth: unlimited").unwrap();
    assert_eq!(config.process_info_depth, ProcessInfoDepth::Unlimited);
}

#[test]
fn test_dispatching_config_process_info_depth_rejects_invalid_string() {
    let err = serde_yaml::from_str::<DispatchingConfig>("process-info-depth: forever").unwrap_err();
    assert!(
        err.to_string()
            .contains("expected a non-negative integer or \"unlimited\"")
    );
}

#[test]
fn test_anytls_cert_verify_parsing() {
    let cfg = "
type: anytls
server: anytls.example.com
port: 443
password: secret
sni: anytls.example.com
cert-verify: true
";
    let parsed: RawProxyLocalCfg = serde_yaml::from_str(cfg).unwrap();
    let RawProxyLocalCfg::Anytls { cert_verify, .. } = parsed else {
        panic!("expected anytls config");
    };
    assert!(matches!(cert_verify, RawCertVerify::Toggle(true)));
    let underscore_cfg = cfg.replace("cert-verify", "cert_verify");
    assert!(serde_yaml::from_str::<RawProxyLocalCfg>(&underscore_cfg).is_err());

    // A string value is interpreted as a certificate to pin.
    let cfg = cfg.replace("cert-verify: true", "cert-verify: ./certs/server.pem");
    let parsed: RawProxyLocalCfg = serde_yaml::from_str(&cfg).unwrap();
    let RawProxyLocalCfg::Anytls { cert_verify, .. } = parsed else {
        panic!("expected anytls config");
    };
    assert!(matches!(cert_verify, RawCertVerify::Certificate(s) if s == "./certs/server.pem"));

    // cert-verify has no default and must be supplied.
    let cfg = cfg.replace("cert-verify: ./certs/server.pem\n", "");
    assert!(serde_yaml::from_str::<RawProxyLocalCfg>(&cfg).is_err());
}
