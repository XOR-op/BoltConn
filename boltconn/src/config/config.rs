use crate::config::RuleProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawRootCfg {
    pub interface: String,
    #[serde(alias = "api-port")]
    pub api_port: u16,
    pub dns: RawDnsConfig,
    #[serde(alias = "proxy-local")]
    pub proxy_local: HashMap<String, RawProxyLocalCfg>,
    #[serde(alias = "proxy-group")]
    pub proxy_group: HashMap<String, Vec<String>>,
    #[serde(alias = "rule-local")]
    pub rule_local: Vec<String>,
    #[serde(alias = "rule-provider")]
    pub rule_provider: HashMap<String, RuleProvider>,
    #[serde(alias = "mitm-host")]
    pub mitm_host: Option<Vec<String>>,
    #[serde(alias = "rewrite-rule")]
    pub rewrite: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawServerAddr {
    IpAddr(IpAddr),
    DomainName(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawDnsConfig {
    #[serde(alias = "force-direct-dns")]
    pub force_direct_dns: bool,
    pub bootstrap: Vec<IpAddr>,
    pub nameserver: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, tag = "proto")]
pub enum RawProxyLocalCfg {
    #[serde(alias = "socks5")]
    Socks5 {
        server: RawServerAddr,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    #[serde(alias = "ss")]
    Shadowsocks {
        server: RawServerAddr,
        port: u16,
        password: String,
        cipher: String,
    },
}

#[ignore]
#[test]
fn test_raw_root_cfg() {
    let config_text = std::fs::read_to_string("../_private/config/config.yml").unwrap();
    let deserialized: RawRootCfg = serde_yaml::from_str(&config_text).unwrap();
    println!("{:?}", deserialized)
}
