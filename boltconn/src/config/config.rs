use crate::config::RuleProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawRootCfg {
    pub interface: String,
    pub api_port: u16,
    pub dns: RawDnsConfig,
    pub proxy_local: HashMap<String, RawProxyLocalCfg>,
    pub proxy_group: HashMap<String, Vec<String>>,
    pub rule_local: Vec<String>,
    pub rule_provider: HashMap<String, RuleProvider>,
    pub mitm_hosts: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawServerAddr {
    IpAddr(IpAddr),
    DomainName(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawDnsConfig {
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
    let config_text = fs::read_to_string("../_private/config/config.yml").unwrap();
    let deserialized: RawRootCfg = serde_yaml::from_str(&config_text).unwrap();
    println!("{:?}", deserialized)
}
