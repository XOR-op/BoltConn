use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawRootCfg {
    pub interface: String,
    pub dns: Vec<String>,
    pub proxy_local: HashMap<String, RawProxyLocalCfg>,
    pub proxy_group: HashMap<String, Vec<String>>,
    pub rule_local: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawProxyLocalCfg {
    pub proto: String,
    pub ip: IpAddr,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[ignore]
#[test]
fn test_raw_root_cfg() {
    let config_text = fs::read_to_string("../_private/config/config.yml").unwrap();
    let deserialized: RawRootCfg = serde_yaml::from_str(&config_text).unwrap();
    println!("{:?}", deserialized)
}
