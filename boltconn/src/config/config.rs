use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawRootCfg {
    pub interface: String,
    pub dns: Vec<RawDnsCfg>,
    pub proxy_local: Vec<RawProxyLocalCfg>,
    pub proxy_group: Vec<RawProxyGroupCfg>,
    pub policy_local: Vec<RawPolicyLocalCfg>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawDnsCfg {
    pub list: Vec<SocketAddr>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawProxyLocalCfg {
    proto: String,
    name: String,
    ip: IpAddr,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawProxyGroupCfg {
    name: String,
    list: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawPolicyLocalCfg {
    name: String,
    options: Vec<String>,
}
