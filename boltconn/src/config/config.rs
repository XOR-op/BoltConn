use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    pub interface: String,
    pub dns: Vec<DnsConfig>,
    pub proxy: Vec<ProxyConfig>,
    pub policy: PolicyConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    pub list: Vec<SocketAddr>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub enum ProxyConfig {
    Socks5 {
        ip: IpAddr,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {}
