use super::config::default_true;
use crate::config::{PortOrSocketAddr, SingleOrVec};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawInboundServiceConfig {
    Simple(PortOrSocketAddr),
    Complex {
        #[serde(default = "default_inbound_ip_addr")]
        host: IpAddr,
        port: u16,
        #[serde(default = "default_inbound_mapping")]
        auth: HashMap<String, RawInboundServiceEntryConfig>,
        // different inbound can share a same alias
        alias: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawInboundServiceEntryConfig {
    Password(String),
    Complex {
        password: String,
        alias: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawInboundConfig {
    #[serde(alias = "enable-tun", default = "default_true")]
    pub enable_tun: bool,
    #[serde(alias = "enable-icmp-proxy", default = "default_true")]
    pub enable_icmp_proxy: bool,
    pub http: Option<SingleOrVec<RawInboundServiceConfig>>,
    pub socks5: Option<SingleOrVec<RawInboundServiceConfig>>,
}

#[test]
fn test_inbound() {
    let nothing = "\
enable-tun: true
    ";
    let simple1 = "\
http: 1234
    ";
    let simple2 = "\
http: 1234
socks5:
  - 8901
    ";
    let complex = "\
enable-tun: false
http: 1080
socks5:
  - 2000
  - port: 8080
    auth:
      alice: bob
      browser: none
    ";
    let complex2 = "\
enable-tun: false
http: 1080
socks5:
  - 2000
  - host: 0.0.0.0
    port: 8080
  - port: 3000
    auth:
      alice: bob
      browser: none
    ";
    let complex3 = "\
enable-tun: false
http: 1080
socks5:
  - 2000
  - host: 0.0.0.0
    port: 8080
  - port: 3000
    auth:
      alice:
        password: bob
        alias: alice_alias
      browser: none
    ";
    let fail = "\
enable-tun: false
http: 1080
socks5:
    port: 8080
    auth:
    - username: alice
      password: bob
    - username: browser
        ";
    let n: RawInboundConfig = serde_yaml::from_str(nothing).unwrap();
    let s1: RawInboundConfig = serde_yaml::from_str(simple1).unwrap();
    let s2: RawInboundConfig = serde_yaml::from_str(simple2).unwrap();
    let c1: RawInboundConfig = serde_yaml::from_str(complex).unwrap();
    let c2: RawInboundConfig = serde_yaml::from_str(complex2).unwrap();
    let c3: RawInboundConfig = serde_yaml::from_str(complex3).unwrap();
    let err: serde_yaml::Result<RawInboundConfig> = serde_yaml::from_str(fail);
    assert!(err.is_err());
    println!("{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}", n, s1, s2, c1, c2, c3);
}

pub(crate) fn default_inbound_ip_addr() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

fn default_inbound_mapping() -> HashMap<String, RawInboundServiceEntryConfig> {
    Default::default()
}
