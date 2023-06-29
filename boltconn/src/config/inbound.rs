use crate::config::AuthData;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, tag = "type")]
pub enum InboundPortNodeConfig {
    #[serde(alias = "http")]
    Http {
        port: u16,
        #[serde(flatten)]
        auth: Option<AuthData>,
    },
    #[serde(alias = "socks5")]
    Socks5 {
        port: u16,
        #[serde(flatten)]
        auth: Option<AuthData>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawPortConfig {
    Complex {
        inbounds: Vec<InboundPortNodeConfig>,
    },
    Simple {
        http: Option<u16>,
        socks5: Option<u16>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawInboundConfig {
    #[serde(alias = "enable-tun", default = "default_true")]
    pub enable_tun: bool,
    #[serde(flatten)]
    pub service_inbound: RawPortConfig,
}

fn default_true() -> bool {
    true
}

fn main() {
    let nothing = "\
enable-tun: true
    ";
    let simple1 = "\
http: 1234
    ";
    let simple2 = "\
http: 1234
socks: 8901
    ";
    let complex = "\
enable-tun: false
inbounds:
    - type: http
      port: 1080
    - type: socks5
      port: 8080
      username: alice
      password: bob
    ";
    let fail = "\
    enable-tun: false
    inbounds:
        - type: http
          port: 1080
        - type: socks5
          port: 8080
          username: alice
        ";
    let n: RawInboundConfig = serde_yaml::from_str(nothing).unwrap();
    let s1: RawInboundConfig = serde_yaml::from_str(simple1).unwrap();
    let s2: RawInboundConfig = serde_yaml::from_str(simple2).unwrap();
    let c: RawInboundConfig = serde_yaml::from_str(complex).unwrap();
    let err: serde_yaml::Result<RawInboundConfig> = serde_yaml::from_str(fail);
    assert!(err.is_err());
    println!("{:?}\n{:?}\n{:?}\n{:?}", n, s1, s2, c);
}
