use crate::config::AuthData;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawInboundServiceConfig {
    Simple(u16),
    Complex { port: u16, auth: Vec<AuthData> },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawInboundConfig {
    #[serde(alias = "enable-tun", default = "default_true")]
    pub enable_tun: bool,
    pub http: Option<RawInboundServiceConfig>,
    pub socks5: Option<RawInboundServiceConfig>,
}

fn default_true() -> bool {
    true
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
socks: 8901
    ";
    let complex = "\
enable-tun: false
http: 1080
socks5:
    port: 8080
    auth:
    - username: alice
      password: bob
    - username: browser
      password: none
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
    let c: RawInboundConfig = serde_yaml::from_str(complex).unwrap();
    let err: serde_yaml::Result<RawInboundConfig> = serde_yaml::from_str(fail);
    assert!(err.is_err());
    println!("{:?}\n{:?}\n{:?}\n{:?}", n, s1, s2, c);
}
