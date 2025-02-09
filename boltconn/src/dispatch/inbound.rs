use regex::Regex;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

#[derive(Clone, PartialEq)]
pub(crate) enum InboundInfo {
    Tun,
    Http(InboundIdentity),
    Socks5(InboundIdentity),
}

impl InboundInfo {
    pub fn contains(&self, rhs: &Self) -> bool {
        match (self, rhs) {
            (InboundInfo::Tun, InboundInfo::Tun) => true,
            (InboundInfo::Http(me), InboundInfo::Http(rhs)) => me.contains(rhs),
            (InboundInfo::Socks5(me), InboundInfo::Socks5(rhs)) => me.contains(rhs),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InboundIdentity {
    pub(crate) user: Option<String>,
    pub(crate) port: Option<u16>,
}

impl InboundIdentity {
    pub fn contains(&self, rhs: &Self) -> bool {
        let user_match = self
            .user
            .as_ref()
            .map(|user| (rhs.user.as_ref() == Some(user)));
        let port_match = self.port.map(|port| (rhs.port == Some(port)));
        !matches!(
            (user_match, port_match),
            (Some(false), _) | (_, Some(false))
        )
    }

    fn format(&self, category: &str) -> String {
        format!(
            "{}{}{}",
            self.user
                .as_ref()
                .map_or("".to_string(), |user| format!("{user}@")),
            category,
            self.port
                .as_ref()
                .map_or("".to_string(), |port| format!(":{}", *port))
        )
    }
}

impl Debug for InboundInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            match self {
                InboundInfo::Tun => "TUN".to_string(),
                InboundInfo::Http(user) => user.format("HTTP"),
                InboundInfo::Socks5(user) => user.format("SOCKS5"),
            }
            .as_str(),
        )
    }
}

impl Display for InboundInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl FromStr for InboundInfo {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "tun" {
            Ok(Self::Tun)
        } else {
            //
            let re = Regex::new(r"^((?P<user>[^@:]+)@)?(?P<inbound>http|socks5)(:(?P<port>\d+))?$")
                .unwrap();
            match re.captures(s) {
                Some(captures) => {
                    let identity = InboundIdentity {
                        user: captures.name("user").map(|m| m.as_str().to_string()),
                        port: captures
                            .name("port")
                            .map(|m| u16::from_str(m.as_str()))
                            .transpose()
                            .map_err(|_| ())?,
                    };
                    match captures.name("inbound").ok_or(())?.as_str() {
                        "http" => Ok(Self::Http(identity)),
                        "socks5" => Ok(Self::Socks5(identity)),
                        _ => unreachable!(),
                    }
                }
                None => Err(()),
            }
        }
    }
}

#[test]
fn parsing_inbound() {
    let valid_list = vec![
        "joe@http:1080",
        "joe@http",
        "http:8080",
        "joe@socks5:1080",
        "socks5",
    ];
    let invalid_list = vec!["joe@http:", "@http:1080", "@http:", "http:", "what"];
    for valid in valid_list {
        assert!(InboundInfo::from_str(valid).is_ok())
    }
    for invalid in invalid_list {
        assert!(InboundInfo::from_str(invalid).is_err())
    }
}
