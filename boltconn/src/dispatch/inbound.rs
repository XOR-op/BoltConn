use regex::Regex;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use std::{collections::HashMap, net::SocketAddr};

use crate::config::RawInboundServiceEntryConfig;

struct InboundAuth {
    user: String,
    password: String,
    alias: Option<String>,
}

pub(crate) struct InboundManager {
    addr: SocketAddr,
    auth: HashMap<String, InboundAuth>,
    // alias when no auth is configured
    default_alias: Option<String>,
}

impl InboundManager {
    pub fn new(
        addr: SocketAddr,
        auth: HashMap<String, RawInboundServiceEntryConfig>,
        default_alias: Option<String>,
    ) -> Self {
        let auth = auth
            .into_iter()
            .map(|(user, entry)| {
                let (password, alias) = match entry {
                    RawInboundServiceEntryConfig::Password(password) => (password, None),
                    RawInboundServiceEntryConfig::Complex { password, alias } => (password, alias),
                };
                let user_2 = user.clone();
                (
                    user,
                    InboundAuth {
                        user: user_2,
                        password,
                        alias,
                    },
                )
            })
            .collect();

        InboundManager {
            addr,
            auth,
            default_alias,
        }
    }

    pub fn has_auth(&self) -> bool {
        !self.auth.is_empty()
    }

    pub fn default_extra(&self) -> InboundExtra {
        InboundExtra {
            user: None,
            port: Some(self.addr.port()),
            alias: self.default_alias.clone(),
        }
    }

    pub fn authenticate(&self, user: &str, password: &str) -> Option<InboundExtra> {
        self.auth.get(user).and_then(|auth| {
            if auth.password == password {
                Some(InboundExtra {
                    user: Some(auth.user.clone()),
                    port: Some(self.addr.port()),
                    alias: auth.alias.clone(),
                })
            } else {
                None
            }
        })
    }
}

#[derive(Clone, PartialEq)]
pub(crate) enum InboundInfo {
    Tun,
    Http(InboundExtra),
    Socks5(InboundExtra),
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

    pub fn matches_alias(&self, alias: &str) -> bool {
        match self {
            InboundInfo::Tun => false,
            InboundInfo::Http(info) | InboundInfo::Socks5(info) => {
                info.alias.as_ref().map_or(false, |a| a == alias)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InboundExtra {
    pub(crate) user: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) alias: Option<String>,
}

impl InboundExtra {
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
            "{}{}{}{}",
            self.alias
                .as_ref()
                .map_or("".to_string(), |alias| { format!("<{alias}>") }),
            self.user
                .as_ref()
                .map_or("".to_string(), |user| format!("{user}@")),
            category,
            self.port
                .as_ref()
                .map_or("".to_string(), |port| format!(":{}", *port)),
        )
    }
}

impl Debug for InboundInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            match self {
                InboundInfo::Tun => "TUN".to_string(),
                InboundInfo::Http(info) => info.format("HTTP"),
                InboundInfo::Socks5(info) => info.format("SOCKS5"),
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
                    let identity = InboundExtra {
                        user: captures.name("user").map(|m| m.as_str().to_string()),
                        port: captures
                            .name("port")
                            .map(|m| u16::from_str(m.as_str()))
                            .transpose()
                            .map_err(|_| ())?,
                        alias: None, // Alias is not parsed from the string
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
