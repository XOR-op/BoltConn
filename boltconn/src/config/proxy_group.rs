use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RawProxyGroupCfg {
    pub proxies: Option<Vec<String>>,
    pub providers: Option<Vec<RawProxyProviderOption>>,
    pub chains: Option<Vec<String>>,
    pub interface: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields, untagged)]
pub enum RawProxyProviderOption {
    Name(String),
    Filter { name: String, filter: String },
}

impl RawProxyGroupCfg {
    pub fn roughly_validate(&self) -> bool {
        let valid_proxy_list = !(self.proxies.is_none() && self.providers.is_none());
        valid_proxy_list ^ self.chains.is_some()
    }
}
