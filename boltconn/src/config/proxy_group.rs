use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RawProxyGroupCfg {
    pub proxies: Option<Vec<String>>,
    pub providers: Option<Vec<RawProxyProviderOption>>,
    pub interface: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields, untagged, rename_all_fields = "kebab-case")]
pub enum RawProxyProviderOption {
    Name(String),
    Filter { name: String, filter: String },
}

impl RawProxyGroupCfg {
    pub fn roughly_validate(&self) -> bool {
        !(self.proxies.is_none() && self.providers.is_none())
    }
}
