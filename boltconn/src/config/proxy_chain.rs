use super::default_false;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RawProxyChainCfg {
    pub chains: Vec<String>,
    pub interface: Option<String>,
    #[serde(alias = "reconnect-when-changed", default = "default_false")]
    pub reconnect_when_changed: bool,
}

impl RawProxyChainCfg {
    pub fn roughly_validate(&self) -> bool {
        !self.chains.is_empty()
    }
}
