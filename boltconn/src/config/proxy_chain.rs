use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RawProxyChainCfg {
    pub chains: Vec<String>,
    pub interface: Option<String>,
}

impl RawProxyChainCfg {
    pub fn roughly_validate(&self) -> bool {
        !self.chains.is_empty()
    }
}
