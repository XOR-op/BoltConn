use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawState {
    pub proxy_group: String,
    pub proxy: String,
    pub rule: HashMap<String, String>,
}

impl RawState {
    pub fn into_state(self) -> State {
        todo!()
    }
}

pub struct State {}
