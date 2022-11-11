use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawState {
    pub proxy_group: String,
    pub proxy: String,
    pub rule: HashMap<String, String>,
}

impl RawState {
    pub fn into_state(self) ->State{

    }
}

pub struct State{
    
}

