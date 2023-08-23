use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct InterceptionConfig {
    pub name: Option<String>,
    pub filters: Vec<String>,
    pub actions: Vec<String>,
}
