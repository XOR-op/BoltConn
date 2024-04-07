use super::config::{default_false, default_true};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct InterceptionConfig {
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(alias = "parrot-fingerprint", default = "default_false")]
    pub parrot_fingerprint: bool,
    pub filters: Vec<String>,
    pub actions: Vec<ActionConfig>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum ActionConfig {
    Script(ScriptActionConfig),
    Standard(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ScriptActionConfig {
    #[serde(alias = "script-name")]
    pub name: Option<String>,
    #[serde(alias = "type")]
    pub script_type: String,
    pub pattern: Option<String>,
    pub script: String,
}
