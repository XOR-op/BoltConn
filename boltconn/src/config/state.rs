use crate::config::RuleConfigLine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawState {
    pub group_selection: HashMap<String, String>,
    pub temporary_list: Option<Vec<RuleConfigLine>>,
}

#[derive(Debug)]
pub struct LinkedState {
    pub state_path: PathBuf,
    pub state: RawState,
}

fn default_list() -> Vec<RuleConfigLine> {
    Default::default()
}

#[ignore]
#[test]
fn test_raw_state() {
    let config_text = std::fs::read_to_string("../_private/config/state.yml").unwrap();
    let deserialized: RawState = serde_yaml::from_str(&config_text).unwrap();
    println!("{:?}", deserialized)
}
