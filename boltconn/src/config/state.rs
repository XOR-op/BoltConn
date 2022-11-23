use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawState {
    pub proxy: String,
    pub group: HashMap<String, String>,
}


#[ignore]
#[test]
fn test_raw_state() {
    let config_text = fs::read_to_string("../_private/config/state.yml").unwrap();
    let deserialized: RawState = serde_yaml::from_str(&config_text).unwrap();
    println!("{:?}", deserialized)
}
