use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubDispatchConfig {
    pub matches: String,
    pub subrules: Vec<RuleConfigLine>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RuleAction {
    #[serde(alias = ".LOCAL-RESOLVE")]
    LocalResolve,
    #[serde(alias = ".SUB-DISPATCH")]
    SubDispatch(SubDispatchConfig),
}

// Warning: order matters here; changing order may result in break
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RuleConfigLine {
    Complex(RuleAction),
    Simple(String),
}

#[test]
fn test_rule_config() {
    let config = "
    - DOMAIN-SUFFIX, google.com, DIRECT
    - .LOCAL-RESOLVE
    - IP-CIDR, 1.0.0.0/8, REJECT
    - .SUB-DISPATCH:
        matches: INBOUND, vscode/socks5
        subrules:
        - IP-CIDR, 8.0.0.0/8, DIRECT
        - FALLBACK, REJECT
    - FALLBACK, DIRECT
";
    let s: Vec<RuleConfigLine> = serde_yaml::from_str(config).unwrap();
    assert!(matches!(
        s.get(1).unwrap(),
        RuleConfigLine::Complex(RuleAction::LocalResolve)
    ));
    let r = s.get(2).unwrap();
    match r {
        RuleConfigLine::Complex(_) => panic!(),
        RuleConfigLine::Simple(l) => assert_eq!("IP-CIDR, 1.0.0.0/8, REJECT", l),
    }
    assert!(matches!(
        s.get(3).unwrap(),
        RuleConfigLine::Complex(RuleAction::SubDispatch(_))
    ))
}
