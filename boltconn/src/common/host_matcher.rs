use radix_trie::{Trie, TrieCommon};

#[derive(Debug, Clone, Copy)]
enum HostType {
    Exact,
    Suffix,
}

pub struct HostMatcher(Trie<String, HostType>);

impl HostMatcher {
    pub fn matches(&self, host: &str) -> bool {
        let rev_dn: String = host.chars().rev().collect();
        if let Some(result) = self.0.get_ancestor(rev_dn.as_str()) {
            if let Some(val) = result.value() {
                let key = result.key().unwrap();
                match val {
                    HostType::Exact => {
                        if key.len() == rev_dn.len() {
                            // DOMAIN rule
                            return true;
                        }
                    }
                    HostType::Suffix => {
                        if key.len() == rev_dn.len()
                            || (key.len() < rev_dn.len()
                                && rev_dn.chars().nth(key.len()).unwrap() == '.')
                        {
                            // DOMAIN-SUFFIX rule
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

pub struct HostMatcherBuilder(Vec<(String, HostType)>);

impl HostMatcherBuilder {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add_exact(&mut self, host: &str) {
        self.0.push((host.chars().rev().collect(), HostType::Exact))
    }

    pub fn add_suffix(&mut self, host: &str) {
        self.0
            .push((host.chars().rev().collect(), HostType::Suffix))
    }

    pub fn build(self) -> HostMatcher {
        HostMatcher(Trie::from_iter(self.0))
    }

    pub fn merge(&mut self, rhs: Self) {
        self.0.extend(rhs.0);
    }
}

#[test]
fn test_matcher() {
    let mut builder = HostMatcherBuilder::new();
    builder.add_suffix("telemetry.google.com");
    builder.add_suffix("analytics.google.com");
    builder.add_exact("test.google.com");
    let matcher = builder.build();
    assert!(!matcher.matches("google.com"));
    assert!(matcher.matches("telemetry.google.com"));
    assert!(matcher.matches("t-01.telemetry.google.com"));
    assert!(matcher.matches("test.google.com"));
    assert!(!matcher.matches("notgoogle.com"));
    assert!(!matcher.matches("me.notgoogle.com"));
    assert!(!matcher.matches("ogle.com"));
    assert!(!matcher.matches("t-02.test.google.com"));
    let mut builder = HostMatcherBuilder::new();
    builder.add_suffix("ogle.com");
    let matcher = builder.build();
    assert!(matcher.matches("hi.ogle.com"));
    assert!(!matcher.matches("google.com"));
    assert!(!matcher.matches("hi.google.com"));
}
