use radix_trie::{Trie, TrieCommon, TrieKey};

#[derive(Debug, Clone, Copy)]
enum HostType {
    Exact,
    Suffix,
}


pub struct HostMatcher(Trie<String, HostType>);

impl HostMatcher {
    pub fn matches(&self, host: &String) -> bool {
        let rev_dn: String = host.chars().rev().collect();
        if let Some(result) = self.0.get_ancestor(rev_dn.as_str()) {
            if let Some(val) = result.value() {
                match val {
                    HostType::Exact => {
                        if result.key().unwrap().len() == rev_dn.len() {
                            // DOMAIN rule
                            return true;
                        }
                    }
                    HostType::Suffix => {
                        if result.key().unwrap().len() <= rev_dn.len() {
                            // DOMAIN-SUFFIX rule
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}

pub struct HostMatcherBuilder(Vec<(String, HostType)>);

impl HostMatcherBuilder {
    pub fn new() -> Self {
        Self { 0: Vec::new() }
    }

    pub fn add_exact(&mut self, host: &str) {
        self.0.push((host.chars().rev().collect(), HostType::Exact))
    }

    pub fn add_suffix(&mut self, host: &str) {
        self.0.push((host.chars().rev().collect(), HostType::Suffix))
    }

    pub fn build(self) -> HostMatcher {
        HostMatcher(Trie::from_iter(self.0.into_iter()))
    }

    pub fn merge(&mut self, rhs: Self) {
        self.0.extend(rhs.0.into_iter());
    }
}

