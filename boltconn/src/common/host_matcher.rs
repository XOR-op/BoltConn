use zerotrie::ZeroTrieSimpleAscii;

#[derive(Debug, Clone, Copy)]
enum HostType {
    Exact,
    Suffix,
}

impl HostType {
    fn from_usize(value: usize) -> Option<Self> {
        match value {
            0 => Some(Self::Exact),
            1 => Some(Self::Suffix),
            _ => None,
        }
    }

    fn matches_host(self, key_len: usize, rev_dn: &[u8]) -> bool {
        match self {
            Self::Exact => key_len == rev_dn.len(),
            Self::Suffix => {
                key_len == rev_dn.len()
                    || (key_len < rev_dn.len() && rev_dn[key_len] == b'.')
            }
        }
    }
}

impl From<HostType> for usize {
    fn from(value: HostType) -> Self {
        match value {
            HostType::Exact => 0,
            HostType::Suffix => 1,
        }
    }
}

pub struct HostMatcher(ZeroTrieSimpleAscii<Vec<u8>>);

impl HostMatcher {
    pub fn matches(&self, host: &str) -> bool {
        let rev_dn: String = host.chars().rev().collect();
        let rev_dn_bytes = rev_dn.as_bytes();
        let mut cursor = self.0.cursor();

        if let Some(value) = cursor.take_value()
            && let Some(host_type) = HostType::from_usize(value)
            && host_type.matches_host(0, rev_dn_bytes)
        {
            return true;
        }

        // Walk every ancestor in the reversed hostname and accept the first
        // rule that matches the original exact/suffix semantics.
        for (idx, byte) in rev_dn_bytes.iter().copied().enumerate() {
            cursor.step(byte);
            if let Some(value) = cursor.take_value()
                && let Some(host_type) = HostType::from_usize(value)
                && host_type.matches_host(idx + 1, rev_dn_bytes)
            {
                return true;
            }
            if cursor.is_empty() {
                break;
            }
        }
        false
    }

    pub fn builder() -> HostMatcherBuilder {
        HostMatcherBuilder::new()
    }
}

pub struct HostMatcherBuilder(Vec<(String, HostType)>);

impl HostMatcherBuilder {
    fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add_exact(&mut self, host: &str) {
        self.0.push((host.chars().rev().collect(), HostType::Exact))
    }

    pub fn add_suffix(&mut self, host: &str) {
        self.0
            .push((host.chars().rev().collect(), HostType::Suffix))
    }

    /// Automatically add a host to the matcher, determining the type based on wildcards.
    pub fn add_auto(&mut self, host: &str) {
        if let Some(stripped_host) = host.strip_prefix("*.") {
            self.add_suffix(stripped_host);
        } else {
            self.add_exact(host);
        }
    }

    pub fn build(self) -> HostMatcher {
        HostMatcher(ZeroTrieSimpleAscii::from_iter(
            self.0.into_iter().map(|(k, v)| (k, v.into())),
        ))
    }

    pub fn merge(&mut self, rhs: Self) {
        self.0.extend(rhs.0);
    }
}

#[test]
fn test_matcher() {
    let mut builder = HostMatcher::builder();
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
    let mut builder = HostMatcher::builder();
    builder.add_suffix("ogle.com");
    let matcher = builder.build();
    assert!(matcher.matches("hi.ogle.com"));
    assert!(!matcher.matches("google.com"));
    assert!(!matcher.matches("hi.google.com"));
}

#[test]
fn test_matcher_ancestor_preference() {
    let mut builder = HostMatcher::builder();
    builder.add_suffix("com");
    builder.add_exact("google.com");
    let matcher = builder.build();

    assert!(matcher.matches("google.com"));
    assert!(matcher.matches("mail.google.com"));
}
