use regex::Regex;
use std::collections::HashMap;
use std::str::FromStr;
use tokio::sync::RwLock;

#[derive(Copy, Clone, Debug)]
pub enum UrlModType {
    Resp302,
    Resp307,
    ReqHeader,
}

#[derive(Debug)]
pub struct UrlModRule {
    mod_type: UrlModType,
    regex: Regex,
    replaced_url: Vec<ReplacedUrlChunk>,
}

fn get_id(s: &str) -> Result<u8, core::num::ParseIntError> {
    u8::from_str(s.chars().skip(1).collect::<String>().as_str())
}

impl UrlModRule {
    pub fn new(mod_type: UrlModType, matched_url: &str, replaced_url: &str) -> Option<Self> {
        let Ok(regex) = Regex::new(matched_url) else {
            return None;
        };
        let pattern = Regex::new(r"\$\d+").unwrap();
        // test num ref validity
        for caps in pattern.captures_iter(replaced_url) {
            for m in caps.iter() {
                if let Some(idx) = m {
                    match get_id(idx.as_str()) {
                        Ok(idx) if idx < regex.captures_len() as u8 => {}
                        _ => return None,
                    }
                }
            }
        }
        // ok, construct
        let mut chunks = vec![];
        let mut last = 0;
        for ma in pattern.find_iter(replaced_url) {
            if last != ma.start() {
                chunks.push(ReplacedUrlChunk::Literal(
                    replaced_url[last..ma.start()].to_string(),
                ));
            }
            chunks.push(ReplacedUrlChunk::Captured(get_id(ma.as_str()).unwrap()));
            last = ma.end();
        }
        if last < replaced_url.len() {
            chunks.push(ReplacedUrlChunk::Literal(replaced_url[last..].to_string()));
        }
        Some(Self {
            mod_type,
            regex,
            replaced_url: chunks,
        })
    }

    pub fn rewrite(&self, url: &str) -> Option<String> {
        if let Some(caps) = self.regex.captures(url) {
            let mut res = String::new();
            for item in &self.replaced_url {
                match item {
                    ReplacedUrlChunk::Literal(s) => res += s.as_str(),
                    ReplacedUrlChunk::Captured(id) => {
                        if let Some(content) = caps.get(*id as usize) {
                            res += content.as_str()
                        } else {
                            // do nothing, "" for purpose
                        }
                    }
                }
            }
            Some(res)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
enum ReplacedUrlChunk {
    Literal(String),
    Captured(u8),
}

#[derive(Debug)]
struct UrlModManagerInner {
    host_rules: HashMap<String, Vec<UrlModRule>>,
    any_rules: Vec<UrlModRule>,
}

#[derive(Debug)]
pub struct UrlModManager {
    inner: RwLock<UrlModManagerInner>,
}

#[test]
fn test_url_match() {
    let raw_rule = UrlModRule::new(
        UrlModType::Resp302,
        "^https://twitter.com(.*)",
        "https://nitter.it$1",
    )
    .unwrap();
    assert_eq!(
        raw_rule.rewrite("https://twitter.com"),
        Some("https://nitter.it".to_string())
    );
    assert_eq!(
        raw_rule.rewrite("https://google.com/args?ref=https://twitter.com"),
        None
    );
    assert_eq!(
        raw_rule.rewrite("https://twitter.com/elon_musk"),
        Some("https://nitter.it/elon_musk".to_string())
    );
    drop(raw_rule);

    let cap_rule = UrlModRule::new(
        UrlModType::Resp302,
        r"^https://www.google.com/(.*\?)((.*)&)?(source=[^&]+)(.*)",
        "https://www.google.com/$1$3$5",
    )
    .unwrap();
    assert_eq!(
        cap_rule.rewrite("https://www.google.com/search?q=test"),
        None
    );
    assert_eq!(
        cap_rule.rewrite("https://www.google.com/search?q=test&utm_source=chrome"),
        None
    );
    assert_eq!(
        cap_rule.rewrite("https://www.google.com/search?q=test&source=chrome"),
        Some("https://www.google.com/search?q=test".to_string())
    );

    println!(
        "{:?}",
        UrlModRule::new(
            UrlModType::Resp302,
            r"https://www.google.com/(.*\?)((.*)&)?(source=[^&]+)(.*)",
            "https://www.google.com/$1$3$6",
        )
    );
    assert!(UrlModRule::new(
        UrlModType::Resp302,
        r"https://www.google.com/(.*\?)((.*)&)?(source=[^&]+)(.*)",
        "https://www.google.com/$1$3$6",
    )
    .is_none());
}
