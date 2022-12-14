use regex::{Regex, RegexSet};
use std::collections::HashMap;
use std::str::FromStr;
use tokio::sync::RwLock;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum UrlModType {
    R301,
    R302,
    R307,
    R308,
    R404,
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
    fn new(mod_type: UrlModType, matched_url: &str, replaced_url: Option<&str>) -> Option<Self> {
        let Ok(regex) = Regex::new(matched_url) else {
            return None;
        };
        if mod_type == UrlModType::R404 {
            return Some(Self {
                mod_type,
                regex,
                replaced_url: vec![],
            });
        }

        let pattern = Regex::new(r"\$\d+").unwrap();
        let replaced_url = replaced_url.unwrap();
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

    pub fn rewrite(&self, url: &str) -> Option<(UrlModType, Option<String>)> {
        match self.mod_type {
            UrlModType::R301 | UrlModType::R302 | UrlModType::R307 | UrlModType::R308 => {
                if let Some(caps) = self.regex.captures(url) {
                    let mut res = String::new();
                    for item in &self.replaced_url {
                        match item {
                            ReplacedUrlChunk::Literal(s) => res += s.as_str(),
                            ReplacedUrlChunk::Captured(id) => {
                                if let Some(content) = caps.get(*id as usize) {
                                    res += content.as_str()
                                } else {
                                    // do nothing, "" as intended
                                }
                            }
                        }
                    }
                    Some((self.mod_type, Some(res)))
                } else {
                    None
                }
            }
            UrlModType::R404 => {
                if self.regex.is_match(url) {
                    Some((self.mod_type, None))
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
enum ReplacedUrlChunk {
    Literal(String),
    Captured(u8),
}

#[derive(Debug)]
pub struct UrlModManager {
    rules: Vec<UrlModRule>,
    regex_set: RegexSet,
    // inner: RwLock<UrlModManagerInner>,
}

impl UrlModManager {
    pub fn new(cfg: &[String]) -> anyhow::Result<Self> {
        let (rules, regexes) = parse_rules(cfg).map_err(|s| anyhow::anyhow!(s))?;
        Ok(Self {
            rules,
            regex_set: RegexSet::new(&regexes)?, // inner: RwLock::new(new_inner),
        })
    }

    pub fn empty() -> Self {
        Self {
            rules: vec![],
            regex_set: RegexSet::empty(),
        }
    }

    pub async fn try_rewrite(&self, url: &str) -> Option<(UrlModType, Option<String>)> {
        let matches = self.regex_set.matches(url);
        if matches.matched_any() {
            // rewrite with the first rule; the topper, the more priority
            let idx = matches.iter().next().unwrap();
            self.rules.get(idx).unwrap().rewrite(url)
        } else {
            None
        }
    }
}

fn parse_rules(cfg: &[String]) -> Result<(Vec<UrlModRule>, Vec<String>), String> {
    let mut coll = vec![];
    let mut str_coll = vec![];
    for line in cfg {
        // url, <Rewrite_type>, <original_url>, <modified_url>
        // Example: url, ^https://twitter.com(.*), 302, https://nitter.it$1
        //          url, ^https://doubleclick.com, 404
        let processed_str: String = line.chars().filter(|c| *c != ' ').collect();
        let list: Vec<&str> = processed_str.split(',').collect();
        if list.len() < 3 {
            return Err(line.clone());
        }
        // check rule
        if *list.get(0).unwrap() != "url" {
            return Err(line.clone());
        }
        let (mod_type, valid_len) = match *list.get(2).unwrap() {
            "301" => (UrlModType::R301, 4),
            "302" => (UrlModType::R302, 4),
            "307" => (UrlModType::R307, 4),
            "308" => (UrlModType::R308, 4),
            "404" => (UrlModType::R404, 3),
            _ => return Err(line.clone()),
        };
        if list.len() != valid_len {
            return Err(line.clone());
        }
        match UrlModRule::new(
            mod_type,
            list.get(1).unwrap(),
            if mod_type != UrlModType::R404 {
                Some(list.get(3).unwrap())
            } else {
                None
            },
        ) {
            None => return Err(line.clone()),
            Some(instance) => {
                coll.push(instance);
                str_coll.push(list.get(1).unwrap().to_string());
            }
        }
    }
    Ok((coll, str_coll))
}

#[test]
fn test_url_match() {
    let raw_rule = UrlModRule::new(
        UrlModType::R302,
        "^https://twitter.com(.*)",
        Some("https://nitter.it$1"),
    )
    .unwrap();
    assert_eq!(
        raw_rule.rewrite("https://twitter.com"),
        Some((UrlModType::R302, Some("https://nitter.it".to_string())))
    );
    assert_eq!(
        raw_rule.rewrite("https://google.com/args?ref=https://twitter.com"),
        None
    );
    assert_eq!(
        raw_rule.rewrite("https://twitter.com/elon_musk"),
        Some((
            UrlModType::R302,
            Some("https://nitter.it/elon_musk".to_string())
        ))
    );
    drop(raw_rule);

    let cap_rule = UrlModRule::new(
        UrlModType::R302,
        r"^https://www.google.com/(.*\?)((.*)&)?(source=[^&]+)(.*)",
        Some("https://www.google.com/$1$3$5"),
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
        Some((
            UrlModType::R302,
            Some("https://www.google.com/search?q=test".to_string())
        ))
    );

    assert!(UrlModRule::new(
        UrlModType::R302,
        r"https://www.google.com/(.*\?)((.*)&)?(source=[^&]+)(.*)",
        Some("https://www.google.com/$1$3$6"),
    )
    .is_none());
    assert!(UrlModRule::new(
        UrlModType::R404,
        r"https://www.google.com/(.*\?)((.*)&)?(source=[^&]+)(.*)",
        None,
    )
    .is_some());
}
