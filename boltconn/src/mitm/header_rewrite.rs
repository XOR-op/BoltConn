use crate::mitm::Replacement;
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue};
use regex::Regex;

#[derive(Copy, Clone, Debug)]
pub enum HeaderModType {
    Add,
    Del,
    Set,
    // regex
    Replace,
}

enum HeaderOperand {
    Add(HeaderName, HeaderValue),
    Del(HeaderName),
    Set(HeaderName, HeaderValue),
    // regex
    Replace(HeaderName, Replacement),
}

pub struct HeaderRule(HeaderOperand);

impl HeaderRule {
    pub fn new_add(key: &str, value: &str) -> Option<Self> {
        match (key.parse().ok(), HeaderValue::from_str(value).ok()) {
            (Some(k), Some(v)) => Some(Self(HeaderOperand::Add(k, v))),
            _ => None,
        }
    }

    pub fn new_del(key: &str) -> Option<Self> {
        key.parse().ok().map(|k| Self(HeaderOperand::Del(k)))
    }

    pub fn new_replace(key: &str, value: &str) -> Option<Self> {
        match (key.parse().ok(), HeaderValue::from_str(value).ok()) {
            (Some(k), Some(v)) => Some(Self(HeaderOperand::Set(k, v))),
            _ => None,
        }
    }

    pub fn new_replace_regex(key: &str, pattern: &str, target: &str) -> Option<Self> {
        match (key.parse().ok(), Regex::new(pattern).ok()) {
            (Some(k), Some(patt)) => {
                Replacement::new(patt, target).map(|r| Self(HeaderOperand::Replace(k, r)))
            }
            _ => None,
        }
    }

    pub fn rewrite_request(&self, header: &mut HeaderMap) -> bool {
        match &self.0 {
            HeaderOperand::Add(k, v) => header.append(k, v.clone()),
            HeaderOperand::Del(k) => header.remove(k).is_some(),
            HeaderOperand::Set(k, v) => {
                if header.contains_key(k) {
                    header.insert(k, v.clone());
                    true
                } else {
                    false
                }
            }
            HeaderOperand::Replace(k, r) => {
                if header.contains_key(k) {
                    let backup = header
                        .get_all(k)
                        .iter()
                        .cloned()
                        .collect::<Vec<HeaderValue>>();
                    header.remove(k);
                    let mut ret = false;
                    for i in backup {
                        let new_value = (|| {
                            if let Ok(s) = i.to_str() {
                                if let Some(new_v) = r.rewrite(s) {
                                    if let Ok(hv) = new_v.parse::<HeaderValue>() {
                                        ret = true;
                                        return Some(hv);
                                    }
                                }
                            }
                            None
                        })()
                        .unwrap_or(i);
                        header.append(k, new_value);
                    }
                    ret
                } else {
                    false
                }
            }
        }
    }
}
