use crate::intercept::Replacement;
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue};
use regex::Regex;
use serde::de::DeserializeOwned;

#[derive(Copy, Clone, Debug)]
enum HeaderModType {
    Add,
    Del,
    Set,
    Replace,
    // regex
    ReplaceWith,
}

#[derive(Clone, Debug)]
pub(super) enum HeaderOperand {
    Add(HeaderName, HeaderValue),
    Del(HeaderName),
    Set(HeaderName, HeaderValue),
    Replace(HeaderName, HeaderValue),
    // regex
    ReplaceWith(HeaderName, Replacement),
}

impl HeaderOperand {
    pub fn new_add(key: &str, value: &str) -> Option<Self> {
        match (key.parse().ok(), HeaderValue::from_str(value).ok()) {
            (Some(k), Some(v)) => Some(HeaderOperand::Add(k, v)),
            _ => None,
        }
    }

    pub fn new_del(key: &str) -> Option<Self> {
        key.parse().ok().map(HeaderOperand::Del)
    }

    pub fn new_set(key: &str, value: &str) -> Option<Self> {
        match (key.parse().ok(), HeaderValue::from_str(value).ok()) {
            (Some(k), Some(v)) => Some(HeaderOperand::Set(k, v)),
            _ => None,
        }
    }

    pub fn new_replace(key: &str, value: &str) -> Option<Self> {
        match (key.parse().ok(), HeaderValue::from_str(value).ok()) {
            (Some(k), Some(v)) => Some(HeaderOperand::Replace(k, v)),
            _ => None,
        }
    }

    pub fn new_replace_with(key: &str, pattern: &str, target: &str) -> Option<Self> {
        match (key.parse().ok(), Regex::new(pattern).ok()) {
            (Some(k), Some(patt)) => {
                Replacement::new(patt, target).map(|r| HeaderOperand::ReplaceWith(k, r))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum HeaderRule {
    Req(HeaderOperand),
    Resp(HeaderOperand),
}

impl HeaderRule {
    pub fn rewrite_request(&self, header: &mut HeaderMap) -> bool {
        match self {
            HeaderRule::Req(op) => Self::rewrite(op, header),
            HeaderRule::Resp(_) => false,
        }
    }

    pub fn rewrite_response(&self, header: &mut HeaderMap) -> bool {
        match self {
            HeaderRule::Resp(op) => Self::rewrite(op, header),
            HeaderRule::Req(_) => false,
        }
    }

    fn rewrite(op: &HeaderOperand, header: &mut HeaderMap) -> bool {
        match op {
            HeaderOperand::Add(k, v) => header.append(k, v.clone()),
            HeaderOperand::Del(k) => header.remove(k).is_some(),
            HeaderOperand::Set(k, v) => {
                header.insert(k, v.clone());
                true
            }
            HeaderOperand::Replace(k, v) => {
                if header.contains_key(k) {
                    header.insert(k, v.clone());
                    true
                } else {
                    false
                }
            }
            HeaderOperand::ReplaceWith(k, r) => {
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

#[derive(Debug)]
pub struct HeaderEngine {
    pattern: Regex,
    rule: HeaderRule,
}

impl HeaderEngine {
    pub fn from_line(line: &str) -> Option<Self> {
        // <header>, <Rewrite_type>, <original_url>, <modified_url>
        // Example: header-req, ^https://twitter.com(.*), set, User-Agent, curl 1.1
        let processed_str: String = line.chars().filter(|c| *c != ' ').collect();
        let list: Vec<&str> = processed_str.split(',').collect();
        if list.len() < 3 {
            return None;
        }
        // determine where to add rule
        #[allow(clippy::get_first)]
        let is_req = match *list.get(0).unwrap() {
            "header-req" => true,
            "header-resp" => false,
            _ => return None,
        };

        let operand = match *list.get(2).unwrap() {
            "add" => {
                let v = deserialize_values::<[String; 2]>(line)?;
                HeaderOperand::new_add(v[0].as_str(), v[1].as_str())?
            }
            "del" => {
                let v = deserialize_values::<[String; 1]>(line)?;
                HeaderOperand::new_del(v[0].as_str())?
            }
            "set" => {
                let v = deserialize_values::<[String; 2]>(line)?;
                HeaderOperand::new_set(v[0].as_str(), v[1].as_str())?
            }
            "replace" => {
                let v = deserialize_values::<[String; 2]>(line)?;
                HeaderOperand::new_replace(v[0].as_str(), v[1].as_str())?
            }
            "replace-with" => {
                let v = deserialize_values::<[String; 3]>(line)?;
                HeaderOperand::new_replace_with(v[0].as_str(), v[1].as_str(), v[2].as_str())?
            }
            _ => {
                return None;
            }
        };
        Some(Self {
            pattern: Regex::new(list.get(1).unwrap()).ok()?,
            rule: if is_req {
                HeaderRule::Req(operand)
            } else {
                HeaderRule::Resp(operand)
            },
        })
    }

    pub fn try_rewrite_request(&self, url: &str, headers: &mut HeaderMap) -> bool {
        if self.pattern.is_match(url) {
            self.rule.rewrite_request(headers)
        } else {
            false
        }
    }

    pub fn try_rewrite_response(&self, url: &str, headers: &mut HeaderMap) -> bool {
        if self.pattern.is_match(url) {
            self.rule.rewrite_response(headers)
        } else {
            false
        }
    }
}

fn split_at_nth(raw: &str, p: char, n: usize) -> Option<&str> {
    raw.match_indices(p)
        .nth(n)
        .map(|(idx, _)| raw.split_at(idx))
        .map(|(_, v)| v)
}

fn deserialize_values<T: DeserializeOwned>(raw: &str) -> Option<T> {
    let part = split_at_nth(raw, ',', 2)?;
    if part.len() == 1 {
        return None;
    }
    // construct yaml string
    let part = "[".to_string() + part.split_at(1).1 + "]";
    serde_yaml::from_str(part.as_str()).ok()
}
