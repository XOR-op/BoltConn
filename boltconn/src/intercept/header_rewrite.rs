use crate::intercept::Replacement;
use http::header::HeaderName;
use http::{HeaderMap, HeaderValue};
use regex::{Regex, RegexSet};
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
enum HeaderOperand {
    Add(HeaderName, HeaderValue),
    Del(HeaderName),
    Set(HeaderName, HeaderValue),
    Replace(HeaderName, HeaderValue),
    // regex
    ReplaceWith(HeaderName, Replacement),
}

#[derive(Clone, Debug)]
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

    pub fn new_set(key: &str, value: &str) -> Option<Self> {
        match (key.parse().ok(), HeaderValue::from_str(value).ok()) {
            (Some(k), Some(v)) => Some(Self(HeaderOperand::Set(k, v))),
            _ => None,
        }
    }

    pub fn new_replace(key: &str, value: &str) -> Option<Self> {
        match (key.parse().ok(), HeaderValue::from_str(value).ok()) {
            (Some(k), Some(v)) => Some(Self(HeaderOperand::Replace(k, v))),
            _ => None,
        }
    }

    pub fn new_replace_with(key: &str, pattern: &str, target: &str) -> Option<Self> {
        match (key.parse().ok(), Regex::new(pattern).ok()) {
            (Some(k), Some(patt)) => {
                Replacement::new(patt, target).map(|r| Self(HeaderOperand::ReplaceWith(k, r)))
            }
            _ => None,
        }
    }

    pub fn rewrite_request(&self, header: &mut HeaderMap) -> bool {
        match &self.0 {
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
pub struct HeaderRewrite {
    pattern: Regex,
    rule: HeaderRule,
}

impl HeaderRewrite {
    pub fn try_rewrite(&self, url: &str, headers: &mut HeaderMap) -> bool {
        if self.pattern.is_match(url) {
            self.rule.rewrite_request(headers)
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct HeaderModManager {
    req_rules: Vec<HeaderRule>,
    resp_rules: Vec<HeaderRule>,
    req_regex_set: RegexSet,
    resp_regex_set: RegexSet,
}

impl HeaderModManager {
    pub fn new(cfg: &[String]) -> anyhow::Result<Self> {
        let (req_rules, resp_rules, req_regexes, resp_regexes) =
            parse_header_actions(cfg).map_err(|s| anyhow::anyhow!(s))?;
        debug_assert_eq!(req_rules.len(), req_regexes.len());
        debug_assert_eq!(resp_rules.len(), resp_regexes.len());
        Ok(Self {
            req_rules,
            resp_rules,
            req_regex_set: RegexSet::new(req_regexes)?,
            resp_regex_set: RegexSet::new(resp_regexes)?,
        })
    }

    pub fn empty() -> Self {
        Self {
            req_rules: vec![],
            resp_rules: vec![],
            req_regex_set: RegexSet::empty(),
            resp_regex_set: RegexSet::empty(),
        }
    }

    pub async fn try_rewrite_request(&self, url: &str, headers: &mut HeaderMap) -> bool {
        let matches = self.req_regex_set.matches(url);
        if matches.matched_any() {
            let mut result = false;
            for i in matches.iter() {
                result |= self.req_rules.get(i).unwrap().rewrite_request(headers);
            }
            result
        } else {
            false
        }
    }

    pub async fn try_rewrite_response(&self, url: &str, headers: &mut HeaderMap) -> bool {
        let matches = self.resp_regex_set.matches(url);
        if matches.matched_any() {
            let mut result = false;
            for i in matches.iter() {
                result |= self.resp_rules.get(i).unwrap().rewrite_request(headers);
            }
            result
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

#[allow(clippy::type_complexity)]
fn parse_header_actions(
    cfg: &[String],
) -> Result<(Vec<HeaderRule>, Vec<HeaderRule>, Vec<String>, Vec<String>), String> {
    let mut req_coll = vec![];
    let mut resp_coll = vec![];
    let mut req_str_coll = vec![];
    let mut resp_str_coll = vec![];
    for line in cfg {
        // <header>, <Rewrite_type>, <original_url>, <modified_url>
        // Example: header-req, ^https://twitter.com(.*), set, User-Agent, curl 1.1
        let processed_str: String = line.chars().filter(|c| *c != ' ').collect();
        let list: Vec<&str> = processed_str.split(',').collect();
        if list.len() < 3 {
            return Err(line.clone());
        }
        // determine where to add rule
        #[allow(clippy::get_first)]
        let (coll, str_coll) = match *list.get(0).unwrap() {
            "header-req" => (&mut req_coll, &mut req_str_coll),
            "header-resp" => (&mut resp_coll, &mut resp_str_coll),
            _ => return Err(line.clone()),
        };

        let rule = match *list.get(2).unwrap() {
            "add" => {
                let Some(v) = deserialize_values::<[String; 2]>(line.as_str()) else {
                    return Err(line.clone());
                };
                let Some(rule) = HeaderRule::new_add(v[0].as_str(), v[1].as_str()) else {
                    return Err(line.clone());
                };
                rule
            }
            "del" => {
                let Some(v) = deserialize_values::<[String; 1]>(line.as_str()) else {
                    return Err(line.clone());
                };
                let Some(rule) = HeaderRule::new_del(v[0].as_str()) else {
                    return Err(line.clone());
                };
                rule
            }
            "set" => {
                let Some(v) = deserialize_values::<[String; 2]>(line.as_str()) else {
                    return Err(line.clone());
                };
                let Some(rule) = HeaderRule::new_set(v[0].as_str(), v[1].as_str()) else {
                    return Err(line.clone());
                };
                rule
            }
            "replace" => {
                let Some(v) = deserialize_values::<[String; 2]>(line.as_str()) else {
                    return Err(line.clone());
                };
                let Some(rule) = HeaderRule::new_replace(v[0].as_str(), v[1].as_str()) else {
                    return Err(line.clone());
                };
                rule
            }
            "replace-with" => {
                let Some(v) = deserialize_values::<[String; 3]>(line.as_str()) else {
                    return Err(line.clone());
                };
                let Some(rule) =
                    HeaderRule::new_replace_with(v[0].as_str(), v[1].as_str(), v[2].as_str())
                else {
                    return Err(line.clone());
                };
                rule
            }
            _ => {
                return Err(line.clone());
            }
        };
        coll.push(rule);
        str_coll.push(list.get(1).unwrap().to_string());
    }
    Ok((req_coll, resp_coll, req_str_coll, resp_str_coll))
}
