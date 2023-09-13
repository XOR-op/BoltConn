use crate::config::InterceptionConfig;
use crate::dispatch::{ConnInfo, Dispatching, DispatchingBuilder, ProxyImpl, RuleSetTable};
use crate::external::MmdbReader;
use crate::intercept::{HeaderModManager, UrlModManager};
use crate::network::dns::Dns;
use std::sync::Arc;

#[derive(Debug)]
struct InterceptionPayload {
    pub url_mgr: UrlModManager,
    pub header_mgr: HeaderModManager,
    pub capture: bool,
}

impl InterceptionPayload {
    fn parse_actions(actions: &[String]) -> anyhow::Result<Self> {
        let (url_list, header_list, capture) = mapping_rewrite(actions)?;
        let (url_mgr, header_mgr) = {
            (
                UrlModManager::new(url_list.as_slice()).map_err(|e| {
                    anyhow::anyhow!("Parse url modifier rules, invalid regexes: {}", e)
                })?,
                HeaderModManager::new(header_list.as_slice()).map_err(|e| {
                    anyhow::anyhow!("Parse header modifier rules, invalid regexes: {}", e)
                })?,
            )
        };
        Ok(Self {
            url_mgr,
            header_mgr,
            capture,
        })
    }
}

fn mapping_rewrite(list: &[String]) -> anyhow::Result<(Vec<String>, Vec<String>, bool)> {
    let mut url_list = vec![];
    let mut header_list = vec![];
    let mut capture = false;
    for s in list.iter() {
        if s.starts_with("url,") {
            url_list.push(s.clone());
        } else if s.starts_with("header-req,") || s.starts_with("header-resp,") {
            header_list.push(s.clone());
        } else if s == "capture" {
            capture = true;
        } else {
            return Err(anyhow::anyhow!("Unexpected: {}", s));
        }
    }
    Ok((url_list, header_list, capture))
}

struct InterceptionEntry {
    filters: Dispatching,
    payload: Arc<InterceptionPayload>,
}

impl InterceptionEntry {
    async fn matches(&self, conn_info: &mut ConnInfo) -> Option<Arc<InterceptionPayload>> {
        match self.filters.matches(conn_info, false).await.0.as_ref() {
            ProxyImpl::Direct => Some(self.payload.clone()),
            _ => None,
        }
    }
}

pub struct InterceptionResult {
    payloads: Vec<Arc<InterceptionPayload>>,
    will_capture: bool,
}

impl InterceptionResult {
    pub fn should_intercept(&self) -> bool {
        !self.payloads.is_empty() || self.will_capture
    }

    pub fn each_payload(&self) -> impl Iterator<Item = (&UrlModManager, &HeaderModManager)> {
        self.payloads.iter().map(|x| (&x.url_mgr, &x.header_mgr))
    }

    pub fn should_capture(&self) -> bool {
        self.will_capture
    }
}

pub struct InterceptionManager {
    entries: Vec<InterceptionEntry>,
}

impl InterceptionManager {
    pub fn new(
        entries: &[InterceptionConfig],
        dns: Arc<Dns>,
        mmdb: Option<Arc<MmdbReader>>,
        rulesets: &RuleSetTable,
    ) -> anyhow::Result<Self> {
        let mut res = vec![];
        for i in entries.iter() {
            let filters = DispatchingBuilder::empty(dns.clone(), mmdb.clone())
                .build_filter(i.filters.as_slice(), rulesets)?;
            let payload = InterceptionPayload::parse_actions(i.actions.as_slice())?;
            res.push(InterceptionEntry {
                filters,
                payload: Arc::new(payload),
            })
        }
        Ok(Self { entries: res })
    }

    pub async fn matches(&self, conn_info: &mut ConnInfo) -> InterceptionResult {
        let mut result = vec![];
        let mut capture = false;
        for i in self.entries.iter() {
            if let Some(payload) = i.matches(conn_info).await {
                capture |= payload.capture;
                result.push(payload);
            }
        }
        InterceptionResult {
            payloads: result,
            will_capture: capture,
        }
    }
}
