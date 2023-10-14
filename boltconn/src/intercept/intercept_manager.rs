use crate::config::{ActionConfig, InterceptionConfig};
use crate::dispatch::{ConnInfo, Dispatching, DispatchingBuilder, ProxyImpl, RuleSetTable};
use crate::external::MmdbReader;
use crate::intercept::{HeaderEngine, ScriptEngine, UrlEngine};
use crate::network::dns::Dns;
use std::sync::Arc;

#[derive(Debug)]
pub enum PayloadEntry {
    Url(UrlEngine),
    Header(HeaderEngine),
    Script(ScriptEngine),
}

#[derive(Debug)]
struct InterceptionPayload {
    pub payloads: Vec<Arc<PayloadEntry>>,
    pub capture_request: bool,
    pub capture_response: bool,
}

impl InterceptionPayload {
    fn parse_actions(actions: &[ActionConfig]) -> anyhow::Result<Self> {
        let mut capture_request = false;
        let mut capture_response = false;
        let mut payloads = vec![];
        for s in actions.iter() {
            match s {
                ActionConfig::Standard(s) => {
                    if s.starts_with("url,") {
                        payloads.push(Arc::new(PayloadEntry::Url(
                            UrlEngine::from_line(s).ok_or_else(|| {
                                anyhow::anyhow!("Parse invalid url modifier rules: {}", s)
                            })?,
                        )));
                    } else if s.starts_with("header-req,") || s.starts_with("header-resp,") {
                        payloads.push(Arc::new(PayloadEntry::Header(
                            HeaderEngine::from_line(s).ok_or_else(|| {
                                anyhow::anyhow!("Parse invalid header modifier rules: {}", s)
                            })?,
                        )));
                    } else if s == "capture" {
                        capture_request = true;
                        capture_response = true;
                    } else if s == "capture-request" {
                        capture_request = true;
                    } else if s == "capture-response" {
                        capture_response = true;
                    } else {
                        return Err(anyhow::anyhow!("Unexpected: {}", s));
                    }
                }
                ActionConfig::Script(cfg) => {
                    payloads.push(Arc::new(PayloadEntry::Script(ScriptEngine::new(
                        cfg.name.as_deref(),
                        cfg.script_type.as_str(),
                        cfg.pattern.as_deref(),
                        &cfg.script,
                    )?)))
                }
            }
        }
        Ok(Self {
            payloads,
            capture_request,
            capture_response,
        })
    }
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
    pub payloads: Vec<Arc<PayloadEntry>>,
    pub capture_request: bool,
    pub capture_response: bool,
    pub contains_script: bool,
}

impl InterceptionResult {
    pub fn should_intercept(&self) -> bool {
        !self.payloads.is_empty() || self.capture_request || self.capture_response
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
        let mut capture_request = false;
        let mut capture_response = false;
        let mut contains_script = false;
        for i in self.entries.iter() {
            if let Some(payload) = i.matches(conn_info).await {
                capture_request |= payload.capture_request;
                capture_response |= payload.capture_response;
                contains_script |= payload
                    .payloads
                    .iter()
                    .any(|x| matches!(x.as_ref(), PayloadEntry::Script(_)));
                result.extend_from_slice(payload.payloads.as_slice());
            }
        }
        InterceptionResult {
            payloads: result,
            capture_request,
            capture_response,
            contains_script,
        }
    }
}
