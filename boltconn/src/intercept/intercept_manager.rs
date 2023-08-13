use crate::dispatch::{ConnInfo, Dispatching, ProxyImpl};
use crate::intercept::{HeaderRewrite, UrlModRule};

#[derive(Debug)]
pub enum InterceptAction {
    Url(UrlModRule),
    Header(HeaderRewrite),
    Capture,
}

#[derive(Debug, Default)]
pub struct InterceptionPayload {
    pub req_actions: Vec<InterceptAction>,
    pub resp_actions: Vec<InterceptAction>,
    pub capture: bool,
}

struct InterceptionEntry {
    filters: Dispatching,
    payload: InterceptionPayload,
}

impl InterceptionEntry {
    async fn matches(&self, conn_info: &mut ConnInfo) -> Option<&InterceptionPayload> {
        match self.filters.matches(conn_info, false).await.0.as_ref() {
            ProxyImpl::Direct => Some(self.payload.as_ref()),
            _ => None,
        }
    }
}

pub struct InterceptionManager {
    entries: Vec<InterceptionEntry>,
}

impl InterceptionManager {
    pub async fn matches(&self, conn_info: &mut ConnInfo) -> Option<InterceptionPayload> {
        let mut result = None;
        for i in self.entries.iter() {
            if let Some(payload) = i.matches(conn_info).await {
                if result == None {
                    result = Some(InterceptionPayload::default());
                }
                let inner = &mut result.unwrap();
                inner.req_actions.extend(payload.req_actions.iter());
                inner.resp_actions.extend(payload.resp_actions.iter());
                inner.capture |= payload.capture;
            }
        }
        result
    }
}
