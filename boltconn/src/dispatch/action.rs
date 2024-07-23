use crate::dispatch::instrument::Instrument;
use crate::dispatch::rule::RuleImpl;
use crate::dispatch::{ConnInfo, DispatchingSnippet, ProxyImpl};
use crate::network::dns::Dns;
use crate::proxy::NetworkAddr;
use async_recursion::async_recursion;
use std::net::SocketAddr;
use std::sync::Arc;

pub enum Action {
    LocalResolve(LocalResolve),
    SubDispatch(SubDispatch),
    Instrument(Instrument),
}

//----------------------------------------------------------------------
pub struct LocalResolve {
    dns: Arc<Dns>,
}

impl LocalResolve {
    pub fn new(dns: Arc<Dns>) -> Self {
        Self { dns }
    }

    pub async fn resolve_to(&self, info: &mut ConnInfo) {
        if info.resolved_dst.is_none() {
            if let NetworkAddr::DomainName { domain_name, port } = &info.dst {
                if let Some(addr) = self.dns.genuine_lookup(domain_name).await {
                    info.resolved_dst = Some(SocketAddr::new(addr, *port));
                }
            }
        }
    }
}

//----------------------------------------------------------------------
pub struct SubDispatch {
    rule: RuleImpl,
    snippet: DispatchingSnippet,
}

impl SubDispatch {
    pub fn new(rule: RuleImpl, snippet: DispatchingSnippet) -> Self {
        Self { rule, snippet }
    }

    #[async_recursion]
    pub async fn matches(
        &self,
        info: &mut ConnInfo,
        verbose: bool,
    ) -> Option<(String, Arc<ProxyImpl>, Option<String>)> {
        if self.rule.matches(info) {
            Some(self.snippet.matches(info, verbose).await)
        } else {
            None
        }
    }
}
