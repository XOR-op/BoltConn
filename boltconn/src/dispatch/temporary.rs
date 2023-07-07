use crate::dispatch::action::Action;
use crate::dispatch::rule::RuleOrAction;
use crate::dispatch::ruleset::RuleSet;
use crate::dispatch::{ConnInfo, DispatchingSnippet, Proxy, ProxyGroup, ProxyImpl};
use crate::external::MmdbReader;
use crate::network::dns::Dns;
use std::collections::HashMap;
use std::sync::Arc;

pub struct TemporaryList {
    list: Vec<RuleOrAction>,
}

impl TemporaryList {
    pub fn empty() -> Self {
        Self { list: vec![] }
    }

    pub async fn matches(
        &self,
        info: &mut ConnInfo,
        verbose: bool,
    ) -> Option<(Arc<ProxyImpl>, Option<String>)> {
        for v in &self.list {
            match v {
                RuleOrAction::Rule(v) => {
                    if let Some(proxy) = v.matches(info) {
                        return Some(DispatchingSnippet::proxy_filtering(
                            &proxy,
                            info,
                            format!("TEMP@{}", v).as_str(),
                            verbose,
                        ));
                    }
                }
                RuleOrAction::Action(a) => match a {
                    Action::LocalResolve(r) => r.resolve_to(info).await,
                    Action::SubDispatch(sub) => {
                        if let Some(r) = sub.matches(info, verbose).await {
                            return Some(r);
                        }
                    }
                },
            }
        }
        None
    }
}

pub struct TemporaryListBuilder {
    proxies: HashMap<String, Arc<Proxy>>,
    groups: HashMap<String, Arc<ProxyGroup>>,
    rulesets: HashMap<String, Arc<RuleSet>>,
    dns: Arc<Dns>,
    mmdb: Option<Arc<MmdbReader>>,
}

impl TemporaryListBuilder {
    pub fn new(
        proxies: HashMap<String, Arc<Proxy>>,
        groups: HashMap<String, Arc<ProxyGroup>>,
        rulesets: HashMap<String, Arc<RuleSet>>,
        dns: Arc<Dns>,
        mmdb: Option<Arc<MmdbReader>>,
    ) -> Self {
        Self {
            proxies,
            groups,
            rulesets,
            dns,
            mmdb,
        }
    }
}
