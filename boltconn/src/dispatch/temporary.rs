use crate::dispatch::action::Action;
use crate::dispatch::rule::RuleOrAction;
use crate::dispatch::{ConnInfo, DispatchingSnippet, ProxyImpl};
use std::sync::Arc;

pub struct TemporaryList {
    list: Vec<RuleOrAction>,
}

impl TemporaryList {
    pub fn empty() -> Self {
        Self { list: vec![] }
    }

    pub fn new(list: Vec<RuleOrAction>) -> Self {
        Self { list }
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
