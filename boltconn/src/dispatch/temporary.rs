use crate::dispatch::action::Action;
use crate::dispatch::rule::RuleOrAction;
use crate::dispatch::{ConnInfo, DispatchMatch, DispatchingSnippet};

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
        conn: Option<&crate::proxy::ConnHandle>,
    ) -> Option<DispatchMatch> {
        for v in &self.list {
            match v {
                RuleOrAction::Rule(v) => {
                    if let Some(proxy) = v.matches(info) {
                        return Some(DispatchingSnippet::proxy_filtering(
                            &proxy,
                            info,
                            v.provenance(),
                            verbose,
                        ));
                    }
                }
                RuleOrAction::Action(a) => match a {
                    Action::LocalResolve(r) => r.resolve_to(info, conn).await,
                    Action::SubDispatch(sub) => {
                        if let Some(r) = sub.matches(info, verbose, conn).await {
                            return Some(r);
                        }
                    }
                    Action::Instrument(r) => r.execute(info).await,
                    Action::Request(r) => {
                        if let Some(result) = r.execute(info, verbose).await {
                            return Some(result);
                        }
                    }
                },
            }
        }
        None
    }
}
