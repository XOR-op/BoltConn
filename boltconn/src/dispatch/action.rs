use crate::dispatch::RuleImpl;
use crate::dispatch::{ConnInfo, DispatchMatch, DispatchingSnippet};
use crate::instrument::action::InstrumentAction;
use crate::instrument::request_action::RequestAction;
use crate::network::dns::Dns;
use crate::proxy::NetworkAddr;
use async_recursion::async_recursion;
use std::net::SocketAddr;
use std::sync::Arc;

pub enum Action {
    LocalResolve(LocalResolve),
    SubDispatch(SubDispatch),
    Instrument(InstrumentAction),
    Request(RequestAction),
}

//----------------------------------------------------------------------
pub struct LocalResolve {
    dns: Arc<Dns>,
}

impl LocalResolve {
    pub fn new(dns: Arc<Dns>) -> Self {
        Self { dns }
    }

    pub async fn resolve_to(&self, info: &mut ConnInfo, conn: Option<&crate::proxy::ConnHandle>) {
        if info.resolved_dst.is_some() {
            return;
        }
        let NetworkAddr::Domain {
            name: domain_name,
            port,
        } = &info.dst
        else {
            return;
        };
        if let Some(conn) = conn {
            conn.set_state(boltapi::ConnState::Resolving);
            conn.set_resolution(boltapi::DestinationResolution::InProgress);
        }
        match self
            .dns
            .genuine_lookup_for(domain_name, boltapi::DnsLookupPurpose::Destination, conn)
            .await
        {
            Ok(Some(addr)) => {
                let address = SocketAddr::new(addr, *port);
                info.resolved_dst = Some(address);
                if let Some(conn) = conn {
                    conn.set_resolution(boltapi::DestinationResolution::Resolved { address });
                    conn.set_state(boltapi::ConnState::Routing);
                }
            }
            _ => {
                if let Some(conn) = conn {
                    // Local resolution is a routing aid; failure is evidence but
                    // does not terminate because later rules may still select a
                    // proxy that resolves the destination remotely.
                    conn.set_resolution(boltapi::DestinationResolution::Failed);
                    conn.set_state(boltapi::ConnState::Routing);
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
        conn: Option<&crate::proxy::ConnHandle>,
    ) -> Option<DispatchMatch> {
        if self.rule.matches(info) {
            Some(self.snippet.matches(info, verbose, conn).await)
        } else {
            None
        }
    }
}
