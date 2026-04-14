use std::sync::Arc;
use std::time::Duration;

use boltapi::instrument::RequestPayload;

use crate::dispatch::{ConnInfo, InboundInfo, ProxyImpl, RuleImpl};
use crate::instrument::action::collect_all_parents;
use crate::instrument::bus::{BusMessage, BusPublisher, MessageBus, SubId};
use crate::platform::process::NetworkType;

#[derive(Clone, Copy, Debug)]
pub enum RouteDecision {
    Continue,
    Reject,
    BlackHole,
}

impl RouteDecision {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "CONTINUE" => Some(Self::Continue),
            "REJECT" => Some(Self::Reject),
            "BLACKHOLE" => Some(Self::BlackHole),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Continue => "CONTINUE",
            Self::Reject => "REJECT",
            Self::BlackHole => "BLACKHOLE",
        }
    }
}

pub struct RequestAction {
    rule: RuleImpl,
    sub_id: SubId,
    timeout: Duration,
    request_route: RouteDecision,
    fallback: RouteDecision,
    bus: Arc<MessageBus>,
    bus_publisher: BusPublisher,
}

impl RequestAction {
    pub fn new(
        rule: RuleImpl,
        sub_id: SubId,
        timeout: Duration,
        request_route: RouteDecision,
        fallback: RouteDecision,
        bus: Arc<MessageBus>,
        bus_publisher: BusPublisher,
    ) -> Self {
        Self {
            rule,
            sub_id,
            timeout,
            request_route,
            fallback,
            bus,
            bus_publisher,
        }
    }

    pub async fn execute(
        &self,
        info: &ConnInfo,
        verbose: bool,
    ) -> Option<(String, Arc<ProxyImpl>, Option<String>)> {
        if !self.rule.matches(info) {
            return None;
        }
        let request_id = self.bus.alloc_request_id();
        let Some(rx) = self.bus.register_pending_response(self.sub_id, request_id) else {
            return self.apply(self.fallback, info, false, verbose);
        };

        let payload = build_request_payload(
            self.sub_id,
            request_id,
            self.request_route,
            self.timeout,
            info,
        );
        self.bus_publisher.publish(BusMessage::new(
            self.sub_id,
            serde_json::to_string(&payload).expect("infallible"),
        ));

        let (decision, active_decision) = match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(route_str)) => resolve_route_choice(Some(route_str.as_str()), self.fallback),
            _ => resolve_route_choice(None, self.fallback),
        };
        // Best-effort completion cleanup. Disconnect cleanup may have removed it already.
        self.bus.remove_pending_response(request_id);
        self.apply(decision, info, active_decision, verbose)
    }

    fn apply(
        &self,
        decision: RouteDecision,
        info: &ConnInfo,
        active_decision: bool,
        verbose: bool,
    ) -> Option<(String, Arc<ProxyImpl>, Option<String>)> {
        let (reject_proxy, what) = match decision {
            RouteDecision::Continue => return None,
            RouteDecision::Reject => (Arc::new(ProxyImpl::Reject), "REJECT"),
            RouteDecision::BlackHole => (Arc::new(ProxyImpl::BlackHole), "BLACKHOLE"),
        };
        let rule_str = format!(
            "REQUEST({},{})",
            self.sub_id,
            if active_decision { "USER" } else { "DEFAULT" }
        );
        if verbose {
            tracing::info!(
                "[{}]({},{}) {}{} => {}",
                rule_str,
                crate::dispatch::stringfy_process(info),
                info.inbound,
                info.dst,
                if info.connection_type == NetworkType::Udp {
                    "(UDP)"
                } else {
                    ""
                },
                what,
            );
        }
        Some((rule_str, reject_proxy, None))
    }
}

fn build_request_payload(
    sub_id: SubId,
    request_id: u64,
    request_route: RouteDecision,
    timeout: Duration,
    info: &ConnInfo,
) -> RequestPayload {
    let now = chrono::Local::now();

    RequestPayload {
        sub_id,
        request_id,
        suggested_route: request_route.as_str().to_string(),
        timeout: timeout.as_secs(),
        addr_src: info.src.to_string(),
        addr_dst: info.dst.to_string(),
        addr_resolved_dst: info.resolved_dst.map(|a| a.to_string()),
        ip_local: info.local_ip.map(|ip| ip.to_string()),
        inbound_type: match &info.inbound {
            InboundInfo::Tun => "tun",
            InboundInfo::Http(_) => "http",
            InboundInfo::Socks5(_) => "socks5",
        }
        .to_string(),
        inbound_port: match &info.inbound {
            InboundInfo::Tun => None,
            InboundInfo::Http(u) | InboundInfo::Socks5(u) => u.port,
        },
        inbound_user: match &info.inbound {
            InboundInfo::Tun => None,
            InboundInfo::Http(u) | InboundInfo::Socks5(u) => u.user.clone(),
        },
        conn_type: info.connection_type.to_string(),
        process_name: info.process_info.as_ref().map(|p| p.name.clone()),
        process_cmdline: info.process_info.as_ref().map(|p| p.cmdline.clone()),
        process_path: info.process_info.as_ref().map(|p| p.path.clone()),
        process_cwd: info.process_info.as_ref().map(|p| p.cwd.clone()),
        process_pid: info.process_info.as_ref().map(|p| p.pid),
        process_tag: info.process_info.as_ref().and_then(|p| p.tag.clone()),
        process_parent_all: collect_all_parents(info.process_info.as_ref()),
        time_hms_ms: now.format("%H:%M:%S%.3f").to_string(),
    }
}

fn resolve_route_choice(route_str: Option<&str>, fallback: RouteDecision) -> (RouteDecision, bool) {
    match route_str {
        Some("FALLBACK") => (fallback, true),
        Some(route) => match RouteDecision::from_str(route) {
            Some(decision) => (decision, true),
            None => (fallback, false),
        },
        None => (fallback, false),
    }
}

#[cfg(test)]
mod tests {
    use super::{RouteDecision, resolve_route_choice};

    #[test]
    fn test_resolve_route_choice_accepts_fallback_response() {
        let (decision, active) = resolve_route_choice(Some("FALLBACK"), RouteDecision::BlackHole);
        assert!(active);
        assert!(matches!(decision, RouteDecision::BlackHole));
    }

    #[test]
    fn test_resolve_route_choice_keeps_invalid_route_on_default_fallback() {
        let (decision, active) = resolve_route_choice(Some("NOPE"), RouteDecision::Reject);
        assert!(!active);
        assert!(matches!(decision, RouteDecision::Reject));
    }
}
