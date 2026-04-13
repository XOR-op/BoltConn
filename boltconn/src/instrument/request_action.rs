use std::sync::Arc;
use std::time::Duration;

use boltapi::instrument::RequestPayload;
use serde_json::Value;

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
        if !self.bus.has_subscriber(self.sub_id) {
            return self.apply(self.fallback, info, false, verbose);
        }

        let request_id = self.bus.alloc_request_id();
        let rx = self.bus.register_pending_response(self.sub_id, request_id);

        let payload = build_request_payload(self.sub_id, request_id, self.request_route, info);
        self.bus_publisher.publish(BusMessage::new(
            self.sub_id,
            serde_json::to_string(&payload).expect("infallible"),
        ));

        let (decision, active_decision) = match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(route_str)) => match RouteDecision::from_str(&route_str) {
                Some(d) => (d, true),
                None => (self.fallback, false),
            },
            _ => (self.fallback, false),
        };
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
    info: &ConnInfo,
) -> RequestPayload {
    let now = chrono::Local::now();
    let parents = collect_all_parents(info.process_info.as_ref());
    let process_parent_all = serde_json::to_value(&parents).unwrap_or(Value::Array(vec![]));

    RequestPayload {
        sub_id,
        request_id,
        suggested_route: request_route.as_str().to_string(),
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
        process_pid: info.process_info.as_ref().map(|p| p.pid),
        process_tag: info.process_info.as_ref().and_then(|p| p.tag.clone()),
        process_parent_all,
        time_hms_ms: now.format("%H:%M:%S%.3f").to_string(),
    }
}
