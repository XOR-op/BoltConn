use crate::adapter::{OutboundType, Socks5Config};
use crate::platform::process::{NetworkType, ProcessInfo};
use crate::session::NetworkAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use crate::dispatch::GeneralProxy;
use crate::dispatch::proxy::ProxyImpl;
use crate::dispatch::rule::Rule;

pub struct ConnInfo {
    pub src: SocketAddr,
    pub dst: NetworkAddr,
    pub connection_type: NetworkType,
    pub process_info: Option<ProcessInfo>,
}

pub struct Dispatching {
    socks5: Vec<Arc<Socks5Config>>,
    rules: Vec<Rule>,
    fallback: Option<GeneralProxy>,
}

impl Dispatching {
    pub fn matches(&self, info: &ConnInfo) -> ProxyImpl {
        for v in &self.rules {
            if let Some(proxy) = v.matches(&info) {
                return match proxy {
                    GeneralProxy::Single(p) => p.get_impl(),
                    GeneralProxy::Group(g) => g.get_selection().get_impl()
                };
            }
        }
        match &self.fallback {
            GeneralProxy::Single(p) => p.get_impl(),
            GeneralProxy::Group(g) => g.get_selection().get_impl()
        }
    }
}
