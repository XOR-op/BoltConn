use crate::adapter::OutboundType;
use crate::platform::process::{NetworkType, ProcessInfo};
use crate::session::NetworkAddr;
use std::net::SocketAddr;
use crate::dispatch::configuration::ProxyImpl;

pub struct ConnInfo {
    pub src: SocketAddr,
    pub dst: NetworkAddr,
    pub connection_type: NetworkType,
    pub process_info: Option<ProcessInfo>,
}

pub struct Dispatching {}

impl Dispatching {
    pub fn matches(&self, info: ConnInfo) -> ProxyImpl {
        // todo
        ProxyImpl::Direct
    }
}
