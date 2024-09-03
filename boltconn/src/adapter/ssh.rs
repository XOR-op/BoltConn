use crate::network::dns::Dns;
use crate::proxy::NetworkAddr;
use crate::transport::ssh::SshConfig;
use std::sync::Arc;

#[derive(Clone)]
pub struct SshOutboundHandle {
    iface_name: String,
    dst: NetworkAddr,
    dns: Arc<Dns>,
    config: Arc<SshConfig>,
}

impl SshOutboundHandle {
    pub fn new(iface_name: &str, dst: NetworkAddr, dns: Arc<Dns>, config: Arc<SshConfig>) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
            dns,
            config,
        }
    }
}
