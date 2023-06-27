use crate::dispatch::ConnInfo;
use crate::network::dns::Dns;
use crate::proxy::NetworkAddr;
use std::net::SocketAddr;
use std::sync::Arc;

pub enum Action {
    LocalResolve(LocalResolve),
}

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
