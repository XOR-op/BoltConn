use crate::network::dns::provider::IfaceProvider;
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::AsyncResolver;
use std::net::{IpAddr, Ipv4Addr};

pub struct BootstrapResolver {
    resolver: Option<AsyncResolver<GenericConnector<IfaceProvider>>>,
}

impl BootstrapResolver {
    pub fn new(resolver: AsyncResolver<GenericConnector<IfaceProvider>>) -> Self {
        Self {
            resolver: Some(resolver),
        }
    }

    /// Used only for configuration validation; no network activity is performed.
    pub(crate) fn mocked() -> Self {
        tracing::warn!("Using mocked resolver for bootstrap resolver");
        Self { resolver: None }
    }

    pub async fn lookup_ip(
        &self,
        domain: &str,
    ) -> Result<Vec<IpAddr>, hickory_resolver::error::ResolveError> {
        if let Some(resolver) = &self.resolver {
            Ok(resolver.lookup_ip(domain).await?.iter().collect())
        } else {
            Ok(vec![Ipv4Addr::new(127, 0, 0, 1).into()])
        }
    }
}
