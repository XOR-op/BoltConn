use crate::adapter;
use crate::common::duplex_chan::DuplexChan;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::error::TransportError;
use crate::proxy::NetworkAddr;
use crate::transport::ssh::{SshConfig, SshTunnel};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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

pub struct SshManager {
    iface: String,
    // We use an async wrapper to avoid deadlock in DashMap
    active_conn: tokio::sync::Mutex<HashMap<SshConfig, Arc<SshTunnel>>>,
    server_resolver: Arc<Dns>,
    timeout: Duration,
}

impl SshManager {
    pub fn new(iface: &str, dns: Arc<Dns>, timeout: Duration) -> Self {
        Self {
            iface: iface.to_string(),
            active_conn: Default::default(),
            server_resolver: dns,
            timeout,
        }
    }

    pub async fn get_ssh_conn(
        &self,
        config: &SshConfig,
        next_step: Option<DuplexChan>,
        ret_tx: tokio::sync::oneshot::Sender<bool>,
    ) -> Result<Arc<SshTunnel>, TransportError> {
        for _ in 0..10 {
            // get an existing conn, or create
            let mut guard = self.active_conn.lock().await;
            if let Some(endpoint) = guard.get(config) {
                if endpoint.is_active() {
                    let _ = ret_tx.send(false);
                    return Ok(endpoint.clone());
                } else {
                    guard.remove(config);
                    continue;
                }
            } else {
                let _ = ret_tx.send(true);
                let tunnel = Arc::new(match next_step {
                    Some(next_step) => SshTunnel::new(config, next_step).await?,
                    None => {
                        let server_addr =
                            adapter::get_dst(&self.server_resolver, &config.server).await?;
                        let stream = match server_addr {
                            SocketAddr::V4(_) => {
                                Egress::new(self.iface.as_str())
                                    .tcpv4_stream(server_addr)
                                    .await?
                            }
                            SocketAddr::V6(_) => {
                                Egress::new(self.iface.as_str())
                                    .tcpv6_stream(server_addr)
                                    .await?
                            }
                        };
                        SshTunnel::new(config, stream).await?
                    }
                });
                guard.insert(config.clone(), tunnel.clone());
                return Ok(tunnel);
            }
        }
        Err(TransportError::Ssh(russh::Error::ConnectionTimeout))
    }
}
