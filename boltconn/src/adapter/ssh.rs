use crate::adapter;
use crate::adapter::{
    AddrConnector, Connector, Outbound, OutboundType, empty_handle, established_tcp,
};
use crate::common::{StreamOutboundTrait, io_err};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::UdpSocketAdapter;
use crate::transport::ssh::{SshConfig, SshTunnel};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct SshOutboundHandle {
    name: String,
    iface_name: String,
    dst: NetworkAddr,
    dns: Arc<Dns>,
    config: SshConfig,
    manager: Arc<SshManager>,
}

impl SshOutboundHandle {
    pub fn new(
        name: &str,
        iface_name: &str,
        dst: NetworkAddr,
        dns: Arc<Dns>,
        config: SshConfig,
        manager: Arc<SshManager>,
    ) -> Self {
        Self {
            name: name.to_string(),
            iface_name: iface_name.to_string(),
            dst,
            dns,
            config,
            manager,
        }
    }

    async fn attach_tcp(
        self,
        inbound: Connector,
        outbound: Option<Box<dyn StreamOutboundTrait>>,
        abort_handle: ConnAbortHandle,
        completion_tx: tokio::sync::oneshot::Sender<bool>,
    ) -> Result<(), TransportError> {
        let master_conn = match tokio::time::timeout(
            Duration::from_secs(10),
            self.manager
                .get_ssh_conn(&self.config, outbound, completion_tx),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                tracing::trace!(
                    "Failed to establish SSH proxy connection to {}: {:?}",
                    self.config.server,
                    e
                );
                return Err(e);
            }
            Err(_) => {
                tracing::trace!(
                    "Failed to establish SSH proxy connection to {}: timeout",
                    self.config.server
                );
                return Err(TransportError::Ssh(russh::Error::ConnectionTimeout));
            }
        };
        let channel = master_conn.new_mapped_connection(self.dst.clone()).await?;
        established_tcp(self.name, inbound, channel, abort_handle).await;
        Ok(())
    }
}

#[async_trait]
impl Outbound for SshOutboundHandle {
    fn id(&self) -> String {
        self.name.clone()
    }

    fn outbound_type(&self) -> OutboundType {
        OutboundType::Ssh
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<Result<(), TransportError>> {
        let (tx, _) = tokio::sync::oneshot::channel();
        let self_clone = self.clone();
        tokio::spawn(async move {
            let abort_handle2 = abort_handle.clone();
            let r = self_clone.attach_tcp(inbound, None, abort_handle, tx).await;
            if let Err(e) = r {
                abort_handle2.cancel();
                return Err(e);
            }
            Ok(())
        })
    }

    async fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> Result<bool, TransportError> {
        if tcp_outbound.is_none() || udp_outbound.is_some() {
            tracing::error!("Invalid SSH proxy tcp spawn");
            return Err(TransportError::Internal("Invalid outbound"));
        }
        let (comp_tx, comp_rx) = tokio::sync::oneshot::channel();
        let self_clone = self.clone();
        tokio::spawn(async move {
            let abort_handle2 = abort_handle.clone();
            let r = self_clone
                .attach_tcp(inbound, tcp_outbound, abort_handle, comp_tx)
                .await;
            if let Err(e) = r {
                abort_handle2.cancel();
                return Err(io_err(format!("SSH TCP spawn error: {:?}", e).as_str()));
            }
            Ok(())
        });
        comp_rx
            .await
            .map_err(|_| TransportError::ShadowSocks("Aborted"))
    }

    fn spawn_udp(
        &self,
        _inbound: AddrConnector,
        _abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> JoinHandle<Result<(), TransportError>> {
        tracing::error!("spawn_udp() should not be called with SshOutbound");
        empty_handle()
    }

    async fn spawn_udp_with_outbound(
        &self,
        _inbound: AddrConnector,
        _tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        _udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        _abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> Result<bool, TransportError> {
        tracing::error!("spawn_udp() should not be called with SshOutbound");
        Err(TransportError::Internal("Invalid outbound"))
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
        next_step: Option<Box<dyn StreamOutboundTrait>>,
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
                        let stream = Egress::new(&self.iface).tcp_stream(server_addr).await?;
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
