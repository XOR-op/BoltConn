use crate::adapter;
use crate::adapter::{
    empty_handle, established_tcp, AddrConnector, Connector, Outbound, OutboundType,
};
use crate::common::{io_err, StreamOutboundTrait};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::ssh::{SshConfig, SshTunnel};
use crate::transport::UdpSocketAdapter;
use async_trait::async_trait;
use futures::TryFutureExt;
use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct SshOutboundHandle {
    iface_name: String,
    dst: NetworkAddr,
    dns: Arc<Dns>,
    config: SshConfig,
    manager: Arc<SshManager>,
}

impl SshOutboundHandle {
    pub fn new(
        iface_name: &str,
        dst: NetworkAddr,
        dns: Arc<Dns>,
        config: SshConfig,
        manager: Arc<SshManager>,
    ) -> Self {
        Self {
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
        let master_conn = self
            .manager
            .get_ssh_conn(&self.config, outbound, completion_tx)
            .await?;
        let channel = master_conn.new_mapped_connection(self.dst.clone()).await?;
        established_tcp(inbound, channel, abort_handle).await;
        Ok(())
    }
}

#[async_trait]
impl Outbound for SshOutboundHandle {
    fn outbound_type(&self) -> OutboundType {
        OutboundType::Ssh
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<std::io::Result<()>> {
        let (tx, _) = tokio::sync::oneshot::channel();
        tokio::spawn(adapter::connect_timeout(
            self.clone()
                .attach_tcp(inbound, None, abort_handle, tx)
                .map_err(|e| io_err(format!("SSH TCP spawn error: {:?}", e).as_str())),
            "SSH TCP",
        ))
    }

    async fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> std::io::Result<bool> {
        if tcp_outbound.is_none() || udp_outbound.is_some() {
            tracing::error!("Invalid SSH proxy tcp spawn");
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (comp_tx, comp_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(adapter::connect_timeout(
            self.clone()
                .attach_tcp(inbound, None, abort_handle, comp_tx)
                .map_err(|e| io_err(format!("SSH TCP spawn error: {:?}", e).as_str())),
            "SSH TCP multi-hop",
        ));
        comp_rx
            .await
            .map_err(|_| ErrorKind::ConnectionAborted.into())
    }

    fn spawn_udp(
        &self,
        _inbound: AddrConnector,
        _abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> JoinHandle<std::io::Result<()>> {
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
    ) -> std::io::Result<bool> {
        tracing::error!("spawn_udp() should not be called with SshOutbound");
        Err(io::ErrorKind::InvalidData.into())
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
