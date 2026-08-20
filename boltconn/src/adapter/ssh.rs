use crate::adapter;
use crate::adapter::{
    AddrConnector, Connector, InitializationDecision, LinkInitializationTable, LinkRuntimeConfig,
    LinkTable, ManagedRuntime, Outbound, OutboundType, empty_handle, established_tcp,
};
use crate::common::{StreamOutboundTrait, io_err};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, ConnHandle, NetworkAddr};
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
    config: LinkRuntimeConfig<SshConfig>,
    manager: Arc<SshManager>,
}

impl SshOutboundHandle {
    pub fn new(
        name: &str,
        iface_name: &str,
        dst: NetworkAddr,
        dns: Arc<Dns>,
        config: LinkRuntimeConfig<SshConfig>,
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
        conn: Option<ConnHandle>,
    ) -> Result<(), TransportError> {
        let managed = match self
            .manager
            .get_ssh_conn(&self.name, &self.config, outbound, completion_tx)
            .await
        {
            Ok(conn) => conn,
            Err(e) => {
                tracing::trace!(
                    "Failed to establish SSH proxy connection to {}: {:?}",
                    self.config.config.server,
                    e
                );
                return Err(e);
            }
        };
        if let Some(conn) = &conn {
            conn.consider_link_path(managed.record.dependency_path());
        }
        let channel = managed
            .runtime
            .new_mapped_connection(self.dst.clone())
            .await?;
        established_tcp(self.name, inbound, channel, abort_handle, conn).await;
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
        conn: Option<ConnHandle>,
    ) -> JoinHandle<Result<(), TransportError>> {
        let (tx, _) = tokio::sync::oneshot::channel();
        let self_clone = self.clone();
        tokio::spawn(async move {
            let abort_handle2 = abort_handle.clone();
            let r = self_clone
                .attach_tcp(inbound, None, abort_handle, tx, conn)
                .await;
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
        conn: Option<ConnHandle>,
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
                .attach_tcp(inbound, tcp_outbound, abort_handle, comp_tx, conn)
                .await;
            if let Err(e) = r {
                abort_handle2.cancel();
                return Err(io_err(format!("SSH TCP spawn error: {:?}", e).as_str()));
            }
            Ok(())
        });
        comp_rx
            .await
            .map_err(|_| TransportError::Io(io_err("SSH aborted")))
    }

    fn spawn_udp(
        &self,
        _inbound: AddrConnector,
        _abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
        _conn: Option<ConnHandle>,
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
        _conn: Option<ConnHandle>,
    ) -> Result<bool, TransportError> {
        tracing::error!("spawn_udp() should not be called with SshOutbound");
        Err(TransportError::Internal("Invalid outbound"))
    }
}

pub struct SshManager {
    iface: String,
    active_conn: tokio::sync::Mutex<HashMap<String, ManagedRuntime<SshTunnel>>>,
    initializing_conn: LinkInitializationTable,
    server_resolver: Arc<Dns>,
    timeout: Duration,
    link_table: Arc<LinkTable>,
}

impl SshManager {
    pub fn new(iface: &str, dns: Arc<Dns>, timeout: Duration, link_table: Arc<LinkTable>) -> Self {
        Self {
            iface: iface.to_string(),
            active_conn: Default::default(),
            initializing_conn: Default::default(),
            server_resolver: dns,
            timeout,
            link_table,
        }
    }

    pub async fn get_ssh_conn(
        &self,
        name: &str,
        requested: &LinkRuntimeConfig<SshConfig>,
        next_step: Option<Box<dyn StreamOutboundTrait>>,
        ret_tx: tokio::sync::oneshot::Sender<bool>,
    ) -> Result<ManagedRuntime<SshTunnel>, TransportError> {
        let config = &requested.config;
        let mut lease = self
            .link_table
            .acquire(name, requested)
            .map_err(|_| TransportError::Internal("stale SSH link acquisition"))?;

        let active = self.active_conn.lock().await.get(name).cloned();
        if let Some(active) = active {
            if active.generation == lease.generation.number() && active.runtime.is_active() {
                let _ = ret_tx.send(false);
                return Ok(active);
            }
            self.remove_and_finalize_dead(name, active).await;
            // The failed runtime's generation is terminal now; create its
            // replacement under a fresh generation record.
            lease = self
                .link_table
                .acquire(name, requested)
                .map_err(|_| TransportError::Internal("stale SSH link acquisition"))?;
        }

        match self
            .initializing_conn
            .begin(name, lease.generation.number())
            .await
        {
            InitializationDecision::Wait(completed) => {
                let _ = ret_tx.send(false);
                LinkInitializationTable::wait(completed).await;
                if let Some(active) = self.active_conn.lock().await.get(name)
                    && active.generation == lease.generation.number()
                    && active.runtime.is_active()
                {
                    return Ok(active.clone());
                }
                Err(TransportError::Ssh(russh::Error::ConnectionTimeout))
            }
            InitializationDecision::Create => {
                let _ = ret_tx.send(true);
                let result = tokio::time::timeout(
                    self.timeout,
                    self.create_tunnel(name, config, next_step, &lease.generation),
                )
                .await
                .unwrap_or_else(|_| Err(TransportError::Ssh(russh::Error::ConnectionTimeout)));
                let tunnel = match result {
                    Ok(tunnel) => tunnel,
                    Err(error) => {
                        self.initializing_conn
                            .finish(name, lease.generation.number())
                            .await;
                        self.mark_creation_failure(name, lease.generation.number(), &error);
                        return Err(error);
                    }
                };

                if !self
                    .link_table
                    .is_current_generation(name, lease.generation.number())
                {
                    tunnel.close().await;
                    self.retain_tunnel_snapshot(&lease.generation, &tunnel);
                    self.initializing_conn
                        .finish(name, lease.generation.number())
                        .await;
                    return Err(TransportError::Internal(
                        "SSH generation changed during initialization",
                    ));
                }
                let managed = ManagedRuntime {
                    generation: lease.generation.number(),
                    record: lease.generation.clone(),
                    runtime: tunnel.clone(),
                };
                if self
                    .link_table
                    .publish_creation_route(
                        name,
                        lease.generation.number(),
                        &requested.creation_route,
                    )
                    .is_err()
                {
                    tunnel.close().await;
                    self.retain_tunnel_snapshot(&lease.generation, &tunnel);
                    self.initializing_conn
                        .finish(name, lease.generation.number())
                        .await;
                    self.link_table.mark_terminal(
                        name,
                        lease.generation.number(),
                        boltapi::LinkState::Failed,
                        boltapi::LinkHealth::Unhealthy,
                        boltapi::LinkReason {
                            code: boltapi::LinkReasonCode::DependencyFailed,
                            detail: Some("could not resolve SSH creation route".to_string()),
                        },
                        boltapi::ConnResultCode::LinkLost,
                    );
                    return Err(TransportError::Internal(
                        "SSH link creation route is unavailable",
                    ));
                }
                self.active_conn
                    .lock()
                    .await
                    .insert(name.to_string(), managed.clone());
                if !self
                    .link_table
                    .is_current_generation(name, lease.generation.number())
                {
                    self.stop_generation(name, lease.generation.number()).await;
                    return Err(TransportError::Internal(
                        "SSH generation changed during initialization",
                    ));
                }
                // Insert first, then release waiters for this generation.
                self.initializing_conn
                    .finish(name, lease.generation.number())
                    .await;
                Ok(managed)
            }
        }
    }

    async fn create_tunnel(
        &self,
        name: &str,
        config: &SshConfig,
        next_step: Option<Box<dyn StreamOutboundTrait>>,
        record: &Arc<crate::adapter::LinkGeneration>,
    ) -> Result<Arc<SshTunnel>, TransportError> {
        let (tunnel, endpoints) = match next_step {
            Some(next_step) => (SshTunnel::new(config, next_step).await?, Vec::new()),
            None => {
                let server_addr =
                    adapter::get_link_dst(&self.server_resolver, &config.server, name, record)
                        .await?;
                let stream = Egress::new(&self.iface).tcp_stream(server_addr).await?;
                (SshTunnel::new(config, stream).await?, vec![server_addr])
            }
        };
        let tunnel = Arc::new(tunnel);
        tunnel.start_probe();
        let (state, health, evidence) = tunnel.link_snapshot();
        record.set_live_snapshot(state, health, endpoints, evidence);
        Ok(tunnel)
    }

    pub(crate) async fn stop_generation(&self, name: &str, generation: u64) {
        self.initializing_conn.cancel(name, generation).await;
        let runtime = {
            let mut active = self.active_conn.lock().await;
            if active
                .get(name)
                .is_some_and(|runtime| runtime.generation == generation)
            {
                active.remove(name)
            } else {
                None
            }
        };
        if let Some(runtime) = runtime {
            runtime.runtime.close().await;
            self.retain_tunnel_snapshot(&runtime.record, &runtime.runtime);
        }
    }

    pub(crate) async fn refresh_evidence(&self) {
        let runtimes: Vec<_> = self
            .active_conn
            .lock()
            .await
            .iter()
            .map(|(name, runtime)| (name.clone(), runtime.clone()))
            .collect();
        for (name, runtime) in runtimes {
            let (state, health, evidence) = runtime.runtime.link_snapshot();
            if state == boltapi::LinkState::Failed {
                self.remove_and_finalize_dead(&name, runtime).await;
            } else {
                runtime.record.set_live_evidence(state, health, evidence);
            }
        }
    }

    async fn remove_and_finalize_dead(&self, name: &str, runtime: ManagedRuntime<SshTunnel>) {
        {
            let mut active = self.active_conn.lock().await;
            if active
                .get(name)
                .is_some_and(|current| current.generation == runtime.generation)
            {
                active.remove(name);
            }
        }
        runtime.runtime.close().await;
        self.retain_tunnel_snapshot(&runtime.record, &runtime.runtime);
        self.link_table.mark_terminal(
            name,
            runtime.generation,
            boltapi::LinkState::Failed,
            boltapi::LinkHealth::Unhealthy,
            boltapi::LinkReason {
                code: boltapi::LinkReasonCode::TaskStopped,
                detail: None,
            },
            boltapi::ConnResultCode::LinkLost,
        );
    }

    fn retain_tunnel_snapshot(
        &self,
        record: &Arc<crate::adapter::LinkGeneration>,
        tunnel: &SshTunnel,
    ) {
        let (_, health, evidence) = tunnel.link_snapshot();
        record.retain_final_evidence(health, evidence);
    }

    fn mark_creation_failure(&self, name: &str, generation: u64, error: &TransportError) {
        let code = match error {
            TransportError::Dns(_) => boltapi::LinkReasonCode::DnsFailed,
            TransportError::Ssh(russh::Error::NotAuthenticated) => {
                boltapi::LinkReasonCode::AuthenticationFailed
            }
            TransportError::Ssh(_) => boltapi::LinkReasonCode::ProtocolFailed,
            _ => boltapi::LinkReasonCode::ConnectFailed,
        };
        self.link_table.mark_terminal(
            name,
            generation,
            boltapi::LinkState::Failed,
            boltapi::LinkHealth::Unhealthy,
            boltapi::LinkReason {
                code,
                detail: Some(crate::proxy::bounded_error_detail(&error.to_string())),
            },
            boltapi::ConnResultCode::LinkLost,
        );
    }
}
