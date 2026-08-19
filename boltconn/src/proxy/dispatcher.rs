use crate::adapter::{
    AddrConnector, AnytlsManager, AnytlsOutboundHandle, ChainOutbound, Connector, DirectOutbound,
    HttpOutbound, LinkInvalidation, LinkRuntimeConfig, LinkTable, NamedLinkConfig, Outbound,
    OutboundType, SSOutbound, Socks5Outbound, SocksUdpAdapter, SshManager, SshOutboundHandle,
    TcpAdapter, TrojanOutbound, TunUdpAdapter, WireguardHandle, WireguardManager,
};
use crate::common::StreamOutboundTrait;
use crate::common::duplex_chan::DuplexChan;
use crate::dispatch::{
    ConnInfo, DispatchMatch, Dispatching, GeneralProxy, InboundExtra, InboundInfo, ProxyImpl,
};
use crate::intercept::{HttpIntercept, HttpsIntercept, InterceptionManager, ModifierClosure};
use crate::network::dns::Dns;
use crate::platform::process::{NetworkType, ProcessInfo, ProcessInfoDepth};
use crate::platform::{get_iface_address, process};
use crate::proxy::{ConnAbortHandle, ConnHandle, ConnTarget, ContextManager, NetworkAddr};
use arc_swap::ArcSwap;
use boltapi::{ConnResultCode, ConnStage, ConnState, DestinationResolution, IdentificationSource};
use bytes::Bytes;
use rcgen::Certificate;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::error::TransportError;

pub(crate) enum DispatchError {
    Reject,
    BlackHole,
    BadMitmCert,
    BadChain,
    Error(TransportError),
}

fn finish_dispatch_error(info: &ConnHandle, error: &DispatchError) {
    match error {
        DispatchError::Reject => {
            info.finish(
                ConnResultCode::RouteRejected,
                Some(ConnStage::Routing),
                None,
            );
        }
        DispatchError::BlackHole => {
            info.finish(ConnResultCode::Blackholed, Some(ConnStage::Routing), None);
        }
        DispatchError::BadMitmCert => {
            info.finish(
                ConnResultCode::HandshakeError,
                Some(ConnStage::Handshaking),
                None,
            );
        }
        DispatchError::BadChain => {
            info.finish(
                ConnResultCode::InternalError,
                Some(ConnStage::Routing),
                None,
            );
        }
        DispatchError::Error(error) => {
            finish_transport_error(info, error, ConnStage::Connecting);
        }
    }
}

fn finish_transport_error(info: &ConnHandle, error: &TransportError, fallback_stage: ConnStage) {
    let (code, stage) = classify_transport_error(error, fallback_stage);
    info.finish(code, Some(stage), Some(bounded_detail(&error.to_string())));
}

fn classify_transport_error(
    error: &TransportError,
    fallback_stage: ConnStage,
) -> (ConnResultCode, ConnStage) {
    match error {
        TransportError::Dns(_) => (ConnResultCode::DnsError, ConnStage::Resolving),
        TransportError::Timeout(_) => (ConnResultCode::ConnectTimeout, ConnStage::Connecting),
        TransportError::Http(_)
        | TransportError::Socks5(_)
        | TransportError::Socks5Extra(_)
        | TransportError::Trojan(_)
        | TransportError::Anytls(_)
        | TransportError::ShadowSocks(_)
        | TransportError::Ssh(_)
        | TransportError::Handshake(_) => (ConnResultCode::HandshakeError, ConnStage::Handshaking),
        TransportError::Io(error)
            if fallback_stage == ConnStage::Inspecting
                && error.kind() == std::io::ErrorKind::UnexpectedEof =>
        {
            (ConnResultCode::ClientClosed, ConnStage::Inspecting)
        }
        TransportError::Io(_) if fallback_stage == ConnStage::Transferring => {
            (ConnResultCode::TransferError, ConnStage::Transferring)
        }
        TransportError::Io(_) | TransportError::WireGuard(_) => {
            (ConnResultCode::ConnectError, fallback_stage)
        }
        TransportError::Internal(_) | TransportError::InternalExtra(_) => {
            (ConnResultCode::InternalError, fallback_stage)
        }
    }
}

fn bounded_detail(detail: &str) -> String {
    crate::proxy::bounded_error_detail(detail)
}

pub struct Dispatcher {
    iface_name: String,
    dns: Arc<Dns>,
    sniff_flag: AtomicBool,
    stat_center: Arc<ContextManager>,
    dispatching: ArcSwap<Dispatching>,
    ca_certificate: Certificate,
    modifier: ArcSwap<ModifierClosure>,
    intercept_mgr: ArcSwap<InterceptionManager>,
    wireguard_mgr: Arc<WireguardManager>,
    ssh_mgr: Arc<SshManager>,
    anytls_mgr: Arc<AnytlsManager>,
    link_table: Arc<LinkTable>,
    pub(crate) process_info_depth: ProcessInfoDepth,
}

impl Dispatcher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        iface_name: &str,
        dns: Arc<Dns>,
        sniff_flag: bool,
        stat_center: Arc<ContextManager>,
        dispatching: Arc<Dispatching>,
        ca_certificate: Certificate,
        modifier: ModifierClosure,
        intercept_mgr: Arc<InterceptionManager>,
        wireguard_mgr: Arc<WireguardManager>,
        link_table: Arc<LinkTable>,
        process_info_depth: ProcessInfoDepth,
    ) -> Self {
        let ssh_mgr = SshManager::new(
            iface_name,
            dns.clone(),
            Duration::from_secs(10),
            link_table.clone(),
        );
        Self {
            iface_name: iface_name.into(),
            dns,
            sniff_flag: AtomicBool::new(sniff_flag),
            stat_center,
            dispatching: ArcSwap::new(dispatching),
            ca_certificate,
            modifier: ArcSwap::new(Arc::new(modifier)),
            intercept_mgr: ArcSwap::new(intercept_mgr),
            wireguard_mgr,
            ssh_mgr: Arc::new(ssh_mgr),
            anytls_mgr: Arc::new(AnytlsManager::new(link_table.clone())),
            link_table,
            process_info_depth,
        }
    }

    /// Reconciles link identity before the caller publishes its new routing
    /// graph, then terminates every connection tied to an invalidated generation.
    pub(crate) async fn reconcile_link_configs(
        &self,
        configured: HashMap<String, NamedLinkConfig>,
    ) -> Vec<LinkInvalidation> {
        let invalidations = self.link_table.reconcile(configured);
        for invalidation in &invalidations {
            self.stat_center.finish_link_dependents(
                &invalidation.name,
                invalidation.generation,
                invalidation.connection_result,
            );
            self.wireguard_mgr
                .stop_generation(&invalidation.name, invalidation.generation)
                .await;
            self.ssh_mgr
                .stop_generation(&invalidation.name, invalidation.generation)
                .await;
            self.anytls_mgr
                .stop_generation(&invalidation.name, invalidation.generation)
                .await;
        }
        invalidations
    }

    pub(crate) fn link_table(&self) -> Arc<LinkTable> {
        self.link_table.clone()
    }

    /// Pull protocol-owned evidence into the shared generation records before
    /// a controller snapshot. This keeps callers independent of manager type.
    pub(crate) async fn refresh_link_evidence(&self) {
        tokio::join!(
            self.wireguard_mgr.refresh_evidence(),
            self.ssh_mgr.refresh_evidence(),
            self.anytls_mgr.refresh_evidence(),
        );
    }

    pub fn replace_dispatching(&self, dispatching: Arc<Dispatching>) {
        self.dispatching.store(dispatching);
    }

    pub fn replace_intercept_filter(&self, intercept_mgr: Arc<InterceptionManager>) {
        self.intercept_mgr.store(intercept_mgr);
    }

    pub fn replace_modifier(&self, closure: ModifierClosure) {
        self.modifier.store(Arc::new(closure));
    }

    pub fn set_sniff_flag(&self, flag: bool) {
        self.sniff_flag
            .store(flag, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_wg_mgr(&self) -> Arc<WireguardManager> {
        self.wireguard_mgr.clone()
    }

    pub(super) fn get_iface_name(&self) -> String {
        self.iface_name.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_normal_outbound(
        &self,
        routing: &Dispatching,
        proxy_name: &str,
        iface_name: &str,
        proxy_config: &ProxyImpl,
        src_addr: SocketAddr,
        dst_addr: &NetworkAddr,
        resolved_dst: Option<&SocketAddr>,
    ) -> Result<(Box<dyn Outbound>, OutboundType), ()> {
        Ok(match proxy_config {
            ProxyImpl::Direct => (
                Box::new(DirectOutbound::new(
                    iface_name,
                    dst_addr.clone(),
                    resolved_dst.cloned(),
                    self.dns.clone(),
                )),
                OutboundType::Direct,
            ),
            ProxyImpl::Http(cfg) => (
                Box::new(HttpOutbound::new(
                    proxy_name,
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Http,
            ),
            ProxyImpl::Socks5(cfg) => (
                Box::new(Socks5Outbound::new(
                    proxy_name,
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Socks5,
            ),
            ProxyImpl::Shadowsocks(cfg) => (
                Box::new(SSOutbound::new(
                    proxy_name,
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Shadowsocks,
            ),
            ProxyImpl::Trojan(cfg) => (
                Box::new(TrojanOutbound::new(
                    proxy_name,
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Trojan,
            ),
            ProxyImpl::Anytls(config) => (
                Box::new(AnytlsOutboundHandle::new(
                    proxy_name,
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    LinkRuntimeConfig::new(
                        config.clone(),
                        routing.link_routes(proxy_name).ok_or(())?.to_vec(),
                    ),
                    self.anytls_mgr.clone(),
                )),
                OutboundType::Anytls,
            ),
            ProxyImpl::Wireguard(config) => (
                Box::new(WireguardHandle::new(
                    proxy_name,
                    src_addr,
                    dst_addr.clone(),
                    LinkRuntimeConfig::new(
                        (**config).clone(),
                        routing.link_routes(proxy_name).ok_or(())?.to_vec(),
                    ),
                    self.wireguard_mgr.clone(),
                )),
                OutboundType::Wireguard,
            ),
            ProxyImpl::Ssh(config) => (
                Box::new(SshOutboundHandle::new(
                    proxy_name,
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    LinkRuntimeConfig::new(
                        config.clone(),
                        routing.link_routes(proxy_name).ok_or(())?.to_vec(),
                    ),
                    self.ssh_mgr.clone(),
                )),
                OutboundType::Ssh,
            ),
            ProxyImpl::Chain(_) => {
                tracing::warn!("Nested chain unsupported");
                return Err(());
            }
            ProxyImpl::BlackHole | ProxyImpl::Reject => return Err(()),
        })
    }

    pub(super) fn create_chain(
        &self,
        routing: &Dispatching,
        chain_name: &str,
        vec: &[GeneralProxy],
        src_addr: SocketAddr,
        dst_addr: &NetworkAddr,
        iface_name: &str,
    ) -> Result<ChainOutbound, ()> {
        let impls: Vec<_> = vec
            .iter()
            .map(|n| match n {
                GeneralProxy::Single(p) => (p.get_name(), p.get_impl()),
                GeneralProxy::Group(g) => {
                    let proxy = g.get_proxy();
                    (proxy.get_name(), proxy.get_impl())
                }
            })
            .collect();
        let mut res = vec![];
        let mut dst_addrs = vec![];

        // extract destination
        // if A->B->C, then vec is [C, B, A]
        dst_addrs.push(dst_addr.clone());
        for idx in 1..vec.len() {
            let proxy_impl = impls.get(idx - 1).unwrap().1.as_ref();
            if let Some(dst) = proxy_impl.server_addr() {
                dst_addrs.push(dst);
            } else {
                tracing::warn!("{:?} should not be a part of chain", proxy_impl);
                return Err(());
            }
        }

        for idx in 0..vec.len() {
            let proxy = impls.get(idx).unwrap();
            let (outbounding, _) = self.build_normal_outbound(
                routing,
                &proxy.0,
                iface_name,
                &proxy.1,
                src_addr,
                dst_addrs.get(idx).unwrap(),
                None,
            )?;
            res.push(outbounding);
        }
        Ok(ChainOutbound::new(chain_name, res))
    }

    pub async fn construct_outbound(
        &self,
        src_addr: SocketAddr,
        dst_addr: &NetworkAddr,
        proxy_config: &ProxyImpl,
        proxy_name: &str,
        iface_name: &str,
        resolved_dst: Option<&SocketAddr>,
    ) -> Result<(Box<dyn Outbound>, OutboundType), DispatchError> {
        let routing = self.dispatching.load_full();
        self.construct_outbound_from(
            routing.as_ref(),
            src_addr,
            dst_addr,
            proxy_config,
            proxy_name,
            iface_name,
            resolved_dst,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn construct_outbound_from(
        &self,
        routing: &Dispatching,
        src_addr: SocketAddr,
        dst_addr: &NetworkAddr,
        proxy_config: &ProxyImpl,
        proxy_name: &str,
        iface_name: &str,
        resolved_dst: Option<&SocketAddr>,
    ) -> Result<(Box<dyn Outbound>, OutboundType), DispatchError> {
        Ok(match proxy_config {
            ProxyImpl::Chain(vec) => (
                Box::new(
                    self.create_chain(routing, proxy_name, vec, src_addr, dst_addr, iface_name)
                        .map_err(|_| DispatchError::BadChain)?,
                ),
                OutboundType::Chain,
            ),
            ProxyImpl::BlackHole => {
                return Err(DispatchError::BlackHole);
            }
            _ => self
                .build_normal_outbound(
                    routing,
                    proxy_name,
                    iface_name,
                    proxy_config,
                    src_addr,
                    dst_addr,
                    resolved_dst,
                )
                .map_err(|_| DispatchError::Reject)?,
        })
    }

    // All invocations of this function should be in a spawned task
    // since submission may block on DNS resolution or SNI sniff etc.
    pub async fn submit_tcp<S: StreamOutboundTrait>(
        &self,
        inbound: InboundInfo,
        src_addr: SocketAddr,
        target: ConnTarget,
        indicator: Arc<AtomicU8>,
        stream: S,
    ) -> Result<(), DispatchError> {
        let process_info = process::get_pid(src_addr, process::NetworkType::Tcp)
            .map_or(None, |pid| {
                process::get_process_info(pid, self.process_info_depth)
            });

        let abort_handle = ConnAbortHandle::new();
        let dst_addr = target.effective;

        let mut conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            local_ip: get_iface_address(self.iface_name.as_str()).ok(),
            inbound: inbound.clone(),
            resolved_dst: None,
            connection_type: NetworkType::Tcp,
            process_info: process_info.clone(),
        };
        let info = self.stat_center.begin(
            conn_info.clone(),
            target.accepted,
            None,
            abort_handle.clone(),
        );
        if let Some(source) = target.identification {
            info.set_identified_target(dst_addr.clone(), source);
        }

        let (inbound_conn, next_conn) = Connector::new_pair(10);
        let mut inbound_adapter = TcpAdapter::new(
            src_addr,
            dst_addr.clone(),
            stream,
            indicator,
            inbound_conn,
            abort_handle.clone(),
        );

        let mut parsed_proto = None;
        if self.sniff_flag.load(std::sync::atomic::Ordering::Relaxed) {
            info.set_state(ConnState::Inspecting);
            match inbound_adapter.try_sni_or_host().await {
                Ok(Some((proto, domain_name))) => {
                    let identified = NetworkAddr::Domain {
                        name: domain_name,
                        port: dst_addr.port(),
                    };
                    conn_info.dst = identified.clone();
                    info.set_identified_target(
                        identified,
                        match proto {
                            crate::proxy::SessionProtocol::Http => IdentificationSource::HttpHost,
                            crate::proxy::SessionProtocol::Tls => IdentificationSource::TlsSni,
                            _ => unreachable!("sniffer identifies only HTTP or TLS hostnames"),
                        },
                    );
                    info.set_protocol(proto);
                    parsed_proto = Some(proto);
                }
                Ok(None) => {}
                Err(error) => {
                    finish_transport_error(&info, &error, ConnStage::Inspecting);
                    return Err(DispatchError::Error(error));
                }
            }
        }

        // match outbound proxy
        info.set_state(ConnState::Routing);
        let routing = self.dispatching.load_full();
        let DispatchMatch {
            proxy_name,
            proxy: proxy_config,
            iface,
            route,
        } = routing.matches(&mut conn_info, true, Some(&info)).await;
        info.set_route(route);
        if let Some(address) = conn_info.resolved_dst {
            info.set_resolution(DestinationResolution::Resolved { address });
        } else if matches!(conn_info.dst, NetworkAddr::Domain { .. })
            && !matches!(
                proxy_config.as_ref(),
                ProxyImpl::Direct | ProxyImpl::Reject | ProxyImpl::BlackHole
            )
        {
            info.set_resolution(DestinationResolution::Delegated);
        }
        let iface_name = iface
            .as_ref()
            .map_or(self.iface_name.as_str(), |s| s.as_str());
        let (outbounding, proxy_type): (Box<dyn Outbound>, OutboundType) = match self
            .construct_outbound_from(
                routing.as_ref(),
                src_addr,
                &dst_addr,
                &proxy_config,
                &proxy_name,
                iface_name,
                conn_info.resolved_dst.as_ref(),
            )
            .await
        {
            Ok(r) => r,
            Err(DispatchError::Reject) => {
                info.finish(
                    ConnResultCode::RouteRejected,
                    Some(ConnStage::Routing),
                    None,
                );
                return Err(DispatchError::Reject);
            }
            Err(DispatchError::BlackHole) => {
                info.finish(ConnResultCode::Blackholed, Some(ConnStage::Routing), None);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(inbound_adapter);
                });
                return Err(DispatchError::BlackHole);
            }
            Err(error) => {
                finish_dispatch_error(&info, &error);
                return Err(error);
            }
        };

        let mut handles = Vec::new();
        info.set_outbound(proxy_name, proxy_type);
        if let Some(proto) = parsed_proto {
            info.set_protocol(proto);
        }
        info.set_state(ConnState::Connecting);
        handles.push({
            let info = info.clone();
            (
                "tcp".to_string(),
                tokio::spawn(async move {
                    if let Err(err) = inbound_adapter.run(info).await {
                        tracing::error!("[Dispatcher] run TcpAdapter failed: {}", err)
                    }
                }),
            )
        });

        // mitm for 80/443
        if let NetworkAddr::Domain {
            name: domain_name,
            port,
        } = conn_info.dst.clone()
            && (port == 80 || port == 443)
        {
            let result = self.intercept_mgr.load().matches(conn_info).await;
            if result.should_intercept() {
                let parrot_fingerprint = result.parrot_fingerprint;
                let modifier = (self.modifier.load())(result, process_info);
                match port {
                    80 => {
                        // hijack
                        tracing::debug!("HTTP intercept for {}", domain_name);
                        {
                            let info = info.clone();
                            tokio::spawn(async move {
                                let mocker = HttpIntercept::new(
                                    DuplexChan::new(next_conn),
                                    modifier,
                                    outbounding,
                                    info,
                                );
                                if let Err(err) = mocker.run().await {
                                    tracing::error!("[Dispatcher] mock HTTP failed: {}", err)
                                }
                            })
                        };
                        abort_handle.fulfill(handles);
                        return Ok(());
                    }
                    443 => {
                        tracing::debug!(
                            "HTTPS intercept for {}; parrot_fingerprint={}",
                            domain_name,
                            parrot_fingerprint
                        );
                        {
                            let info = info.clone();
                            let mocker = match HttpsIntercept::new(
                                &self.ca_certificate,
                                domain_name,
                                DuplexChan::new(next_conn),
                                modifier,
                                outbounding,
                                info.clone(),
                                parrot_fingerprint,
                            ) {
                                Ok(v) => v,
                                Err(err) => {
                                    tracing::error!(
                                        "[Dispatcher] sign certificate failed: {}",
                                        err
                                    );
                                    info.finish(
                                        ConnResultCode::HandshakeError,
                                        Some(ConnStage::Handshaking),
                                        Some(bounded_detail(&err.to_string())),
                                    );
                                    return Err(DispatchError::BadMitmCert);
                                }
                            };
                            tokio::spawn(async move {
                                if let Err(err) = mocker.run().await {
                                    tracing::error!("[Dispatcher] mock HTTPS failed: {}", err)
                                }
                            })
                        };
                        abort_handle.fulfill(handles);
                        return Ok(());
                    }
                    _ => {
                        // fallback
                    }
                }
            }
        }
        let abort_handle2 = abort_handle.clone();
        let outbound_info = info.clone();
        handles.push((
            outbounding.outbound_type().to_string(),
            tokio::spawn(async move {
                let result = outbounding
                    .spawn_tcp(next_conn, abort_handle2, Some(outbound_info.clone()))
                    .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::error!("[Dispatcher] create failed: {}", error);
                        finish_transport_error(&outbound_info, &error, ConnStage::Connecting);
                    }
                    Err(error) => {
                        tracing::error!("[Dispatcher] outbound task failed: {}", error);
                        outbound_info.finish(
                            ConnResultCode::InternalError,
                            Some(ConnStage::Connecting),
                            Some(bounded_detail(&error.to_string())),
                        );
                    }
                }
            }),
        ));
        abort_handle.fulfill(handles);
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    async fn route_udp(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        mut conn_info: ConnInfo,
        info: &ConnHandle,
    ) -> Result<(Box<dyn Outbound>, OutboundType, String), DispatchError> {
        info.set_state(ConnState::Routing);
        let routing = self.dispatching.load_full();
        let DispatchMatch {
            proxy_name,
            proxy: proxy_config,
            iface,
            route,
        } = routing.matches(&mut conn_info, true, Some(info)).await;
        info.set_route(route);
        if let Some(address) = conn_info.resolved_dst {
            info.set_resolution(DestinationResolution::Resolved { address });
        } else if matches!(conn_info.dst, NetworkAddr::Domain { .. })
            && !matches!(
                proxy_config.as_ref(),
                ProxyImpl::Direct | ProxyImpl::Reject | ProxyImpl::BlackHole
            )
        {
            info.set_resolution(DestinationResolution::Delegated);
        }
        let iface_name = iface
            .as_ref()
            .map_or(self.iface_name.as_str(), |s| s.as_str());
        let (outbounding, proxy_type): (Box<dyn Outbound>, OutboundType) =
            match proxy_config.as_ref() {
                ProxyImpl::Chain(vec) => (
                    Box::new(
                        self.create_chain(
                            routing.as_ref(),
                            &proxy_name,
                            vec,
                            src_addr,
                            &dst_addr,
                            iface_name,
                        )
                        .map_err(|_| DispatchError::Reject)?,
                    ),
                    OutboundType::Chain,
                ),
                ProxyImpl::BlackHole => return Err(DispatchError::BlackHole),
                _ => self
                    .build_normal_outbound(
                        routing.as_ref(),
                        &proxy_name,
                        iface_name,
                        proxy_config.as_ref(),
                        src_addr,
                        &dst_addr,
                        conn_info.resolved_dst.as_ref(),
                    )
                    .map_err(|_| DispatchError::Reject)?,
            };
        Ok((outbounding, proxy_type, proxy_name))
    }

    pub async fn allow_tun_udp(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        proc_info: Option<ProcessInfo>,
    ) -> bool {
        let mut conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr,
            local_ip: get_iface_address(self.iface_name.as_str()).ok(),
            inbound: InboundInfo::Tun,
            resolved_dst: None,
            connection_type: NetworkType::Udp,
            process_info: proc_info,
        };
        !matches!(
            self.dispatching
                .load()
                .matches(&mut conn_info, false, None)
                .await
                .proxy
                .as_ref(),
            ProxyImpl::Reject
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn submit_any_udp_session(
        &self,
        inbound: InboundInfo,
        src_addr: SocketAddr,
        target: ConnTarget,
        proc_info: Option<ProcessInfo>,
        send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
        recv_tx: UdpReturnChannel,
        indicator: Arc<AtomicBool>,
    ) -> Result<(), DispatchError> {
        let dst_addr = target.effective;
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            local_ip: get_iface_address(self.iface_name.as_str()).ok(),
            inbound,
            resolved_dst: None,
            connection_type: NetworkType::Udp,
            process_info: proc_info,
        };
        let abort_handle = ConnAbortHandle::new();
        let info = self.stat_center.begin(
            conn_info.clone(),
            target.accepted,
            None,
            abort_handle.clone(),
        );
        if let Some(source) = target.identification {
            info.set_identified_target(dst_addr.clone(), source);
        }
        let (outbounding, proxy_type, proxy_name) =
            match self.route_udp(src_addr, dst_addr, conn_info, &info).await {
                Ok(r) => r,
                Err(DispatchError::BlackHole) => {
                    info.finish(ConnResultCode::Blackholed, Some(ConnStage::Routing), None);
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        drop(send_rx);
                        drop(recv_tx);
                    });
                    return Err(DispatchError::BlackHole);
                }
                Err(DispatchError::Reject) => {
                    info.finish(
                        ConnResultCode::RouteRejected,
                        Some(ConnStage::Routing),
                        None,
                    );
                    return Err(DispatchError::Reject);
                }
                Err(error) => {
                    finish_dispatch_error(&info, &error);
                    return Err(error);
                }
            };
        info.set_outbound(proxy_name, proxy_type);
        info.set_state(ConnState::Connecting);

        let mut handles = Vec::new();

        let (adapter_now, adapter_next) = AddrConnector::new_pair(10);

        handles.push(("udp".to_string(), {
            let info = info.clone();
            let abort_handle = abort_handle.clone();
            let dns = self.dns.clone();
            tokio::spawn(async move {
                match recv_tx {
                    UdpReturnChannel::Tun(recv_tx) => {
                        let udp_adapter =
                            TunUdpAdapter::new(info, send_rx, recv_tx, adapter_now, dns, indicator);
                        if let Err(err) = udp_adapter.run(abort_handle).await {
                            tracing::error!("[Dispatcher] run TunUdpAdapter failed: {}", err)
                        }
                    }
                    UdpReturnChannel::Socks(recv_tx) => {
                        let udp_adapter = SocksUdpAdapter::new(
                            info,
                            send_rx,
                            recv_tx,
                            src_addr,
                            indicator,
                            adapter_now,
                        );
                        if let Err(err) = udp_adapter.run(abort_handle).await {
                            tracing::error!("[Dispatcher] run TunUdpAdapter failed: {}", err)
                        }
                    }
                }
            })
        }));
        let abort_handle2 = abort_handle.clone();
        let outbound_info = info.clone();
        handles.push((
            outbounding.outbound_type().to_string(),
            tokio::spawn(async move {
                let result = outbounding
                    .spawn_udp(
                        adapter_next,
                        abort_handle2,
                        false,
                        Some(outbound_info.clone()),
                    )
                    .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::error!("[Dispatcher] create failed: {}", error);
                        finish_transport_error(&outbound_info, &error, ConnStage::Connecting);
                    }
                    Err(error) => {
                        tracing::error!("[Dispatcher] outbound task failed: {}", error);
                        outbound_info.finish(
                            ConnResultCode::InternalError,
                            Some(ConnStage::Connecting),
                            Some(bounded_detail(&error.to_string())),
                        );
                    }
                }
            }),
        ));
        abort_handle.fulfill(handles);
        Ok(())
    }

    pub async fn submit_tun_udp_session(
        &self,
        src_addr: SocketAddr,
        target: ConnTarget,
        proc_info: Option<ProcessInfo>,
        send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
        recv_tx: mpsc::Sender<(Bytes, SocketAddr)>,
        indicator: Arc<AtomicBool>,
    ) -> Result<(), DispatchError> {
        self.submit_any_udp_session(
            InboundInfo::Tun,
            src_addr,
            target,
            proc_info,
            send_rx,
            UdpReturnChannel::Tun(recv_tx),
            indicator,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn submit_socks_udp_session(
        &self,
        inbound_extra: InboundExtra,
        src_addr: SocketAddr,
        target: ConnTarget,
        process_info: Option<ProcessInfo>,
        send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
        recv_tx: Arc<UdpSocket>,
        indicator: Arc<AtomicBool>,
    ) -> Result<(), DispatchError> {
        self.submit_any_udp_session(
            InboundInfo::Socks5(inbound_extra),
            src_addr,
            target,
            process_info,
            send_rx,
            UdpReturnChannel::Socks(recv_tx),
            indicator,
        )
        .await
    }
}

enum UdpReturnChannel {
    Tun(mpsc::Sender<(Bytes, SocketAddr)>),
    Socks(Arc<UdpSocket>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_handle() -> (ContextManager, ConnHandle) {
        let manager = ContextManager::new(10);
        let destination = NetworkAddr::from(SocketAddr::from(([203, 0, 113, 1], 443)));
        let handle = manager.begin(
            ConnInfo {
                src: SocketAddr::from(([127, 0, 0, 1], 12_345)),
                dst: destination.clone(),
                local_ip: None,
                inbound: InboundInfo::Tun,
                resolved_dst: None,
                connection_type: NetworkType::Tcp,
                process_info: None,
            },
            destination,
            None,
            ConnAbortHandle::placeholder(),
        );
        (manager, handle)
    }

    #[test]
    fn inspection_failure_is_retained_before_routing() {
        let (manager, handle) = test_handle();
        handle.set_state(ConnState::Inspecting);
        finish_transport_error(
            &handle,
            &TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed during inspection",
            )),
            ConnStage::Inspecting,
        );

        assert!(manager.get_active_copy().is_empty());
        let snapshot = manager.get_inactive_copy()[0].snapshot();
        assert_eq!(snapshot.state.state, ConnState::Closed);
        let termination = snapshot.state.termination.unwrap();
        assert_eq!(termination.code, ConnResultCode::ClientClosed);
        assert_eq!(termination.stage, Some(ConnStage::Inspecting));
    }

    #[test]
    fn transport_errors_have_stable_result_and_stage_classification() {
        let cases = [
            (
                TransportError::Dns(crate::proxy::error::DnsError::ResolveDomain(
                    "example.com".to_string(),
                )),
                ConnResultCode::DnsError,
                ConnStage::Resolving,
            ),
            (
                TransportError::Timeout("connect"),
                ConnResultCode::ConnectTimeout,
                ConnStage::Connecting,
            ),
            (
                TransportError::Trojan("authentication failed"),
                ConnResultCode::HandshakeError,
                ConnStage::Handshaking,
            ),
            (
                TransportError::Io(std::io::Error::other("relay failed")),
                ConnResultCode::TransferError,
                ConnStage::Transferring,
            ),
        ];

        for (error, expected_code, expected_stage) in cases {
            assert_eq!(
                classify_transport_error(&error, expected_stage),
                (expected_code, expected_stage)
            );
        }
    }

    #[test]
    fn terminal_details_are_sanitized_and_bounded() {
        let detail = format!("\u{0}\n{}", "x".repeat(300));
        let bounded = bounded_detail(&detail);
        assert_eq!(bounded.chars().count(), 256);
        assert!(bounded.chars().all(|character| !character.is_control()));
        assert!(bounded.starts_with(' '));
    }
}
