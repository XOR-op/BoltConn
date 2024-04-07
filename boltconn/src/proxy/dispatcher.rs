use crate::adapter::{
    AddrConnector, ChainOutbound, Connector, DirectOutbound, HttpOutbound, Outbound, OutboundType,
    SSOutbound, Socks5Outbound, StandardUdpAdapter, TcpAdapter, TrojanOutbound, TunUdpAdapter,
    WireguardHandle, WireguardManager,
};
use crate::common::duplex_chan::DuplexChan;
use crate::dispatch::{
    ConnInfo, Dispatching, GeneralProxy, InboundIdentity, InboundInfo, ProxyImpl,
};
use crate::intercept::{HttpIntercept, HttpsIntercept, InterceptionManager, ModifierClosure};
use crate::network::dns::Dns;
use crate::platform::process::{NetworkType, ProcessInfo};
use crate::platform::{get_iface_address, process};
use crate::proxy::{ConnAbortHandle, ConnContext, ContextManager, NetworkAddr};
use arc_swap::ArcSwap;
use bytes::Bytes;
use rcgen::Certificate;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

pub(crate) enum DispatchError {
    Reject,
    BlackHole,
    BadMitmCert,
    BadChain,
}

pub struct Dispatcher {
    iface_name: String,
    dns: Arc<Dns>,
    stat_center: Arc<ContextManager>,
    dispatching: ArcSwap<Dispatching>,
    ca_certificate: Certificate,
    modifier: ArcSwap<ModifierClosure>,
    intercept_mgr: ArcSwap<InterceptionManager>,
    wireguard_mgr: Arc<WireguardManager>,
}

impl Dispatcher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        iface_name: &str,
        dns: Arc<Dns>,
        stat_center: Arc<ContextManager>,
        dispatching: Arc<Dispatching>,
        ca_certificate: Certificate,
        modifier: ModifierClosure,
        intercept_mgr: Arc<InterceptionManager>,
    ) -> Self {
        let wg_mgr = WireguardManager::new(iface_name, dns.clone(), Duration::from_secs(180));
        Self {
            iface_name: iface_name.into(),
            dns,
            stat_center,
            dispatching: ArcSwap::new(dispatching),
            ca_certificate,
            modifier: ArcSwap::new(Arc::new(modifier)),
            intercept_mgr: ArcSwap::new(intercept_mgr),
            wireguard_mgr: Arc::new(wg_mgr),
        }
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

    pub(super) fn get_iface_name(&self) -> String {
        self.iface_name.clone()
    }

    pub(super) fn build_normal_outbound(
        &self,
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
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Http,
            ),
            ProxyImpl::Socks5(cfg) => (
                Box::new(Socks5Outbound::new(
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Socks5,
            ),
            ProxyImpl::Shadowsocks(cfg) => (
                Box::new(SSOutbound::new(
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Shadowsocks,
            ),
            ProxyImpl::Trojan(cfg) => (
                Box::new(TrojanOutbound::new(
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Trojan,
            ),
            ProxyImpl::Wireguard(cfg) => (
                Box::new(WireguardHandle::new(
                    src_addr,
                    dst_addr.clone(),
                    cfg.clone(),
                    self.wireguard_mgr.clone(),
                    Arc::new(cfg.dns.clone()),
                )),
                OutboundType::Wireguard,
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
        vec: &[GeneralProxy],
        src_addr: SocketAddr,
        dst_addr: &NetworkAddr,
        iface_name: &str,
    ) -> Result<ChainOutbound, ()> {
        let impls: Vec<_> = vec
            .iter()
            .map(|n| match n {
                GeneralProxy::Single(p) => p.get_impl(),
                GeneralProxy::Group(g) => g.get_proxy().get_impl(),
            })
            .collect();
        let mut res = vec![];
        let mut dst_addrs = vec![];

        // extract destination
        // if A->B->C, then vec is [C, B, A]
        dst_addrs.push(dst_addr.clone());
        for idx in 1..vec.len() {
            let proxy_impl = impls.get(idx - 1).unwrap().as_ref();
            if let Some(dst) = proxy_impl.server_addr() {
                dst_addrs.push(dst);
            } else {
                tracing::warn!("{:?} should not be a part of chain", proxy_impl);
                return Err(());
            }
        }

        for idx in 0..vec.len() {
            let (outbounding, _) = self.build_normal_outbound(
                iface_name,
                impls.get(idx).unwrap().as_ref(),
                src_addr,
                dst_addrs.get(idx).unwrap(),
                None,
            )?;
            res.push(outbounding);
        }
        Ok(ChainOutbound::new(res))
    }

    pub async fn submit_tcp(
        &self,
        inbound: InboundInfo,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        indicator: Arc<AtomicU8>,
        stream: TcpStream,
    ) -> Result<(), DispatchError> {
        let process_info = process::get_pid(src_addr, process::NetworkType::Tcp)
            .map_or(None, process::get_process_info);
        let mut conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            local_ip: get_iface_address(self.iface_name.as_str()).ok(),
            inbound: inbound.clone(),
            resolved_dst: None,
            connection_type: NetworkType::Tcp,
            process_info: process_info.clone(),
        };
        // match outbound proxy
        let (proxy_config, iface) = self.dispatching.load().matches(&mut conn_info, true).await;
        let iface_name = iface
            .as_ref()
            .map_or(self.iface_name.as_str(), |s| s.as_str());
        let (outbounding, proxy_type): (Box<dyn Outbound>, OutboundType) =
            match proxy_config.as_ref() {
                ProxyImpl::Chain(vec) => (
                    Box::new(
                        self.create_chain(vec, src_addr, &dst_addr, iface_name)
                            .map_err(|_| DispatchError::BadChain)?,
                    ),
                    OutboundType::Chain,
                ),
                ProxyImpl::BlackHole => {
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        drop(stream)
                    });
                    return Err(DispatchError::BlackHole);
                }
                _ => self
                    .build_normal_outbound(
                        iface_name,
                        proxy_config.as_ref(),
                        src_addr,
                        &dst_addr,
                        conn_info.resolved_dst.as_ref(),
                    )
                    .map_err(|_| DispatchError::Reject)?,
            };

        // conn info
        let abort_handle = ConnAbortHandle::new();
        let info = Arc::new(ConnContext::new(
            dst_addr.clone(),
            process_info.clone(),
            inbound,
            proxy_type,
            NetworkType::Tcp,
            abort_handle.clone(),
            self.stat_center.get_upload(),
            self.stat_center.get_download(),
        ));

        let (tun_conn, tun_next) = Connector::new_pair(10);
        let mut handles = Vec::new();

        handles.push({
            let info = info.clone();
            let dst_addr = dst_addr.clone();
            let abort_handle = abort_handle.clone();
            (
                "tcp".to_string(),
                tokio::spawn(async move {
                    let tun = TcpAdapter::new(
                        src_addr,
                        dst_addr,
                        info,
                        stream,
                        indicator,
                        tun_conn,
                        abort_handle,
                    );
                    if let Err(err) = tun.run().await {
                        tracing::error!("[Dispatcher] run TcpAdapter failed: {}", err)
                    }
                }),
            )
        });

        // mitm for 80/443
        if let NetworkAddr::DomainName { domain_name, port } = dst_addr {
            if port == 80 || port == 443 {
                let result = self.intercept_mgr.load().matches(&mut conn_info).await;
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
                                        DuplexChan::new(tun_next),
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
                            self.stat_center.push(info);
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
                                    DuplexChan::new(tun_next),
                                    modifier,
                                    outbounding,
                                    info,
                                    parrot_fingerprint,
                                ) {
                                    Ok(v) => v,
                                    Err(err) => {
                                        tracing::error!(
                                            "[Dispatcher] sign certificate failed: {}",
                                            err
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
                            self.stat_center.push(info);
                            return Ok(());
                        }
                        _ => {
                            // fallback
                        }
                    }
                }
            }
        }
        let abort_handle2 = abort_handle.clone();
        handles.push((
            outbounding.outbound_type().to_string(),
            tokio::spawn(async move {
                if let Err(err) = outbounding.spawn_tcp(tun_next, abort_handle2).await {
                    tracing::error!("[Dispatcher] create failed: {}", err)
                }
            }),
        ));
        abort_handle.fulfill(handles);
        self.stat_center.push(info);
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    async fn route_udp(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        mut conn_info: ConnInfo,
    ) -> Result<(Box<dyn Outbound>, Arc<ConnContext>, ConnAbortHandle), DispatchError> {
        let (proxy_config, iface) = self.dispatching.load().matches(&mut conn_info, true).await;
        let iface_name = iface
            .as_ref()
            .map_or(self.iface_name.as_str(), |s| s.as_str());
        let (outbounding, proxy_type): (Box<dyn Outbound>, OutboundType) =
            match proxy_config.as_ref() {
                ProxyImpl::Chain(vec) => (
                    Box::new(
                        self.create_chain(vec, src_addr, &dst_addr, iface_name)
                            .map_err(|_| DispatchError::Reject)?,
                    ),
                    OutboundType::Chain,
                ),
                ProxyImpl::BlackHole => return Err(DispatchError::BlackHole),
                _ => self
                    .build_normal_outbound(
                        iface_name,
                        proxy_config.as_ref(),
                        src_addr,
                        &dst_addr,
                        conn_info.resolved_dst.as_ref(),
                    )
                    .map_err(|_| DispatchError::Reject)?,
            };
        // conn info
        let abort_handle = ConnAbortHandle::new();
        let info = Arc::new(ConnContext::new(
            dst_addr,
            conn_info.process_info,
            conn_info.inbound,
            proxy_type,
            NetworkType::Udp,
            abort_handle.clone(),
            self.stat_center.get_upload(),
            self.stat_center.get_download(),
        ));
        Ok((outbounding, info, abort_handle))
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
                .matches(&mut conn_info, false)
                .await
                .0
                .as_ref(),
            ProxyImpl::Reject
        )
    }

    pub async fn submit_tun_udp_session(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        proc_info: Option<ProcessInfo>,
        send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
        recv_tx: mpsc::Sender<(Bytes, SocketAddr)>,
        indicator: Arc<AtomicBool>,
    ) -> Result<(), DispatchError> {
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            local_ip: get_iface_address(self.iface_name.as_str()).ok(),
            inbound: InboundInfo::Tun,
            resolved_dst: None,
            connection_type: NetworkType::Udp,
            process_info: proc_info,
        };
        let (outbounding, info, abort_handle) =
            match self.route_udp(src_addr, dst_addr, conn_info).await {
                Ok(r) => r,
                Err(DispatchError::BlackHole) => {
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        drop(send_rx);
                        drop(recv_tx);
                    });
                    return Err(DispatchError::BlackHole);
                }
                Err(e) => return Err(e),
            };

        let mut handles = Vec::new();

        let (adapter_tun, adapter_next) = AddrConnector::new_pair(10);

        handles.push(("tun_udp".to_string(), {
            let info = info.clone();
            let abort_handle = abort_handle.clone();
            let dns = self.dns.clone();
            tokio::spawn(async move {
                let tun_udp =
                    TunUdpAdapter::new(info, send_rx, recv_tx, adapter_tun, dns, indicator);
                if let Err(err) = tun_udp.run(abort_handle).await {
                    tracing::error!("[Dispatcher] run TunUdpAdapter failed: {}", err)
                }
            })
        }));
        let abort_handle2 = abort_handle.clone();
        handles.push((
            outbounding.outbound_type().to_string(),
            tokio::spawn(async move {
                if let Err(err) = outbounding
                    .spawn_udp(adapter_next, abort_handle2, false)
                    .await
                {
                    tracing::error!("[Dispatcher] create failed: {}", err)
                }
            }),
        ));
        abort_handle.fulfill(handles);
        self.stat_center.push(info.clone());
        Ok(())
    }

    pub async fn submit_socks_udp_pkt(
        &self,
        inbound_port: u16,
        user: Option<String>,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        indicator: Arc<AtomicBool>,
        socket: UdpSocket,
    ) -> Result<(), DispatchError> {
        let process_info =
            process::get_pid(src_addr, NetworkType::Udp).map_or(None, process::get_process_info);
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            local_ip: get_iface_address(self.iface_name.as_str()).ok(),
            inbound: InboundInfo::Socks5(InboundIdentity {
                user,
                port: Some(inbound_port),
            }),
            resolved_dst: None,
            connection_type: NetworkType::Udp,
            process_info: process_info.clone(),
        };
        let (outbounding, info, abort_handle) =
            match self.route_udp(src_addr, dst_addr, conn_info).await {
                Ok(r) => r,
                Err(DispatchError::BlackHole) => {
                    tokio::spawn(async {
                        tokio::time::interval(Duration::from_secs(30)).tick().await;
                        drop(socket);
                    });
                    return Err(DispatchError::BlackHole);
                }
                Err(e) => return Err(e),
            };
        let mut handles = Vec::new();

        let (adapter_conn, adapter_next) = AddrConnector::new_pair(10);

        handles.push(("udp".to_string(), {
            let info = info.clone();
            let abort_handle = abort_handle.clone();
            tokio::spawn(async move {
                let udp_adapter =
                    StandardUdpAdapter::new(info, socket, src_addr, indicator, adapter_conn);
                if let Err(err) = udp_adapter.run(abort_handle).await {
                    tracing::error!("[Dispatcher] run StandardUdpAdapter failed: {}", err)
                }
            })
        }));
        let abort_handle2 = abort_handle.clone();
        handles.push((
            outbounding.outbound_type().to_string(),
            tokio::spawn(async move {
                if let Err(err) = outbounding
                    .spawn_udp(adapter_next, abort_handle2, false)
                    .await
                {
                    tracing::error!("[Dispatcher] create failed: {}", err)
                }
            }),
        ));
        abort_handle.fulfill(handles);
        self.stat_center.push(info.clone());
        Ok(())
    }
}
