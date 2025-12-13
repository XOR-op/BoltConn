use crate::adapter::{
    AddrConnector, ChainOutbound, Connector, DirectOutbound, HttpOutbound, Outbound, OutboundType,
    SSOutbound, Socks5Outbound, SocksUdpAdapter, SshManager, SshOutboundHandle, TcpAdapter,
    TrojanOutbound, TunUdpAdapter, WireguardHandle, WireguardManager,
};
use crate::common::StreamOutboundTrait;
use crate::common::duplex_chan::DuplexChan;
use crate::dispatch::{ConnInfo, Dispatching, GeneralProxy, InboundExtra, InboundInfo, ProxyImpl};
use crate::intercept::{HttpIntercept, HttpsIntercept, InterceptionManager, ModifierClosure};
use crate::network::dns::Dns;
use crate::platform::process::{NetworkType, ProcessInfo};
use crate::platform::{get_iface_address, process};
use crate::proxy::{ConnAbortHandle, ConnContext, ContextManager, NetworkAddr};
use arc_swap::ArcSwap;
use bytes::Bytes;
use rcgen::Certificate;
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
    ) -> Self {
        let wg_mgr = WireguardManager::new(iface_name, dns.clone(), Duration::from_secs(180));
        let ssh_mgr = SshManager::new(iface_name, dns.clone(), Duration::from_secs(180));
        Self {
            iface_name: iface_name.into(),
            dns,
            sniff_flag: AtomicBool::new(sniff_flag),
            stat_center,
            dispatching: ArcSwap::new(dispatching),
            ca_certificate,
            modifier: ArcSwap::new(Arc::new(modifier)),
            intercept_mgr: ArcSwap::new(intercept_mgr),
            wireguard_mgr: Arc::new(wg_mgr),
            ssh_mgr: Arc::new(ssh_mgr),
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

    pub(super) fn build_normal_outbound(
        &self,
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
            ProxyImpl::Wireguard(cfg) => (
                Box::new(WireguardHandle::new(
                    proxy_name,
                    src_addr,
                    dst_addr.clone(),
                    cfg.clone(),
                    self.wireguard_mgr.clone(),
                    Arc::new(cfg.dns.clone()),
                )),
                OutboundType::Wireguard,
            ),
            ProxyImpl::Ssh(cfg) => (
                Box::new(SshOutboundHandle::new(
                    proxy_name,
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                    cfg.clone(),
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
        Ok(match proxy_config {
            ProxyImpl::Chain(vec) => (
                Box::new(
                    self.create_chain(proxy_name, vec, src_addr, dst_addr, iface_name)
                        .map_err(|_| DispatchError::BadChain)?,
                ),
                OutboundType::Chain,
            ),
            ProxyImpl::BlackHole => {
                return Err(DispatchError::BlackHole);
            }
            _ => self
                .build_normal_outbound(
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
        dst_addr: NetworkAddr,
        indicator: Arc<AtomicU8>,
        stream: S,
    ) -> Result<(), DispatchError> {
        let process_info = process::get_pid(src_addr, process::NetworkType::Tcp)
            .map_or(None, process::get_process_info);

        // conn info
        let abort_handle = ConnAbortHandle::new();

        let (inbound_conn, next_conn) = Connector::new_pair(10);
        let mut inbound_adapter = TcpAdapter::new(
            src_addr,
            dst_addr.clone(),
            stream,
            indicator,
            inbound_conn,
            abort_handle.clone(),
        );

        let mut conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            local_ip: get_iface_address(self.iface_name.as_str()).ok(),
            inbound: inbound.clone(),
            resolved_dst: None,
            connection_type: NetworkType::Tcp,
            process_info: process_info.clone(),
        };

        let mut parsed_proto = None;
        if self.sniff_flag.load(std::sync::atomic::Ordering::Relaxed)
            && let Some((proto, domain_name)) = inbound_adapter
                .try_sni_or_host()
                .await
                .map_err(DispatchError::Error)?
        {
            conn_info.dst = NetworkAddr::DomainName {
                domain_name: domain_name.clone(),
                port: dst_addr.port(),
            };
            parsed_proto = Some(proto);
        };

        // match outbound proxy
        let (proxy_name, proxy_config, iface) =
            self.dispatching.load().matches(&mut conn_info, true).await;
        let iface_name = iface
            .as_ref()
            .map_or(self.iface_name.as_str(), |s| s.as_str());
        let (outbounding, proxy_type): (Box<dyn Outbound>, OutboundType) = match self
            .construct_outbound(
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
            Err(DispatchError::Reject) => return Err(DispatchError::Reject),
            Err(DispatchError::BlackHole) => {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(inbound_adapter);
                });
                return Err(DispatchError::BlackHole);
            }
            Err(e) => return Err(e),
        };

        let mut handles = Vec::new();
        let info = Arc::new(ConnContext::new(
            self.stat_center.alloc_unique_id(),
            conn_info.clone(),
            proxy_name,
            proxy_type,
            parsed_proto,
            abort_handle.clone(),
            self.stat_center.get_upload(),
            self.stat_center.get_download(),
            self.stat_center.get_notify_handle(),
        ));
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
        if let NetworkAddr::DomainName { domain_name, port } = conn_info.dst.clone()
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
                                DuplexChan::new(next_conn),
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
        let abort_handle2 = abort_handle.clone();
        handles.push((
            outbounding.outbound_type().to_string(),
            tokio::spawn(async move {
                if let Err(err) = outbounding.spawn_tcp(next_conn, abort_handle2).await {
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
        let (proxy_name, proxy_config, iface) =
            self.dispatching.load().matches(&mut conn_info, true).await;
        let iface_name = iface
            .as_ref()
            .map_or(self.iface_name.as_str(), |s| s.as_str());
        let (outbounding, proxy_type): (Box<dyn Outbound>, OutboundType) =
            match proxy_config.as_ref() {
                ProxyImpl::Chain(vec) => (
                    Box::new(
                        self.create_chain(&proxy_name, vec, src_addr, &dst_addr, iface_name)
                            .map_err(|_| DispatchError::Reject)?,
                    ),
                    OutboundType::Chain,
                ),
                ProxyImpl::BlackHole => return Err(DispatchError::BlackHole),
                _ => self
                    .build_normal_outbound(
                        &proxy_name,
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
            self.stat_center.alloc_unique_id(),
            conn_info,
            proxy_name,
            proxy_type,
            None,
            abort_handle.clone(),
            self.stat_center.get_upload(),
            self.stat_center.get_download(),
            self.stat_center.get_notify_handle(),
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
                .1
                .as_ref(),
            ProxyImpl::Reject
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn submit_any_udp_session(
        &self,
        inbound: InboundInfo,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        proc_info: Option<ProcessInfo>,
        send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
        recv_tx: UdpReturnChannel,
        indicator: Arc<AtomicBool>,
    ) -> Result<(), DispatchError> {
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            local_ip: get_iface_address(self.iface_name.as_str()).ok(),
            inbound,
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

    pub async fn submit_tun_udp_session(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        proc_info: Option<ProcessInfo>,
        send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
        recv_tx: mpsc::Sender<(Bytes, SocketAddr)>,
        indicator: Arc<AtomicBool>,
    ) -> Result<(), DispatchError> {
        self.submit_any_udp_session(
            InboundInfo::Tun,
            src_addr,
            dst_addr,
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
        dst_addr: NetworkAddr,
        process_info: Option<ProcessInfo>,
        send_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
        recv_tx: Arc<UdpSocket>,
        indicator: Arc<AtomicBool>,
    ) -> Result<(), DispatchError> {
        self.submit_any_udp_session(
            InboundInfo::Socks5(inbound_extra),
            src_addr,
            dst_addr,
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
