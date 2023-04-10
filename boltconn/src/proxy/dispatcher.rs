use crate::adapter::{
    AddrConnector, ChainOutbound, Connector, DirectOutbound, HttpOutbound, OutboundType,
    SSOutbound, Socks5Outbound, StandardUdpAdapter, TcpAdapter, TcpOutBound, TrojanOutbound,
    TunUdpAdapter, UdpOutBound, WireguardHandle, WireguardManager,
};
use crate::common::duplex_chan::DuplexChan;
use crate::dispatch::{ConnInfo, Dispatching, GeneralProxy, ProxyImpl};
use crate::intercept::{HttpIntercept, HttpsIntercept, ModifierClosure};
use crate::network::dns::Dns;
use crate::platform::process;
use crate::platform::process::{NetworkType, ProcessInfo};
use crate::proxy::{AgentCenter, ConnAbortHandle, ConnAgent, NetworkAddr};
use bytes::Bytes;
use rcgen::Certificate;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

pub struct Dispatcher {
    iface_name: String,
    dns: Arc<Dns>,
    stat_center: Arc<AgentCenter>,
    dispatching: RwLock<Arc<Dispatching>>,
    ca_certificate: Certificate,
    modifier: RwLock<ModifierClosure>,
    intercept_filter: RwLock<Arc<Dispatching>>,
    wireguard_mgr: WireguardManager,
}

impl Dispatcher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        iface_name: &str,
        dns: Arc<Dns>,
        stat_center: Arc<AgentCenter>,
        dispatching: Arc<Dispatching>,
        ca_certificate: Certificate,
        modifier: ModifierClosure,
        intercept_filter: Arc<Dispatching>,
    ) -> Self {
        let wg_mgr = WireguardManager::new(iface_name, dns.clone(), Duration::from_secs(180));
        Self {
            iface_name: iface_name.into(),
            dns,
            stat_center,
            dispatching: RwLock::new(dispatching),
            ca_certificate,
            modifier: RwLock::new(modifier),
            intercept_filter: RwLock::new(intercept_filter),
            wireguard_mgr: wg_mgr,
        }
    }

    pub fn replace_dispatching(&self, dispatching: Arc<Dispatching>) {
        *self.dispatching.write().unwrap() = dispatching;
    }

    pub fn replace_intercept_filter(&self, intercept_filter: Arc<Dispatching>) {
        *self.intercept_filter.write().unwrap() = intercept_filter;
    }

    pub fn replace_modifier(&self, closure: ModifierClosure) {
        *self.modifier.write().unwrap() = closure;
    }

    async fn build_tcp_outbound(
        &self,
        iface_name: &str,
        proxy_config: &ProxyImpl,
        src_addr: &SocketAddr,
        dst_addr: &NetworkAddr,
    ) -> Result<(Box<dyn TcpOutBound>, OutboundType), ()> {
        Ok(match proxy_config {
            ProxyImpl::Direct => (
                Box::new(DirectOutbound::new(
                    iface_name,
                    dst_addr.clone(),
                    self.dns.clone(),
                )),
                OutboundType::Direct,
            ),
            ProxyImpl::Reject => {
                return Err(());
            }
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
            ProxyImpl::Wireguard(cfg) => {
                let Ok(outbound) = self.wireguard_mgr.get_wg_conn(cfg).await else {
                    tracing::warn!("Failed to create wireguard connection");
                    return Err(());
                };
                (
                    Box::new(WireguardHandle::new(
                        src_addr.port(),
                        dst_addr.clone(),
                        outbound,
                        self.dns.clone(),
                    )),
                    OutboundType::Wireguard,
                )
            }
            ProxyImpl::Chain(_) => {
                tracing::warn!("Nested chain unsupported");
                return Err(());
            }
        })
    }

    async fn create_chain(
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
            let (outbounding, _) = self
                .build_tcp_outbound(
                    iface_name,
                    impls.get(idx).unwrap().as_ref(),
                    &src_addr,
                    dst_addrs.get(idx).unwrap(),
                )
                .await?;
            res.push(outbounding);
        }
        Ok(ChainOutbound::new(res))
    }

    pub async fn submit_tcp(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        indicator: Arc<AtomicU8>,
        stream: TcpStream,
    ) -> Result<(), ()> {
        let process_info = process::get_pid(src_addr, process::NetworkType::Tcp)
            .map_or(None, process::get_process_info);
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            connection_type: NetworkType::Tcp,
            process_info: process_info.clone(),
        };
        // match outbound proxy
        let (proxy_config, iface) = self.dispatching.read().unwrap().matches(&conn_info, true);
        let iface_name = iface
            .as_ref()
            .map_or(self.iface_name.as_str(), |s| s.as_str());
        let (outbounding, proxy_type): (Box<dyn TcpOutBound>, OutboundType) =
            if let ProxyImpl::Chain(vec) = proxy_config.as_ref() {
                (
                    Box::new(
                        self.create_chain(vec, src_addr, &dst_addr, iface_name)
                            .await?,
                    ),
                    OutboundType::Chain,
                )
            } else {
                self.build_tcp_outbound(iface_name, proxy_config.as_ref(), &src_addr, &dst_addr)
                    .await?
            };

        // conn info
        let abort_handle = ConnAbortHandle::new();
        let info = Arc::new(tokio::sync::RwLock::new(ConnAgent::new(
            dst_addr.clone(),
            process_info.clone(),
            proxy_type,
            NetworkType::Tcp,
            abort_handle.clone(),
            self.stat_center.get_upload(),
            self.stat_center.get_download(),
        )));

        let (tun_conn, tun_next) = Connector::new_pair(10);
        let mut handles = Vec::new();

        // tun adapter
        handles.push({
            let info = info.clone();
            let dst_addr = dst_addr.clone();
            let abort_handle = abort_handle.clone();
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
                    tracing::error!("[Dispatcher] run TunAdapter failed: {}", err)
                }
            })
        });

        // mitm for 80/443
        if let NetworkAddr::DomainName { domain_name, port } = dst_addr {
            if (port == 80 || port == 443)
                && matches!(
                    self.intercept_filter
                        .read()
                        .unwrap()
                        .matches(&conn_info, false)
                        .0
                        .as_ref(),
                    ProxyImpl::Direct
                )
            {
                let modifier = (self.modifier.read().unwrap())(process_info);
                match port {
                    80 => {
                        // hijack
                        tracing::trace!("HTTP intercept for {}", domain_name);
                        handles.push({
                            let info = info.clone();
                            let abort_handle = abort_handle.clone();
                            tokio::spawn(async move {
                                let mocker = HttpIntercept::new(
                                    DuplexChan::new(tun_next),
                                    modifier,
                                    outbounding,
                                    info,
                                );
                                if let Err(err) = mocker.run(abort_handle).await {
                                    tracing::error!("[Dispatcher] mock HTTP failed: {}", err)
                                }
                            })
                        });
                        abort_handle.fulfill(handles).await;
                        self.stat_center.push(info).await;
                        return Ok(());
                    }
                    443 => {
                        tracing::trace!("HTTPS intercept for {}", domain_name);
                        handles.push({
                            let info = info.clone();
                            let abort_handle = abort_handle.clone();
                            let mocker = match HttpsIntercept::new(
                                &self.ca_certificate,
                                domain_name,
                                DuplexChan::new(tun_next),
                                modifier,
                                outbounding,
                                info,
                            ) {
                                Ok(v) => v,
                                Err(err) => {
                                    tracing::error!(
                                        "[Dispatcher] sign certificate failed: {}",
                                        err
                                    );
                                    return Err(());
                                }
                            };
                            tokio::spawn(async move {
                                if let Err(err) = mocker.run(abort_handle).await {
                                    tracing::error!("[Dispatcher] mock HTTPS failed: {}", err)
                                }
                            })
                        });
                        abort_handle.fulfill(handles).await;
                        self.stat_center.push(info).await;
                        return Ok(());
                    }
                    _ => {
                        // fallback
                    }
                }
            }
        }
        let abort_handle2 = abort_handle.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = outbounding.spawn_tcp(tun_next, abort_handle2).await {
                tracing::error!("[Dispatcher] create failed: {}", err)
            }
        }));
        abort_handle.fulfill(handles).await;
        self.stat_center.push(info).await;
        Ok(())
    }

    async fn route_udp(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        conn_info: ConnInfo,
    ) -> Result<
        (
            Box<dyn UdpOutBound>,
            Arc<tokio::sync::RwLock<ConnAgent>>,
            ConnAbortHandle,
        ),
        (),
    > {
        let (proxy_config, iface) = self.dispatching.read().unwrap().matches(&conn_info, true);
        let iface_name = iface
            .as_ref()
            .map_or(self.iface_name.as_str(), |s| s.as_str());
        let (outbounding, proxy_type): (Box<dyn UdpOutBound>, OutboundType) =
            match proxy_config.as_ref() {
                ProxyImpl::Direct => (
                    Box::new(DirectOutbound::new(
                        iface_name,
                        dst_addr.clone(),
                        self.dns.clone(),
                    )),
                    OutboundType::Direct,
                ),
                ProxyImpl::Reject => {
                    return Err(());
                }
                ProxyImpl::Http(_) => {
                    // http proxy doesn't support udp
                    unreachable!()
                }
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
                ProxyImpl::Wireguard(cfg) => {
                    let Ok(outbound) = self.wireguard_mgr.get_wg_conn(cfg).await else{
                        tracing::warn!("Failed to create wireguard connection");
                        return Err(());
                    };
                    (
                        Box::new(WireguardHandle::new(
                            src_addr.port(),
                            dst_addr.clone(),
                            outbound,
                            self.dns.clone(),
                        )),
                        OutboundType::Wireguard,
                    )
                }
                ProxyImpl::Chain(_) => unreachable!(),
            };

        // conn info
        let abort_handle = ConnAbortHandle::new();
        let info = Arc::new(tokio::sync::RwLock::new(ConnAgent::new(
            dst_addr.clone(),
            conn_info.process_info.clone(),
            proxy_type,
            NetworkType::Udp,
            abort_handle.clone(),
            self.stat_center.get_upload(),
            self.stat_center.get_download(),
        )));
        Ok((outbounding, info, abort_handle))
    }

    pub async fn allow_udp(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        proc_info: Option<ProcessInfo>,
    ) -> bool {
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr,
            connection_type: NetworkType::Udp,
            process_info: proc_info,
        };
        !matches!(
            self.dispatching
                .read()
                .unwrap()
                .matches(&conn_info, false)
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
    ) -> Result<(), ()> {
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            connection_type: NetworkType::Udp,
            process_info: proc_info,
        };
        let (outbounding, info, abort_handle) =
            self.route_udp(src_addr, dst_addr, conn_info).await?;

        let mut handles = Vec::new();

        let (adapter_tun, adapter_next) = AddrConnector::new_pair(10);

        handles.push({
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
        });
        let abort_handle2 = abort_handle.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = outbounding.spawn_udp(adapter_next, abort_handle2).await {
                tracing::error!("[Dispatcher] create failed: {}", err)
            }
        }));
        abort_handle.fulfill(handles).await;
        self.stat_center.push(info.clone()).await;
        Ok(())
    }

    pub async fn submit_socks_udp_pkt(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        indicator: Arc<AtomicBool>,
        socket: UdpSocket,
    ) -> Result<(), ()> {
        let process_info =
            process::get_pid(src_addr, NetworkType::Udp).map_or(None, process::get_process_info);
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            connection_type: NetworkType::Udp,
            process_info: process_info.clone(),
        };
        let (outbounding, info, abort_handle) =
            self.route_udp(src_addr, dst_addr, conn_info).await?;
        let mut handles = Vec::new();

        let (adapter_conn, adapter_next) = AddrConnector::new_pair(10);

        handles.push({
            let info = info.clone();
            let abort_handle = abort_handle.clone();
            tokio::spawn(async move {
                let udp_adapter =
                    StandardUdpAdapter::new(info, socket, src_addr, indicator, adapter_conn);
                if let Err(err) = udp_adapter.run(abort_handle).await {
                    tracing::error!("[Dispatcher] run StandardUdpAdapter failed: {}", err)
                }
            })
        });
        let abort_handle2 = abort_handle.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = outbounding.spawn_udp(adapter_next, abort_handle2).await {
                tracing::error!("[Dispatcher] create failed: {}", err)
            }
        }));
        abort_handle.fulfill(handles).await;
        self.stat_center.push(info.clone()).await;
        Ok(())
    }
}
