use crate::adapter::{
    Connector, DirectOutbound, NatAdapter, OutboundType, SSOutbound, Socks5Outbound, TcpOutBound,
    TunAdapter, UdpOutBound,
};
use crate::common::buf_pool::PktBufHandle;
use crate::common::duplex_chan::DuplexChan;
use crate::common::host_matcher::HostMatcher;
use crate::dispatch::{ConnInfo, Dispatching, ProxyImpl};
use crate::mitm::{HttpMitm, HttpsMitm, ModifierClosure};
use crate::network::dns::Dns;
use crate::platform::process;
use crate::platform::process::NetworkType;
use crate::proxy::{AgentCenter, ConnAbortHandle, ConnAgent, NetworkAddr, SessionManager};
use crate::PktBufPool;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::rustls::{Certificate, PrivateKey};

pub struct Dispatcher {
    iface_name: String,
    allocator: PktBufPool,
    dns: Arc<Dns>,
    stat_center: Arc<AgentCenter>,
    dispatching: RwLock<Arc<Dispatching>>,
    certificate: Vec<Certificate>,
    priv_key: PrivateKey,
    modifier: ModifierClosure,
    mitm_hosts: RwLock<HostMatcher>,
}

impl Dispatcher {
    pub fn new(
        iface_name: &str,
        allocator: PktBufPool,
        dns: Arc<Dns>,
        stat_center: Arc<AgentCenter>,
        dispatching: Arc<Dispatching>,
        certificate: Vec<Certificate>,
        priv_key: PrivateKey,
        modifier: ModifierClosure,
        mitm_hosts: HostMatcher,
    ) -> Self {
        Self {
            iface_name: iface_name.into(),
            allocator,
            dns,
            stat_center,
            dispatching: RwLock::new(dispatching),
            certificate,
            priv_key,
            modifier,
            mitm_hosts: RwLock::new(mitm_hosts),
        }
    }

    pub fn replace_dispatching(&self, dispatching: Arc<Dispatching>) {
        *self.dispatching.write().unwrap() = dispatching;
    }

    pub fn replace_mitm_list(&self, mitm_hosts: HostMatcher) {
        *self.mitm_hosts.write().unwrap() = mitm_hosts;
    }

    pub async fn submit_tun_tcp(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        indicator: Arc<AtomicU8>,
        stream: TcpStream,
    ) {
        let process_info = process::get_pid(src_addr, process::NetworkType::TCP)
            .map_or(None, |pid| process::get_process_info(pid));
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            connection_type: NetworkType::TCP,
            process_info: process_info.clone(),
        };
        // match outbound proxy
        let (outbounding, proxy_type): (Box<dyn TcpOutBound>, OutboundType) = match self
            .dispatching
            .read()
            .unwrap()
            .matches(&conn_info)
            .as_ref()
        {
            ProxyImpl::Direct => (
                Box::new(DirectOutbound::new(
                    &self.iface_name,
                    dst_addr.clone(),
                    self.allocator.clone(),
                    self.dns.clone(),
                )),
                OutboundType::Direct,
            ),
            ProxyImpl::Reject => {
                indicator.store(0, Ordering::Relaxed);
                return;
            }
            ProxyImpl::Socks5(cfg) => (
                Box::new(Socks5Outbound::new(
                    &self.iface_name,
                    dst_addr.clone(),
                    self.allocator.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Socks5,
            ),
            ProxyImpl::Shadowsocks(cfg) => (
                Box::new(SSOutbound::new(
                    &self.iface_name,
                    dst_addr.clone(),
                    self.allocator.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Shadowsocks,
            ),
        };

        // conn info
        let abort_handle = ConnAbortHandle::new();
        let info = Arc::new(tokio::sync::RwLock::new(ConnAgent::new(
            dst_addr.clone(),
            process_info.clone(),
            proxy_type,
            NetworkType::TCP,
            abort_handle.clone(),
        )));

        let (tun_conn, tun_next) = Connector::new_pair(10);
        let mut handles = Vec::new();

        // tun adapter
        handles.push({
            let info = info.clone();
            let allocator = self.allocator.clone();
            let dst_addr = dst_addr.clone();
            let abort_handle = abort_handle.clone();
            tokio::spawn(async move {
                let tun = TunAdapter::new(
                    src_addr,
                    dst_addr,
                    info,
                    stream,
                    indicator,
                    allocator,
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
            if self.mitm_hosts.read().unwrap().matches(&domain_name) {
                let modifier = (self.modifier)(process_info);
                match port {
                    80 => {
                        // hijack
                        tracing::trace!("HTTP MitM for {}", domain_name);
                        handles.push({
                            let allocator = self.allocator.clone();
                            let info = info.clone();
                            let abort_handle = abort_handle.clone();
                            tokio::spawn(async move {
                                let mocker = HttpMitm::new(
                                    DuplexChan::new(allocator, tun_next),
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
                        return;
                    }
                    443 => {
                        tracing::trace!("HTTPS MitM for {}", domain_name);
                        handles.push({
                            let allocator = self.allocator.clone();
                            let cert = self.certificate.clone();
                            let key = self.priv_key.clone();
                            let info = info.clone();
                            let abort_handle = abort_handle.clone();
                            tokio::spawn(async move {
                                let mocker = HttpsMitm::new(
                                    cert,
                                    key,
                                    domain_name,
                                    DuplexChan::new(allocator, tun_next),
                                    modifier,
                                    outbounding,
                                    info,
                                );
                                if let Err(err) = mocker.run(abort_handle).await {
                                    tracing::error!("[Dispatcher] mock HTTPS failed: {}", err)
                                }
                            })
                        });
                        abort_handle.fulfill(handles).await;
                        self.stat_center.push(info).await;
                        return;
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
    }

    pub async fn submit_udp_pkt(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        dst_fake_addr: SocketAddr,
        receiver: mpsc::Receiver<PktBufHandle>,
        indicator: Arc<AtomicBool>,
        socket: &Arc<UdpSocket>,
        session_mgr: &Arc<SessionManager>,
    ) {
        let process_info = process::get_pid(src_addr, NetworkType::UDP)
            .map_or(None, |pid| process::get_process_info(pid));
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            connection_type: NetworkType::UDP,
            process_info: process_info.clone(),
        };
        let (outbounding, proxy_type): (Box<dyn UdpOutBound>, OutboundType) = match self
            .dispatching
            .read()
            .unwrap()
            .matches(&conn_info)
            .as_ref()
        {
            ProxyImpl::Direct => (
                Box::new(DirectOutbound::new(
                    &self.iface_name,
                    dst_addr.clone(),
                    self.allocator.clone(),
                    self.dns.clone(),
                )),
                OutboundType::Direct,
            ),
            ProxyImpl::Reject => {
                indicator.store(false, Ordering::Relaxed);
                return;
            }
            ProxyImpl::Socks5(cfg) => (
                Box::new(Socks5Outbound::new(
                    &self.iface_name,
                    dst_addr.clone(),
                    self.allocator.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Socks5,
            ),
            ProxyImpl::Shadowsocks(cfg) => (
                Box::new(SSOutbound::new(
                    &self.iface_name,
                    dst_addr.clone(),
                    self.allocator.clone(),
                    self.dns.clone(),
                    cfg.clone(),
                )),
                OutboundType::Shadowsocks,
            ),
        };

        // conn info
        let abort_handle = ConnAbortHandle::new();
        let info = Arc::new(tokio::sync::RwLock::new(ConnAgent::new(
            dst_addr.clone(),
            process_info.clone(),
            proxy_type,
            NetworkType::UDP,
            abort_handle.clone(),
        )));
        let mut handles = Vec::new();

        let (nat_conn, nat_next) = Connector::new_pair(10);
        let nat_allocator = self.allocator.clone();

        handles.push({
            let socket = socket.clone();
            let session_mgr = session_mgr.clone();
            let info = info.clone();
            let abort_handle = abort_handle.clone();
            tokio::spawn(async move {
                let nat_adp = NatAdapter::new(
                    info,
                    receiver,
                    socket,
                    src_addr,
                    dst_fake_addr,
                    nat_allocator,
                    nat_conn,
                    session_mgr,
                );
                if let Err(err) = nat_adp.run(abort_handle).await {
                    tracing::error!("[Dispatcher] run NatAdapter failed: {}", err)
                }
            })
        });
        let abort_handle2 = abort_handle.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = outbounding.spawn_udp(nat_next, abort_handle2).await {
                tracing::error!("[Dispatcher] create failed: {}", err)
            }
        }));
        abort_handle.fulfill(handles).await;
        self.stat_center.push(info.clone()).await;
    }
}
