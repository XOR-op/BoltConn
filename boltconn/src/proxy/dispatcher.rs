use crate::adapter::{
    Connector, DirectOutbound, NatAdapter, OutboundType, SSOutbound, Socks5Outbound, TcpOutBound,
    TunAdapter, UdpOutBound,
};
use crate::common::buf_pool::PktBufHandle;
use crate::common::duplex_chan::DuplexChan;
use crate::common::host_matcher::HostMatcher;
use crate::dispatch::{ConnInfo, Dispatching, ProxyImpl};
use crate::network::dns::Dns;
use crate::platform::process;
use crate::platform::process::NetworkType;
use crate::proxy::{NetworkAddr, SessionManager, StatCenter, StatisticsInfo};
use crate::sniff::{HttpSniffer, HttpsSniffer, Modifier, ModifierClosure};
use crate::PktBufPool;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
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
    stat_center: Arc<StatCenter>,
    dispatching: Arc<Dispatching>,
    certificate: Vec<Certificate>,
    priv_key: PrivateKey,
    modifier: ModifierClosure,
    mitm_hosts: HostMatcher,
    udp_sessions: DashMap<(SocketAddr, NetworkAddr), SendSide>,
}

impl Dispatcher {
    pub fn new(
        iface_name: &str,
        allocator: PktBufPool,
        dns: Arc<Dns>,
        stat_center: Arc<StatCenter>,
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
            dispatching,
            certificate,
            priv_key,
            modifier,
            mitm_hosts,
            udp_sessions: DashMap::new(),
        }
    }

    pub fn submit_tun_tcp(
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
        let (outbounding, proxy_type): (Box<dyn TcpOutBound>, OutboundType) =
            match self.dispatching.matches(&conn_info).as_ref() {
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
        let info = Arc::new(RwLock::new(StatisticsInfo::new(
            dst_addr.clone(),
            process_info.clone(),
            proxy_type,
            NetworkType::TCP,
        )));
        self.stat_center.push(info.clone());

        let (tun_conn, tun_next) = Connector::new_pair(10);
        let tun_alloc = self.allocator.clone();
        let out_dst_addr = dst_addr.clone();
        let info_clone = info.clone();
        tokio::spawn(async move {
            let tun = TunAdapter::new(
                src_addr,
                out_dst_addr,
                info,
                stream,
                indicator,
                tun_alloc,
                tun_conn,
            );
            if let Err(err) = tun.run().await {
                tracing::error!("[Dispatcher] run TunAdapter failed: {}", err)
            }
        });
        let modifier = (self.modifier)(process_info);
        if let NetworkAddr::DomainName { domain_name, port } = dst_addr {
            if self.mitm_hosts.matches(&domain_name) {
                match port {
                    80 => {
                        // hijack
                        let http_alloc = self.allocator.clone();
                        tokio::spawn(async move {
                            let mocker = HttpSniffer::new(
                                DuplexChan::new(http_alloc, tun_next),
                                modifier,
                                outbounding,
                                info_clone,
                            );
                            if let Err(err) = mocker.run().await {
                                tracing::error!("[Dispatcher] mock HTTP failed: {}", err)
                            }
                        });
                        return;
                    }
                    443 => {
                        let http_alloc = self.allocator.clone();
                        let cert = self.certificate.clone();
                        let key = self.priv_key.clone();
                        tokio::spawn(async move {
                            let mocker = HttpsSniffer::new(
                                cert,
                                key,
                                domain_name,
                                DuplexChan::new(http_alloc, tun_next),
                                modifier,
                                outbounding,
                                info_clone,
                            );
                            if let Err(err) = mocker.run().await {
                                tracing::error!("[Dispatcher] mock HTTPS failed: {}", err)
                            }
                        });
                        return;
                    }
                    _ => {
                        // fallback
                    }
                }
            }
        }
        tokio::spawn(async move {
            if let Err(err) = outbounding.spawn_tcp(tun_next).await {
                tracing::error!("[Dispatcher] create failed: {}", err)
            }
        });
    }

    pub async fn submit_udp_pkt(
        &self,
        pkt: PktBufHandle,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        dst_fake_addr: SocketAddr,
        indicator: Arc<AtomicBool>,
        socket: &Arc<UdpSocket>,
        session_mgr: &Arc<SessionManager>,
    ) {
        match self.udp_sessions.entry((src_addr, dst_addr.clone())) {
            Entry::Occupied(val) => {
                let _ = val.get().sender.send(pkt).await;
            }
            Entry::Vacant(entry) => {
                let process_info = process::get_pid(src_addr, NetworkType::UDP)
                    .map_or(None, |pid| process::get_process_info(pid));
                let conn_info = ConnInfo {
                    src: src_addr,
                    dst: dst_addr.clone(),
                    connection_type: NetworkType::UDP,
                    process_info: process_info.clone(),
                };
                let (outbounding, proxy_type): (Box<dyn UdpOutBound>, OutboundType) =
                    match self.dispatching.matches(&conn_info).as_ref() {
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
                let info = Arc::new(RwLock::new(StatisticsInfo::new(
                    dst_addr.clone(),
                    process_info.clone(),
                    proxy_type,
                    NetworkType::UDP,
                )));
                self.stat_center.push(info.clone());

                let (nat_conn, nat_next) = Connector::new_pair(10);
                let nat_allocator = self.allocator.clone();
                let (sender, receiver) = mpsc::channel(128);
                let send_side = SendSide { sender, indicator };
                // push packet into channel
                let _ = send_side.sender.send(pkt).await;

                entry.insert(send_side);
                let socket = socket.clone();
                let session_mgr = session_mgr.clone();
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
                    if let Err(err) = nat_adp.run().await {
                        tracing::error!("[Dispatcher] run NatAdapter failed: {}", err)
                    }
                });
                tokio::spawn(async move {
                    if let Err(err) = outbounding.spawn_udp(nat_next).await {
                        tracing::error!("[Dispatcher] create failed: {}", err)
                    }
                });
            }
        }
    }
}

struct SendSide {
    sender: tokio::sync::mpsc::Sender<PktBufHandle>,
    indicator: Arc<AtomicBool>,
}
