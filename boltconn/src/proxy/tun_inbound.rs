use crate::common::buf_pool::{PktBufHandle, PktBufPool};
use crate::proxy::manager::SessionManager;
use crate::proxy::{Dispatcher, NetworkAddr};
use crate::Dns;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::io::Result;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

pub struct UdpOutboundManager(DashMap<(SocketAddr, NetworkAddr), SendSide>);

impl UdpOutboundManager {
    pub fn new() -> Self {
        Self(DashMap::new())
    }
}

struct SendSide {
    sender: mpsc::Sender<PktBufHandle>,
    indicator: Arc<AtomicBool>,
}

pub struct TunInbound {
    nat_addr: SocketAddr,
    session_mgr: Arc<SessionManager>,
    dispatcher: Arc<Dispatcher>,
    dns: Arc<Dns>,
    pool: PktBufPool,
    udp_mgr: Arc<UdpOutboundManager>,
}

impl TunInbound {
    pub fn new(
        addr: SocketAddr,
        session_mgr: Arc<SessionManager>,
        dispatcher: Arc<Dispatcher>,
        dns: Arc<Dns>,
        pool: PktBufPool,
        udp_mgr: Arc<UdpOutboundManager>,
    ) -> Self {
        Self {
            nat_addr: addr,
            session_mgr,
            dispatcher,
            dns,
            pool,
            udp_mgr,
        }
    }

    pub async fn run_tcp(&self) -> Result<()> {
        let tcp_listener = TcpListener::bind(self.nat_addr).await?;
        tracing::event!(
            tracing::Level::INFO,
            "[NAT] Listen TCP at {}, running...",
            self.nat_addr
        );
        loop {
            let (socket, addr) = tcp_listener.accept().await?;
            if let Ok((src_addr, dst_addr, indicator)) =
                self.session_mgr.lookup_tcp_session(addr.port())
            {
                // tracing::trace!("[NAT] received new connection {}->{}", src_addr, dst_addr);
                let dst_addr = match self.dns.fake_ip_to_domain(dst_addr.ip()) {
                    None => NetworkAddr::Raw(dst_addr),
                    Some(s) => NetworkAddr::DomainName {
                        domain_name: s,
                        port: dst_addr.port(),
                    },
                };
                self.dispatcher
                    .submit_tun_tcp(src_addr, dst_addr, indicator, socket)
                    .await;
            } else {
                tracing::warn!("Unexpected: no record found by port {}", addr.port())
            }
        }
    }

    async fn retryable_udp(
        &self,
        pkt: PktBufHandle,
        src: SocketAddr,
        real_dst: &NetworkAddr,
        dst: SocketAddr,
        indicator: &Arc<AtomicBool>,
        udp_listener: &Arc<UdpSocket>,
    ) -> Option<PktBufHandle> {
        match self.udp_mgr.0.entry((src, real_dst.clone())) {
            Entry::Occupied(val) => {
                if let Err(pkt) = val.get().sender.send(pkt).await {
                    val.remove();
                    // let caller to retry
                    return Some(pkt.0);
                }
            }
            Entry::Vacant(entry) => {
                let (sender, receiver) = mpsc::channel(128);
                let send_side = SendSide {
                    sender,
                    indicator: indicator.clone(),
                };
                // push packet into channel
                let _ = send_side.sender.send(pkt).await;
                entry.insert(send_side);
                self.dispatcher
                    .submit_tun_udp_pkt(
                        src,
                        real_dst.clone(),
                        dst,
                        receiver,
                        indicator.clone(),
                        udp_listener,
                        &self.session_mgr,
                    )
                    .await;
            }
        }
        None
    }

    pub async fn run_udp(&self) -> Result<()> {
        let udp_listener = Arc::new(UdpSocket::bind(self.nat_addr).await?);
        tracing::event!(
            tracing::Level::INFO,
            "[NAT] Listen UDP at {}, running...",
            self.nat_addr
        );
        loop {
            let mut buffer = self.pool.obtain().await;
            let (len, src) = udp_listener.recv_from(buffer.as_uninited()).await?;
            buffer.len = len;
            if let Ok((src, dst, indicator)) = self.session_mgr.lookup_udp_session(src.ip()) {
                let real_dst = match self.dns.fake_ip_to_domain(dst.ip()) {
                    None => NetworkAddr::Raw(dst),
                    Some(s) => NetworkAddr::DomainName {
                        domain_name: s,
                        port: dst.port(),
                    },
                };

                if let Some(retry_pkt) = self
                    .retryable_udp(buffer, src, &real_dst, dst, &indicator, &udp_listener)
                    .await
                {
                    // retry once
                    if let Some(recycle) = self
                        .retryable_udp(retry_pkt, src, &real_dst, dst, &indicator, &udp_listener)
                        .await
                    {
                        self.pool.release(recycle);
                    }
                }
            } else {
                // no corresponding, drop
                self.pool.release(buffer);
                continue;
            }
        }
    }
}
