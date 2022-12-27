use crate::common::buf_pool::PktBufPool;
use crate::proxy::manager::SessionManager;
use crate::proxy::{Dispatcher, NetworkAddr};
use crate::Dns;
use std::io::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};

pub struct Nat {
    nat_addr: SocketAddr,
    session_mgr: Arc<SessionManager>,
    dispatcher: Arc<Dispatcher>,
    dns: Arc<Dns>,
    pool: PktBufPool,
}

impl Nat {
    pub fn new(
        addr: SocketAddr,
        session_mgr: Arc<SessionManager>,
        dispatcher: Arc<Dispatcher>,
        dns: Arc<Dns>,
        pool: PktBufPool,
    ) -> Self {
        Self {
            nat_addr: addr,
            session_mgr,
            dispatcher,
            dns,
            pool,
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
                    .submit_tun_tcp(src_addr, dst_addr, indicator, socket);
            } else {
                tracing::warn!("Unexpected: no record found by port {}", addr.port())
            }
        }
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
                if let Err(buffer) = self
                    .dispatcher
                    .submit_udp_pkt(
                        buffer,
                        src,
                        real_dst.clone(),
                        dst,
                        indicator.clone(),
                        &udp_listener,
                        &self.session_mgr,
                    )
                    .await
                {
                    // retry only once
                    let _ = self
                        .dispatcher
                        .submit_udp_pkt(
                            buffer,
                            src,
                            real_dst,
                            dst,
                            indicator,
                            &udp_listener,
                            &self.session_mgr,
                        )
                        .await;
                }
            } else {
                // no corresponding, drop
                self.pool.release(buffer);
                continue;
            }
        }
    }
}
