use crate::Dns;
use crate::dispatch::InboundInfo;
use crate::proxy::dispatcher::DispatchError;
use crate::proxy::manager::MappingSessionManager;
use crate::proxy::{ConnTarget, Dispatcher, NetworkAddr};
use boltapi::IdentificationSource;
use std::io::{ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::TcpListener;

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

pub struct TunTcpInbound {
    nat_addr: SocketAddr,
    session_mgr: Arc<MappingSessionManager>,
    dispatcher: Arc<Dispatcher>,
    dns: Arc<Dns>,
}

impl TunTcpInbound {
    pub fn new(
        addr: SocketAddr,
        session_mgr: Arc<MappingSessionManager>,
        dispatcher: Arc<Dispatcher>,
        dns: Arc<Dns>,
    ) -> Self {
        Self {
            nat_addr: addr,
            session_mgr,
            dispatcher,
            dns,
        }
    }

    pub fn nat_addr(&self) -> SocketAddr {
        self.nat_addr
    }

    pub async fn run(&self, tcp_listener: TcpListener) -> Result<()> {
        tracing::event!(
            tracing::Level::INFO,
            "[NAT] Listen TCP at {}, running...",
            self.nat_addr
        );
        loop {
            let (socket, addr) = match tcp_listener.accept().await {
                Ok(r) => r,
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::ConnectionAborted
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionRefused
                    ) =>
                {
                    // The client went away before accept; the listener is still healthy.
                    tracing::debug!("[NAT] Dropped TCP before accept: {}", e);
                    continue;
                }
                Err(e) => {
                    // Typically fd exhaustion. Keep listening: returning would stop all TUN TCP
                    // for the rest of the process even after descriptors are released.
                    tracing::error!("[NAT] Failed to accept TCP: {}", e);
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            };
            if let Ok((src_addr, dst_addr, indicator)) = self
                .session_mgr
                .lookup_tcp_session(self.nat_addr.is_ipv6(), addr.port())
            {
                let accepted = NetworkAddr::Socket { address: dst_addr };
                let target = match self.dns.fake_ip_to_domain(dst_addr.ip()) {
                    None => accepted.into(),
                    Some(name) => ConnTarget::identified(
                        accepted,
                        NetworkAddr::Domain {
                            name,
                            port: dst_addr.port(),
                        },
                        IdentificationSource::FakeIpMapping,
                    ),
                };
                let dispatcher = self.dispatcher.clone();
                tokio::spawn(async move {
                    match dispatcher
                        .submit_tcp(
                            InboundInfo::Tun,
                            src_addr,
                            target,
                            indicator.clone(),
                            socket,
                        )
                        .await
                    {
                        Ok(_) => {}
                        Err(DispatchError::BlackHole) => {}
                        Err(_) => indicator.store(0, Ordering::Relaxed),
                    }
                });
            } else {
                tracing::warn!("Unexpected: no record found by port {}", addr.port())
            }
        }
    }
}
