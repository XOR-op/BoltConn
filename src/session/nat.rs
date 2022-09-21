use crate::dispatch::Dispatcher;
use crate::session::manager::SessionManager;
use std::io::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};

pub struct Nat {
    nat_addr: SocketAddr,
    session_mgr: Arc<SessionManager>,
    dispatcher: Arc<Dispatcher>,
}

impl Nat {
    pub fn new(addr: SocketAddr, session_mgr: Arc<SessionManager>, dispatcher: Arc<Dispatcher>) -> Self {
        Self {
            nat_addr: addr,
            session_mgr,
            dispatcher,
        }
    }

    pub async fn run_tcp(&self) -> Result<()> {
        let tcp_listener = TcpListener::bind(self.nat_addr).await?;
        tracing::event!(tracing::Level::INFO,"[NAT] Listen TCP at {}",self.nat_addr);
        loop {
            let (socket, addr) = tcp_listener.accept().await?;
            if let Ok((src_addr, dst_addr, indicator)) =
            self.session_mgr.query_tcp_by_token(addr.port())
            {
                tracing::trace!("[NAT] received new connection {}->{}",src_addr,dst_addr);
                self.dispatcher
                    .submit_tcp(src_addr, dst_addr, indicator, socket);
            } else {
                tracing::warn!("Unexpected: no record found by port {}", addr.port())
            }
        }
    }
    pub async fn run_udp(&self) -> Result<()> {
        let udp_listener = UdpSocket::bind(self.nat_addr).await?;
        todo!()
    }
}
