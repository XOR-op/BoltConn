use crate::dispatch::Dispatcher;
use crate::session::manager::SessionManager;
use std::io::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};

pub struct Nat {
    nat_addr: IpAddr,
    nat_port: u16,
    session_mgr: SessionManager,
    dispatcher: Arc<Dispatcher>,
}

impl Nat {
    pub fn new(addr: IpAddr, port: u16, dispatcher: Arc<Dispatcher>) -> Self {
        Self {
            nat_addr: addr,
            nat_port: port,
            session_mgr: SessionManager::new(),
            dispatcher,
        }
    }

    pub async fn run_tcp(&self) -> Result<()> {
        let tcp_listener = TcpListener::bind(SocketAddr::new(self.nat_addr, self.nat_port)).await?;
        loop {
            let (socket, addr) = tcp_listener.accept().await?;
            if let Ok((src_addr, dst_addr, indicator)) =
                self.session_mgr.query_tcp_by_token(addr.port())
            {
                self.dispatcher
                    .submit_tcp(src_addr, dst_addr, indicator, socket);
            } else {
                tracing::warn!("Unexpected: no record found by port {}", addr.port())
            }
        }
    }
    pub async fn run_udp(&self) -> Result<()> {
        let udp_listener = UdpSocket::bind(SocketAddr::new(self.nat_addr, self.nat_port)).await?;
        todo!()
    }
}
