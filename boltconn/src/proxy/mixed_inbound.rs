use crate::dispatch::InboundManager;
use crate::network::dns::Dns;
use crate::proxy::error::TransportError;
use crate::proxy::{Dispatcher, HttpInbound, Socks5Inbound};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

use super::SessionManager;

pub struct MixedInbound {
    sock_addr: SocketAddr,
    server: TcpListener,
    http_mgr: Arc<InboundManager>,
    socks_mgr: Arc<InboundManager>,
    dispatcher: Arc<Dispatcher>,
    session_mgr: Arc<SessionManager>,
    dns: Arc<Dns>,
}

impl MixedInbound {
    pub async fn new(
        sock_addr: SocketAddr,
        http_mgr: InboundManager,
        socks_mgr: InboundManager,
        dispatcher: Arc<Dispatcher>,
        session_mgr: Arc<SessionManager>,
        dns: Arc<Dns>,
    ) -> io::Result<Self> {
        let server = TcpListener::bind(sock_addr).await?;
        Ok(Self {
            sock_addr,
            server,
            http_mgr: Arc::new(http_mgr),
            socks_mgr: Arc::new(socks_mgr),
            dispatcher,
            session_mgr,
            dns,
        })
    }

    pub async fn run(self) {
        tracing::info!("[Mixed] Listen proxy at {}, running...", self.sock_addr);
        loop {
            match self.server.accept().await {
                Ok((socket, src_addr)) => {
                    let disp = self.dispatcher.clone();
                    let http_mgr = self.http_mgr.clone();
                    let socks_mgr = self.socks_mgr.clone();
                    let session_mgr = self.session_mgr.clone();
                    let dns = self.dns.clone();
                    tokio::spawn(Self::serve_connection(
                        self.sock_addr.port(),
                        socket,
                        http_mgr,
                        socks_mgr,
                        src_addr,
                        disp,
                        session_mgr,
                        dns,
                    ));
                }
                Err(err) => {
                    tracing::error!("Mixed inbound failed to accept: {}", err);
                    return;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_connection(
        self_port: u16,
        socks_stream: TcpStream,
        http_mgr: Arc<InboundManager>,
        socks_mgr: Arc<InboundManager>,
        src_addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
        session_mgr: Arc<SessionManager>,
        dns: Arc<Dns>,
    ) -> Result<(), TransportError> {
        let mut first_byte = [0u8; 1];
        socks_stream.peek(&mut first_byte).await?;
        const C_ASCII: u8 = b"C"[0];
        match first_byte[0] {
            4u8 => {
                tracing::warn!("Socks4 not supported");
            }
            5u8 => {
                Socks5Inbound::serve_connection(
                    socks_stream,
                    socks_mgr,
                    src_addr,
                    dispatcher,
                    session_mgr,
                    dns,
                )
                .await?
            }

            C_ASCII => {
                HttpInbound::serve_connection(socks_stream, http_mgr, src_addr, dispatcher).await?
            }
            _ => {
                HttpInbound::serve_legacy_connection(
                    self_port,
                    socks_stream,
                    http_mgr,
                    src_addr,
                    dispatcher,
                )
                .await?
            }
        }
        Ok(())
    }
}
