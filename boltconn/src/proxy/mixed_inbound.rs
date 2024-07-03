use crate::proxy::error::TransportError;
use crate::proxy::{Dispatcher, HttpInbound, Socks5Inbound};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

pub struct MixedInbound {
    sock_addr: SocketAddr,
    server: TcpListener,
    http_auth: Arc<HashMap<String, String>>,
    socks_auth: Arc<HashMap<String, String>>,
    dispatcher: Arc<Dispatcher>,
}

impl MixedInbound {
    pub async fn new(
        sock_addr: SocketAddr,
        http_auth: HashMap<String, String>,
        socks_auth: HashMap<String, String>,
        dispatcher: Arc<Dispatcher>,
    ) -> io::Result<Self> {
        let server = TcpListener::bind(sock_addr).await?;
        Ok(Self {
            sock_addr,
            server,
            http_auth: Arc::new(http_auth),
            socks_auth: Arc::new(socks_auth),
            dispatcher,
        })
    }

    pub async fn run(self) {
        tracing::info!("[Mixed] Listen proxy at {}, running...", self.sock_addr);
        loop {
            match self.server.accept().await {
                Ok((socket, src_addr)) => {
                    let disp = self.dispatcher.clone();
                    let http_auth = self.http_auth.clone();
                    let socks_auth = self.socks_auth.clone();
                    tokio::spawn(Self::serve_connection(
                        self.sock_addr.port(),
                        socket,
                        http_auth,
                        socks_auth,
                        src_addr,
                        disp,
                    ));
                }
                Err(err) => {
                    tracing::error!("Mixed inbound failed to accept: {}", err);
                    return;
                }
            }
        }
    }

    async fn serve_connection(
        self_port: u16,
        mut socks_stream: TcpStream,
        http_auth: Arc<HashMap<String, String>>,
        socks_auth: Arc<HashMap<String, String>>,
        src_addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
    ) -> Result<(), TransportError> {
        let mut first_byte = [0u8; 1];
        socks_stream.read_exact(&mut first_byte).await?;
        const C_ASCII: u8 = b"C"[0];
        match first_byte[0] {
            4u8 => {
                tracing::warn!("Socks4 not supported");
            }
            5u8 => {
                Socks5Inbound::serve_connection(
                    self_port,
                    socks_stream,
                    socks_auth,
                    src_addr,
                    dispatcher,
                    Some(5u8),
                )
                .await?
            }

            C_ASCII => {
                HttpInbound::serve_connection(
                    self_port,
                    socks_stream,
                    http_auth,
                    src_addr,
                    dispatcher,
                    Some("C".to_string()),
                )
                .await?
            }
            _ => {
                // Unknown, drop
            }
        }
        Ok(())
    }
}
