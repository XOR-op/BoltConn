use crate::proxy::{Dispatcher, HttpInbound, Socks5Inbound};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

pub struct MixedInbound {
    port: u16,
    server: TcpListener,
    http_auth: Option<String>,
    socks_auth: Option<(String, String)>,
    dispatcher: Arc<Dispatcher>,
}

impl MixedInbound {
    pub async fn new(
        port: u16,
        http_auth: Option<(String, String)>,
        socks_auth: Option<(String, String)>,
        dispatcher: Arc<Dispatcher>,
    ) -> io::Result<Self> {
        let server =
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)).await?;
        Ok(Self {
            port,
            server,
            http_auth: http_auth.map(|(usr, pwd)| usr + ":" + pwd.as_str()),
            socks_auth,
            dispatcher,
        })
    }

    pub async fn run(self) {
        tracing::info!(
            "[Mixed] Listen proxy at 127.0.0.1:{}, running...",
            self.port
        );
        while let Ok((socket, src_addr)) = self.server.accept().await {
            let disp = self.dispatcher.clone();
            let http_auth = self.http_auth.clone();
            let socks_auth = self.socks_auth.clone();
            tokio::spawn(Self::serve_connection(
                socket, http_auth, socks_auth, src_addr, disp,
            ));
        }
    }

    async fn serve_connection(
        mut socks_stream: TcpStream,
        http_auth: Option<String>,
        socks_auth: Option<(String, String)>,
        src_addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
    ) -> anyhow::Result<()> {
        let mut first_byte = [0u8; 1];
        socks_stream.read_exact(&mut first_byte).await?;
        const C_ASCII: u8 = b"C"[0];
        match first_byte[0] {
            4u8 => {
                tracing::warn!("Socks4 not supported");
            }
            5u8 => {
                Socks5Inbound::serve_connection(
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
