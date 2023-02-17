use crate::proxy::Dispatcher;
use anyhow::anyhow;
use httparse::Request;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

pub struct HttpInbound {
    server: TcpListener,
    auth: Option<(String, String)>,
    dispatcher: Arc<Dispatcher>,
}

impl HttpInbound {
    pub async fn new(
        port: u16,
        auth: Option<(String, String)>,
        dispatcher: Arc<Dispatcher>,
    ) -> io::Result<Self> {
        let server =
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)).await?;
        Ok(Self {
            server,
            auth,
            dispatcher,
        })
    }

    pub async fn run(self) {
        while let Ok((socket, addr)) = self.server.accept().await {
            let disp = self.dispatcher.clone();
            tokio::spawn(Self::serve_connection(socket, addr, disp));
        }
    }

    async fn serve_connection(
        socket: TcpStream,
        addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
    ) -> anyhow::Result<()> {
        // get response
        let mut buf_reader = BufReader::new(socket);
        let mut req = String::new();
        while !req.ends_with("\r\n\r\n") {
            if buf_reader.read_line(&mut req).await? == 0 {
                return Err(anyhow!("EOF"));
            }
            if req.len() > 4096 {
                return Err(anyhow!("Too long resp"));
            }
        }
        let mut socket = buf_reader.into_inner();
        let mut buf = [httparse::EMPTY_HEADER; 1];
        let mut req_struct = Request::new(buf.as_mut());
        req_struct.parse(req.as_bytes())?;
        if req_struct.method.map_or(false, |m| m == "CONNECT")
            // HTTP/1.1
            && req_struct.version.map_or(false, |v| v == 1)
        {
            if let Some(path) = req_struct.path {
                if let Ok(dest) = path.parse() {
                    socket.write_all(Self::response200().as_bytes()).await?;
                    dispatcher
                        .submit_tun_tcp(addr, dest, Arc::new(AtomicU8::new(2)), socket)
                        .await;
                    return Ok(());
                }
            }
        }
        socket.write_all(Self::response403().as_bytes()).await?;
        Err(anyhow!("Invalid CONNECT request"))
    }

    const fn response403() -> &'static str {
        "HTTP/1.1 403 Forbidden\r\n\r\n"
    }

    const fn response200() -> &'static str {
        "HTTP/1.1 200 OK\r\n\r\n"
    }
}
