use crate::dispatch::{InboundIdentity, InboundInfo};
use crate::proxy::error::TransportError;
use crate::proxy::Dispatcher;
use base64::Engine;
use httparse::Request;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

pub struct HttpInbound {
    sock_addr: SocketAddr,
    server: TcpListener,
    auth: Arc<HashMap<String, String>>,
    dispatcher: Arc<Dispatcher>,
}

impl HttpInbound {
    pub async fn new(
        sock_addr: SocketAddr,
        auth: HashMap<String, String>,
        dispatcher: Arc<Dispatcher>,
    ) -> io::Result<Self> {
        let server = TcpListener::bind(sock_addr).await?;
        Ok(Self {
            sock_addr,
            server,
            auth: Arc::new(auth),
            dispatcher,
        })
    }

    pub async fn run(self) {
        tracing::info!("[HTTP] Listen proxy at {}, running...", self.sock_addr);
        loop {
            match self.server.accept().await {
                Ok((socket, addr)) => {
                    let disp = self.dispatcher.clone();
                    let auth = self.auth.clone();
                    tokio::spawn(Self::serve_connection(
                        self.sock_addr.port(),
                        socket,
                        auth,
                        addr,
                        disp,
                        None,
                    ));
                }
                Err(err) => {
                    tracing::error!("HTTP inbound failed to accept: {}", err);
                    return;
                }
            }
        }
    }

    pub(super) async fn serve_connection(
        self_port: u16,
        socket: TcpStream,
        auth: Arc<HashMap<String, String>>,
        addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
        first_byte: Option<String>,
    ) -> Result<(), TransportError> {
        // get response
        let mut buf_reader = BufReader::new(socket);
        let mut req = first_byte.unwrap_or_default();
        while !req.ends_with("\r\n\r\n") {
            if buf_reader.read_line(&mut req).await? == 0 {
                return Err(TransportError::Http("Connecting: EOF"));
            }
            if req.len() > 4096 {
                return Err(TransportError::Http("Connecting: response too long"));
            }
        }
        let mut socket = buf_reader.into_inner();
        let mut buf = [httparse::EMPTY_HEADER; 16];
        let mut req_struct = Request::new(buf.as_mut());
        req_struct
            .parse(req.as_bytes())
            .map_err(|_| TransportError::Http("Failed to parse request header"))?;
        if req_struct.method.map_or(false, |m| m == "CONNECT")
            // HTTP/1.1
            && req_struct.version.map_or(false, |v| v == 1)
        {
            if let Some(Ok(dest)) = req_struct.path.map(|p| p.parse()) {
                // None: invalid
                // Some(None): valid but empty auth
                let authorized = if auth.is_empty() {
                    Some(None)
                } else {
                    // let's verify the auth
                    let mut r = None;
                    for hdr in req_struct.headers.iter() {
                        if hdr.name.eq_ignore_ascii_case("proxy-authorization") {
                            let Ok(value) = std::str::from_utf8(hdr.value) else {
                                break;
                            };
                            // manually split
                            if value.is_ascii() && value.len() > 6 {
                                let (left, right) = value.split_at(6);
                                if left.eq_ignore_ascii_case("basic ") {
                                    let b64decoder = base64::engine::general_purpose::STANDARD;
                                    let code = b64decoder.decode(right).map_err(|_| {
                                        TransportError::Http("bad authorization encoding")
                                    })?;
                                    let text =
                                        std::str::from_utf8(code.as_slice()).map_err(|_| {
                                            TransportError::Http("bad authorization utf-8")
                                        })?;
                                    let v: Vec<String> =
                                        text.split(':').map(|s| s.to_string()).collect();
                                    if v.len() == 2
                                        && auth
                                            .get(v.first().unwrap())
                                            .is_some_and(|pwd| pwd == v.get(1).unwrap())
                                    {
                                        r = Some(Some(v.first().unwrap().clone()));
                                    } else {
                                        r = None;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    r
                };
                if authorized.is_none() {
                    socket.write_all(Self::response403().as_bytes()).await?;
                    return Err(TransportError::Http(
                        "Invalid CONNECT request: unauthorized",
                    ));
                }
                socket.write_all(Self::response200().as_bytes()).await?;
                let _ = dispatcher
                    .submit_tcp(
                        InboundInfo::Http(InboundIdentity {
                            user: authorized.unwrap(),
                            port: Some(self_port),
                        }),
                        addr,
                        dest,
                        Arc::new(AtomicU8::new(2)),
                        socket,
                    )
                    .await;
                return Ok(());
            }
        }
        socket.write_all(Self::response403().as_bytes()).await?;
        Err(TransportError::Http("Invalid CONNECT request"))
    }

    const fn response403() -> &'static str {
        "HTTP/1.1 403 Forbidden\r\n\r\n"
    }

    const fn response200() -> &'static str {
        "HTTP/1.1 200 OK\r\n\r\n"
    }
}
