use crate::adapter::Connector;
use crate::common::duplex_chan::DuplexChan;
use crate::dispatch::{InboundExtra, InboundInfo, InboundManager};
use crate::intercept::HyperBody;
use crate::proxy::error::TransportError;
use crate::proxy::{Dispatcher, NetworkAddr};
use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request, Response};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

pub struct HttpInbound {
    sock_addr: SocketAddr,
    server: TcpListener,
    inbound_mgr: Arc<InboundManager>,
    dispatcher: Arc<Dispatcher>,
}

impl HttpInbound {
    pub async fn new(
        sock_addr: SocketAddr,
        inbound_mgr: InboundManager,
        dispatcher: Arc<Dispatcher>,
    ) -> io::Result<Self> {
        let server = TcpListener::bind(sock_addr).await?;
        Ok(Self {
            sock_addr,
            server,
            inbound_mgr: Arc::new(inbound_mgr),
            dispatcher,
        })
    }

    pub async fn run(self) {
        tracing::info!("[HTTP] Listen proxy at {}, running...", self.sock_addr);
        const C_ASCII: u8 = b"C"[0];
        loop {
            match self.server.accept().await {
                Ok((socket, addr)) => {
                    let disp = self.dispatcher.clone();
                    let inbound_mgr = self.inbound_mgr.clone();
                    let mut first_char = [0u8; 1];
                    let _ = socket.peek(&mut first_char).await;
                    match first_char[0] {
                        C_ASCII => {
                            tokio::spawn(Self::serve_connection(socket, inbound_mgr, addr, disp));
                        }
                        _ => {
                            tokio::spawn(Self::serve_legacy_connection(
                                self.sock_addr.port(),
                                socket,
                                inbound_mgr,
                                addr,
                                disp,
                            ));
                        }
                    }
                }
                Err(err) => {
                    tracing::error!("HTTP inbound failed to accept: {}", err);
                    return;
                }
            }
        }
    }

    pub(super) async fn serve_connection(
        socket: TcpStream,
        mgr: Arc<InboundManager>,
        addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
    ) -> Result<(), TransportError> {
        // get response
        let mut buf_reader = BufReader::new(socket);
        let mut req = String::new();
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
        let mut req_struct = httparse::Request::new(buf.as_mut());
        req_struct
            .parse(req.as_bytes())
            .map_err(|_| TransportError::Http("Failed to parse request header"))?;
        if (req_struct.method == Some("CONNECT"))
            // HTTP/1.1
            && (req_struct.version == Some(1))
        {
            if let Some(Ok(dest)) = req_struct.path.map(|p| p.parse()) {
                let inbound_extra = if !mgr.has_auth() {
                    Some(mgr.default_extra())
                } else {
                    // let's verify the auth
                    let mut r = None;
                    for hdr in req_struct.headers.iter() {
                        if hdr.name.eq_ignore_ascii_case("proxy-authorization") {
                            let Ok(value) = std::str::from_utf8(hdr.value) else {
                                break;
                            };
                            r = validate_auth(Some(value), &mgr);
                            break;
                        }
                    }
                    r
                };
                if inbound_extra.is_none() {
                    socket.write_all(Self::response403().as_bytes()).await?;
                    return Err(TransportError::Http(
                        "Invalid CONNECT request: unauthorized",
                    ));
                }
                socket.write_all(Self::response200().as_bytes()).await?;
                let _ = dispatcher
                    .submit_tcp(
                        InboundInfo::Http(inbound_extra.unwrap()),
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

    pub(super) async fn serve_legacy_connection(
        self_port: u16,
        socket: TcpStream,
        auth: Arc<InboundManager>,
        src: SocketAddr,
        dispatcher: Arc<Dispatcher>,
    ) -> Result<(), TransportError> {
        let legacy_proxy = LegacyProxy {
            client: Arc::new(tokio::sync::Mutex::new(None)),
            auth,
            port: self_port,
            src,
            dispatcher,
        };

        let service = service_fn(move |req| legacy_proxy.clone().serve_connection(req));

        tokio::spawn(
            hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(TokioIo::new(socket), service),
        );
        Ok(())
    }

    const fn response403() -> &'static str {
        "HTTP/1.1 403 Forbidden\r\n\r\n"
    }

    const fn response200() -> &'static str {
        "HTTP/1.1 200 OK\r\n\r\n"
    }
}

#[derive(Clone)]
struct LegacyProxy {
    // Since we only support http/1.1 in legacy proxy, there is no concurrent request.
    client: Arc<tokio::sync::Mutex<Option<hyper::client::conn::http1::SendRequest<Incoming>>>>,
    auth: Arc<InboundManager>,
    port: u16,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
}

impl LegacyProxy {
    pub async fn serve_connection(
        self,
        mut req: Request<Incoming>,
    ) -> hyper::Result<Response<HyperBody>> {
        let conn_keep_alive = check_keep_alive(req.headers());
        let dest = match req.uri().authority() {
            Some(auth) => {
                let host = auth.host();
                let port = auth.port_u16().unwrap_or(80);
                NetworkAddr::DomainName {
                    domain_name: host.to_string(),
                    port,
                }
            }
            None => {
                return Ok(Response::builder()
                    .status(400)
                    .body(HyperBody::new(
                        http_body_util::Full::new(Bytes::new()).map_err(|e| match e {}),
                    ))
                    .unwrap());
            }
        };
        let Some(inbound_extra) = validate_auth(
            if let Some(value) = req.headers().get("Proxy-Authorization") {
                value.to_str().ok()
            } else {
                None
            },
            &self.auth,
        ) else {
            // Unauthorized
            return Ok(Response::builder()
                .status(403)
                .body(HyperBody::new(
                    http_body_util::Full::new(Bytes::new()).map_err(|e| match e {}),
                ))
                .unwrap());
        };
        clean_headers(req.headers_mut());
        set_keep_alive(req.headers_mut(), conn_keep_alive);
        let mut client_holder = self.client.lock().await;
        if client_holder.is_none() {
            let (left, right) = Connector::new_pair(10);
            let _ = self
                .dispatcher
                .submit_tcp(
                    InboundInfo::Http(inbound_extra),
                    self.src,
                    dest,
                    Arc::new(AtomicU8::new(2)),
                    DuplexChan::new(right),
                )
                .await;
            let (send_req, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(DuplexChan::new(left)))
                .await?;
            tokio::spawn(conn);
            *client_holder = Some(send_req);
        }
        let client = client_holder.as_mut().unwrap();
        let mut res = client.send_request(req).await?;
        drop(client_holder);
        let resp_keep_alive = conn_keep_alive && check_keep_alive(res.headers());
        clean_headers(res.headers_mut());
        set_keep_alive(res.headers_mut(), resp_keep_alive);
        Ok(res.map(BoxBody::new))
    }
}

// Return value:
//  - None: invalid
//  - Some(None): valid but empty auth
//  - Some(Some(user)): valid auth
fn validate_auth(auth: Option<&str>, server_auth: &InboundManager) -> Option<InboundExtra> {
    if !server_auth.has_auth() {
        return Some(server_auth.default_extra());
    } else if let Some(value) = auth {
        // manually split
        if value.is_ascii() && value.len() > 6 {
            let (left, right) = value.split_at(6);
            if left.eq_ignore_ascii_case("basic ") {
                let b64decoder = base64::engine::general_purpose::STANDARD;
                let code = b64decoder.decode(right).ok()?;
                let text = std::str::from_utf8(code.as_slice()).ok()?;
                let v: Vec<String> = text.split(':').map(|s| s.to_string()).collect();
                if v.len() == 2 {
                    if let Some(extra) =
                        server_auth.authenticate(v.first().unwrap(), v.get(1).unwrap())
                    {
                        return Some(extra);
                    }
                }
            }
        }
    }
    None
}

fn check_keep_alive(headers: &HeaderMap) -> bool {
    headers.get("Connection").is_some_and(|v| {
        v.to_str()
            .unwrap_or_default()
            .eq_ignore_ascii_case("keep-alive")
    }) || headers.get("Proxy-Connection").is_some_and(|v| {
        v.to_str()
            .unwrap_or_default()
            .eq_ignore_ascii_case("keep-alive")
    })
}

fn clean_headers(headers: &mut HeaderMap) {
    const HOP_BY_HOP_HEADERS: [&str; 10] = [
        "Keep-Alive",
        "Transfer-Encoding",
        "TE",
        "Connection",
        "Trailer",
        "Upgrade",
        "Proxy-Authorization",
        "Proxy-Authenticate",
        "Proxy-Connection", // Not standard, but many implementations do send this header
        "Connection",
    ];
    for key in HOP_BY_HOP_HEADERS.iter() {
        while headers.remove(*key).is_some() {}
    }
}

fn set_keep_alive(headers: &mut HeaderMap, keep_alive: bool) {
    if !keep_alive {
        headers.insert("Connection", HeaderValue::from_static("close"));
    }
}
