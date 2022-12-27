use crate::adapter::TcpOutBound;
use crate::common::duplex_chan::DuplexChan;
use crate::common::id_gen::IdGenerator;
use crate::proxy::ConnAgent;
use crate::sniff::modifier::Modifier;
use crate::sniff::ModifierContext;
use hyper::client::conn;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::io;
use std::sync::{Arc, RwLock};

pub struct HttpSniffer {
    inbound: DuplexChan,
    modifier: Arc<dyn Modifier>,
    creator: Box<dyn TcpOutBound>,
    conn_info: Arc<RwLock<ConnAgent>>,
}

impl HttpSniffer {
    pub fn new(
        inbound: DuplexChan,
        modifier: Arc<dyn Modifier>,
        creator: Box<dyn TcpOutBound>,
        conn_info: Arc<RwLock<ConnAgent>>,
    ) -> Self {
        Self {
            inbound,
            modifier,
            creator,
            conn_info,
        }
    }

    async fn proxy(
        outbound: DuplexChan,
        modifier: Arc<dyn Modifier>,
        req: Request<Body>,
        ctx: ModifierContext,
    ) -> anyhow::Result<Response<Body>> {
        let (mut sender, connection) = conn::Builder::new().handshake(outbound).await?;
        let req = modifier.modify_request(req, &ctx).await?;
        tokio::spawn(async move { connection.await });
        let resp = sender.send_request(req).await?;
        let resp = modifier.modify_response(resp, &ctx).await?;
        Ok(resp)
    }

    pub async fn run(self) -> io::Result<()> {
        let id_gen = IdGenerator::default();
        let service = service_fn(|req| {
            let (conn, _handle) = self.creator.spawn_tcp_with_chan();
            Self::proxy(
                conn,
                self.modifier.clone(),
                req,
                ModifierContext {
                    tag: id_gen.get(),
                    conn_info: self.conn_info.clone(),
                },
            )
        });
        if let Err(http_err) = Http::new().serve_connection(self.inbound, service).await {
            tracing::warn!("Sniff err {}", http_err);
        }
        Ok(())
    }
}
