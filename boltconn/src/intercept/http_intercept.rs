use crate::adapter::{Connector, Outbound};
use crate::common::duplex_chan::DuplexChan;
use crate::common::id_gen::IdGenerator;
use crate::intercept::modifier::Modifier;
use crate::intercept::ModifierContext;
use crate::proxy::{ConnAbortHandle, ConnContext};
use hyper::client::conn;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::io;
use std::sync::Arc;

pub struct HttpIntercept {
    inbound: DuplexChan,
    modifier: Arc<dyn Modifier>,
    creator: Arc<dyn Outbound>,
    conn_info: Arc<ConnContext>,
}

impl HttpIntercept {
    pub fn new(
        inbound: DuplexChan,
        modifier: Arc<dyn Modifier>,
        creator: Box<dyn Outbound>,
        conn_info: Arc<ConnContext>,
    ) -> Self {
        Self {
            inbound,
            modifier,
            creator: Arc::from(creator),
            conn_info,
        }
    }

    async fn proxy(
        creator: Arc<dyn Outbound>,
        modifier: Arc<dyn Modifier>,
        req: Request<Body>,
        ctx: ModifierContext,
    ) -> anyhow::Result<Response<Body>> {
        let abort_handle = ConnAbortHandle::new();
        abort_handle.fulfill(vec![]).await;
        let (req, fake_resp) = modifier.modify_request(req, &ctx).await?;
        if let Some(resp) = fake_resp {
            return Ok(resp);
        }
        let (inbound, outbound) = Connector::new_pair(10);
        let _handle = creator.spawn_tcp(inbound, abort_handle.clone());
        let (mut sender, connection) = conn::Builder::new()
            .handshake(DuplexChan::new(outbound))
            .await?;
        tokio::spawn(async move { connection.await });
        let resp = sender.send_request(req).await?;
        let resp = modifier.modify_response(resp, &ctx).await?;
        Ok(resp)
    }

    pub async fn run(self) -> io::Result<()> {
        let id_gen = IdGenerator::default();
        let service = service_fn(|req| {
            Self::proxy(
                self.creator.clone(),
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
