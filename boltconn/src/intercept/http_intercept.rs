use crate::adapter::{Connector, Outbound};
use crate::common::duplex_chan::DuplexChan;
use crate::common::utils::IdGenerator;
use crate::intercept::modifier::Modifier;
use crate::intercept::{HyperBody, ModifierContext};
use crate::proxy::error::InterceptError;
use crate::proxy::{ConnAbortHandle, ConnContext};
use hyper::client::conn;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
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
        req: Request<HyperBody>,
        ctx: ModifierContext,
    ) -> Result<Response<HyperBody>, InterceptError> {
        let (req, fake_resp) = modifier.modify_request(req, &ctx).await?;
        if let Some(resp) = fake_resp {
            return Ok(resp);
        }
        let (inbound, outbound) = Connector::new_pair(10);
        let _handle = creator.spawn_tcp(inbound, ConnAbortHandle::placeholder());
        let (mut sender, connection) = conn::http1::Builder::new()
            .handshake(TokioIo::new(DuplexChan::new(outbound)))
            .await
            .map_err(InterceptError::Handshake)?;
        tokio::spawn(connection);
        let (parts, resp_body) = sender
            .send_request(req)
            .await
            .map_err(InterceptError::SendRequest)?
            .into_parts();
        let resp = modifier
            .modify_response(Response::from_parts(parts, HyperBody::new(resp_body)), &ctx)
            .await?;
        Ok(resp)
    }

    pub async fn run(self) -> io::Result<()> {
        let id_gen = IdGenerator::default();
        let service = service_fn(|req| {
            let (parts, body) = req.into_parts();
            Self::proxy(
                self.creator.clone(),
                self.modifier.clone(),
                Request::from_parts(parts, HyperBody::new(body)),
                ModifierContext {
                    tag: id_gen.get(),
                    conn_info: self.conn_info.clone(),
                },
            )
        });
        if let Err(http_err) = hyper::server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(TokioIo::new(self.inbound), service)
            .await
        {
            tracing::warn!("Sniff err {}", http_err);
        }
        Ok(())
    }
}
