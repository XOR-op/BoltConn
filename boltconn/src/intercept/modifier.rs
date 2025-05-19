use crate::intercept::{HyperBody, InterceptionResult};
use crate::platform::process::ProcessInfo;
use crate::proxy::error::InterceptError;
use crate::proxy::{
    CapturedBody, ConnContext, DumpedRequest, DumpedResponse, HttpCapturer, NetworkAddr,
};
use async_trait::async_trait;
use dashmap::DashMap;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use std::sync::Arc;
use std::time::Instant;

pub type ModifierClosure =
    Box<dyn Fn(InterceptionResult, Option<ProcessInfo>) -> Arc<dyn Modifier> + Send + Sync>;

pub struct ModifierContext {
    pub tag: u64,
    pub conn_info: Arc<ConnContext>,
}

#[async_trait]
pub trait Modifier: Send + Sync {
    /// Return: new request and generated response, if any.
    async fn modify_request(
        &self,
        req: Request<HyperBody>,
        ctx: &ModifierContext,
    ) -> Result<(Request<HyperBody>, Option<Response<HyperBody>>), InterceptError>;
    async fn modify_response(
        &self,
        resp: Response<HyperBody>,
        ctx: &ModifierContext,
    ) -> Result<Response<HyperBody>, InterceptError>;
}

pub struct Recorder {
    client: Option<ProcessInfo>,
    contents: Arc<HttpCapturer>,
    pending: DashMap<u64, DumpedRequest>,
}

impl Recorder {
    pub fn new(contents: Arc<HttpCapturer>, proc: Option<ProcessInfo>) -> Self {
        Self {
            client: proc,
            contents,
            pending: Default::default(),
        }
    }
}

#[async_trait]
impl Modifier for Recorder {
    async fn modify_request(
        &self,
        req: Request<HyperBody>,
        ctx: &ModifierContext,
    ) -> Result<(Request<HyperBody>, Option<Response<HyperBody>>), InterceptError> {
        let (parts, body) = req.into_parts();
        let whole_body = body
            .collect()
            .await
            .map_err(InterceptError::WaitResponse)?
            .to_bytes();
        let req_copy = DumpedRequest {
            uri: parts.uri.clone(),
            method: parts.method.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
            body: CapturedBody::FullCapture(whole_body.clone()),
            time: Instant::now(),
        };
        self.pending.insert(ctx.tag, req_copy);
        Ok((
            Request::from_parts(
                parts,
                HyperBody::new(http_body_util::Full::new(whole_body).map_err(|e| match e {})),
            ),
            None,
        ))
    }

    async fn modify_response(
        &self,
        resp: Response<HyperBody>,
        ctx: &ModifierContext,
    ) -> Result<Response<HyperBody>, InterceptError> {
        let (parts, body) = resp.into_parts();
        let whole_body = body
            .collect()
            .await
            .map_err(InterceptError::WaitResponse)?
            .to_bytes();
        let resp_copy = DumpedResponse {
            status: parts.status,
            version: parts.version,
            headers: parts.headers.clone(),
            body: CapturedBody::FullCapture(whole_body.clone()),
            time: Instant::now(),
        };
        let req = self
            .pending
            .remove(&ctx.tag)
            .ok_or_else(|| InterceptError::NoCorrespondingId(ctx.tag))?
            .1;
        let host = match &ctx.conn_info.conn_info.dst {
            NetworkAddr::Raw(addr) => addr.ip().to_string(),
            NetworkAddr::DomainName { domain_name, .. } => domain_name.clone(),
        };
        self.contents
            .push((req, resp_copy), host, self.client.clone());
        Ok(Response::from_parts(
            parts,
            HyperBody::new(http_body_util::Full::new(whole_body).map_err(|e| match e {})),
        ))
    }
}
