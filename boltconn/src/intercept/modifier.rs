use crate::intercept::InterceptionResult;
use crate::platform::process::ProcessInfo;
use crate::proxy::{
    CapturedBody, ConnContext, DumpedRequest, DumpedResponse, HttpCapturer, NetworkAddr,
};
use anyhow::anyhow;
use async_trait::async_trait;
use dashmap::DashMap;
use hyper::{Body, Request, Response};
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
        req: Request<Body>,
        ctx: &ModifierContext,
    ) -> anyhow::Result<(Request<Body>, Option<Response<Body>>)>;
    async fn modify_response(
        &self,
        resp: Response<Body>,
        ctx: &ModifierContext,
    ) -> anyhow::Result<Response<Body>>;
}

#[derive(Default)]
pub struct Logger;

#[async_trait]
impl Modifier for Logger {
    async fn modify_request(
        &self,
        req: Request<Body>,
        _ctx: &ModifierContext,
    ) -> anyhow::Result<(Request<Body>, Option<Response<Body>>)> {
        println!("{:?}", req);
        Ok((req, None))
    }

    async fn modify_response(
        &self,
        resp: Response<Body>,
        _ctx: &ModifierContext,
    ) -> anyhow::Result<Response<Body>> {
        println!("{:?}", resp);
        Ok(resp)
    }
}

#[derive(Default)]
pub struct Nooper;

#[async_trait]
impl Modifier for Nooper {
    async fn modify_request(
        &self,
        req: Request<Body>,
        _ctx: &ModifierContext,
    ) -> anyhow::Result<(Request<Body>, Option<Response<Body>>)> {
        Ok((req, None))
    }

    async fn modify_response(
        &self,
        resp: Response<Body>,
        _ctx: &ModifierContext,
    ) -> anyhow::Result<Response<Body>> {
        Ok(resp)
    }
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
        req: Request<Body>,
        ctx: &ModifierContext,
    ) -> anyhow::Result<(Request<Body>, Option<Response<Body>>)> {
        let (parts, body) = req.into_parts();
        let whole_body = hyper::body::to_bytes(body).await?;
        let req_copy = DumpedRequest {
            uri: parts.uri.clone(),
            method: parts.method.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
            body: CapturedBody::FullCapture(whole_body.clone()),
            time: Instant::now(),
        };
        self.pending.insert(ctx.tag, req_copy);
        Ok((Request::from_parts(parts, Body::from(whole_body)), None))
    }

    async fn modify_response(
        &self,
        resp: Response<Body>,
        ctx: &ModifierContext,
    ) -> anyhow::Result<Response<Body>> {
        let (parts, body) = resp.into_parts();
        let whole_body = hyper::body::to_bytes(body).await?;
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
            .ok_or_else(|| anyhow!("no id"))?
            .1;
        let host = match &ctx.conn_info.dest {
            NetworkAddr::Raw(addr) => addr.ip().to_string(),
            NetworkAddr::DomainName { domain_name, .. } => domain_name.clone(),
        };
        self.contents
            .push((req, resp_copy), host, self.client.clone());
        Ok(Response::from_parts(parts, Body::from(whole_body)))
    }
}
