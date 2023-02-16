use crate::mitm::url_rewrite::{UrlModManager, UrlModType};
use crate::mitm::{HeaderModManager, Modifier, ModifierContext};
use crate::platform::process::ProcessInfo;
use crate::proxy::{DumpedRequest, DumpedResponse, HttpCapturer, NetworkAddr};
use anyhow::anyhow;
use async_trait::async_trait;
use dashmap::DashMap;
use http::{header, Request, Response, Version};
use hyper::Body;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

pub struct MitmModifier {
    client: Option<ProcessInfo>,
    contents: Arc<HttpCapturer>,
    url_rewriter: Arc<UrlModManager>,
    header_rewriter: Arc<HeaderModManager>,
    pending: DashMap<u64, DumpedRequest>,
}

impl MitmModifier {
    pub fn new(
        contents: Arc<HttpCapturer>,
        url_rewriter: Arc<UrlModManager>,
        header_rewriter: Arc<HeaderModManager>,
        proc: Option<ProcessInfo>,
    ) -> Self {
        Self {
            client: proc,
            contents,
            url_rewriter,
            header_rewriter,
            pending: Default::default(),
        }
    }
}

#[async_trait]
impl Modifier for MitmModifier {
    async fn modify_request(
        &self,
        req: Request<Body>,
        ctx: &ModifierContext,
    ) -> anyhow::Result<(Request<Body>, Option<Response<Body>>)> {
        let (parts, body) = req.into_parts();
        let whole_body = hyper::body::to_bytes(body).await?;
        let mut req_copy = DumpedRequest {
            uri: parts.uri.clone(),
            method: parts.method.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
            body: whole_body.clone(),
            time: Instant::now(),
        };
        let url = match parts.version {
            Version::HTTP_11 => {
                let prefix = if ctx.conn_info.read().await.dest.port() == 443 {
                    "https://"
                } else {
                    "http://"
                };
                match parts.headers.get(header::HOST) {
                    None => None,
                    Some(host) => match host.to_str() {
                        Ok(s) => Some(prefix.to_string() + s + parts.uri.to_string().as_str()),
                        Err(_) => None,
                    },
                }
            }
            Version::HTTP_2 => Some(parts.uri.to_string()),
            _ => None,
        };
        match url {
            None => {
                self.pending.insert(ctx.tag, req_copy);
                Ok((Request::from_parts(parts, Body::from(whole_body)), None))
            }
            Some(url) => {
                if let Ok(uri) = http::Uri::from_str(url.as_str()) {
                    req_copy.uri = uri;
                }
                if let Some((mod_type, new_url)) = self.url_rewriter.try_rewrite(url.as_str()).await
                {
                    // no real connection
                    let resp = match mod_type {
                        UrlModType::R404 => generate_404(&parts),
                        UrlModType::R301
                        | UrlModType::R302
                        | UrlModType::R307
                        | UrlModType::R308 => {
                            generate_redirect(&parts, mod_type, new_url.unwrap().as_str())
                        }
                    };
                    // record request and fake resp
                    let (resp_parts, body) = resp.into_parts();
                    let resp_body = hyper::body::to_bytes(body).await?;
                    let resp_copy = DumpedResponse {
                        status: resp_parts.status,
                        version: resp_parts.version,
                        headers: resp_parts.headers.clone(),
                        body: resp_body.clone(),
                        time: Instant::now(),
                    };
                    let host = match &ctx.conn_info.read().await.dest {
                        NetworkAddr::Raw(addr) => addr.ip().to_string(),
                        NetworkAddr::DomainName { domain_name, .. } => domain_name.clone(),
                    };
                    self.contents
                        .push((req_copy, resp_copy), host, self.client.clone());
                    Ok((
                        Request::from_parts(parts, Body::from(whole_body)),
                        Some(Response::from_parts(resp_parts, Body::from(resp_body))),
                    ))
                } else {
                    self.pending.insert(ctx.tag, req_copy);
                    Ok((Request::from_parts(parts, Body::from(whole_body)), None))
                }
            }
        }
    }

    async fn modify_response(
        &self,
        resp: Response<Body>,
        ctx: &ModifierContext,
    ) -> anyhow::Result<Response<Body>> {
        let (parts, body) = resp.into_parts();
        let whole_body = hyper::body::to_bytes(body).await?;
        // todo: optimize for large body
        let resp_copy = DumpedResponse {
            status: parts.status,
            version: parts.version,
            headers: parts.headers.clone(),
            body: whole_body.clone(),
            time: Instant::now(),
        };
        let req = self
            .pending
            .remove(&ctx.tag)
            .ok_or_else(|| anyhow!("no id"))?
            .1;
        let host = match &ctx.conn_info.read().await.dest {
            NetworkAddr::Raw(addr) => addr.ip().to_string(),
            NetworkAddr::DomainName { domain_name, .. } => domain_name.clone(),
        };
        self.contents
            .push((req, resp_copy), host, self.client.clone());
        Ok(Response::from_parts(parts, Body::from(whole_body)))
    }
}

fn generate_404(req_parts: &http::request::Parts) -> Response<Body> {
    let resp_builder = http::response::Builder::new();
    resp_builder
        .status(404)
        .version(req_parts.version)
        .header(header::CONNECTION, "close")
        .header(header::CONTENT_LENGTH, 0)
        .body(Body::empty())
        .unwrap()
}

fn generate_redirect(
    req_parts: &http::request::Parts,
    status: UrlModType,
    target_url: &str,
) -> Response<Body> {
    let status = match status {
        UrlModType::R301 => 301,
        UrlModType::R302 => 302,
        UrlModType::R307 => 307,
        UrlModType::R308 => 308,
        _ => unreachable!(),
    };
    let resp_builder = http::response::Builder::new();
    resp_builder
        .status(status)
        .version(req_parts.version)
        .header(header::CONNECTION, "close")
        .header(header::CONTENT_LENGTH, 0)
        .header(header::LOCATION, target_url)
        .body(Body::empty())
        .unwrap()
}
