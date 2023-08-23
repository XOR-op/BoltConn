use crate::intercept::url_rewrite::UrlModType;
use crate::intercept::{InterceptionResult, Modifier, ModifierContext};
use crate::platform::process::ProcessInfo;
use crate::proxy::{BodyOrWarning, DumpedRequest, DumpedResponse, HttpCapturer, NetworkAddr};
use anyhow::anyhow;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use http::{header, Request, Response, Version};
use hyper::body::HttpBody;
use hyper::Body;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

enum ReadData {
    Full(Bytes),
    Partial(Bytes, Body),
}

struct PartialReadStream {
    has_read: Option<Bytes>,
    inner_body: Body,
}

impl futures::Stream for PartialReadStream {
    type Item = Result<Bytes, hyper::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(data) = self.has_read.take() {
            Poll::Ready(Some(Ok(data)))
        } else {
            Pin::new(&mut self.inner_body).poll_data(cx)
        }
    }
}

pub struct InterceptModifier {
    client: Option<ProcessInfo>,
    contents: Arc<HttpCapturer>,
    result: InterceptionResult,
    pending: DashMap<u64, DumpedRequest>,
    size_limit: usize,
}

impl InterceptModifier {
    pub fn new(
        contents: Arc<HttpCapturer>,
        result: InterceptionResult,
        proc: Option<ProcessInfo>,
    ) -> Self {
        Self {
            client: proc,
            contents,
            result,
            pending: Default::default(),
            size_limit: 2 * 1024 * 1024,
        }
    }

    // From hyper::body::to_bytes, with some modifications
    async fn read_at_most(mut body: Body, size_limit: usize) -> anyhow::Result<ReadData> {
        // If there's only 1 chunk, we can just return Buf::to_bytes()
        let mut first = if let Some(buf) = body.data().await {
            buf?
        } else {
            return Ok(ReadData::Full(Bytes::new()));
        };

        // check size
        if first.len() > size_limit {
            return Ok(ReadData::Partial(
                first.copy_to_bytes(first.remaining()),
                body,
            ));
        }

        let second = if let Some(buf) = body.data().await {
            buf?
        } else {
            return Ok(ReadData::Full(first.copy_to_bytes(first.remaining())));
        };

        // Don't pre-emptively reserve *too* much.
        let rest = (body.size_hint().lower() as usize).min(1024 * 16);
        let cap = first
            .remaining()
            .saturating_add(second.remaining())
            .saturating_add(rest);
        // With more than 1 buf, we gotta flatten into a Vec first.
        let mut vec = BytesMut::with_capacity(cap);
        vec.put(first);
        vec.put(second);

        loop {
            if vec.len() > size_limit {
                return Ok(ReadData::Partial(vec.freeze(), body));
            }
            if let Some(buf) = body.data().await {
                vec.put(buf?);
            } else {
                break;
            }
        }

        Ok(ReadData::Full(vec.freeze()))
    }
}

#[async_trait]
impl Modifier for InterceptModifier {
    async fn modify_request(
        &self,
        req: Request<Body>,
        ctx: &ModifierContext,
    ) -> anyhow::Result<(Request<Body>, Option<Response<Body>>)> {
        let (mut parts, body) = req.into_parts();
        let whole_body = hyper::body::to_bytes(body).await?;

        let url = match parts.version {
            Version::HTTP_11 => {
                let prefix = if ctx.conn_info.dest.port() == 443 {
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
                let req_copy = DumpedRequest::from_parts(&parts, &whole_body);
                self.pending.insert(ctx.tag, req_copy);
                Ok((Request::from_parts(parts, Body::from(whole_body)), None))
            }
            Some(url) => {
                for mgr in self.result.each_payload().map(|(_, hdr)| hdr) {
                    mgr.try_rewrite_request(url.as_str(), &mut parts.headers)
                        .await;
                }

                // re-generate CONTENT-LENGTH by hyper
                parts.headers.remove(header::CONTENT_LENGTH);

                for mgr in self.result.each_payload().map(|(url, _)| url) {
                    if let Some((mod_type, new_url)) = mgr.try_rewrite(url.as_str()).await {
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

                        if self.result.should_capture() {
                            let resp_copy = DumpedResponse {
                                status: resp_parts.status,
                                version: resp_parts.version,
                                headers: resp_parts.headers.clone(),
                                body: BodyOrWarning::Body(resp_body.clone()),
                                time: Instant::now(),
                            };
                            let host = match &ctx.conn_info.dest {
                                NetworkAddr::Raw(addr) => addr.ip().to_string(),
                                NetworkAddr::DomainName { domain_name, .. } => domain_name.clone(),
                            };
                            // store copy
                            let mut req_copy = DumpedRequest::from_parts(&parts, &whole_body);
                            if let Ok(uri) = http::Uri::from_str(url.as_str()) {
                                req_copy.uri = uri;
                            }
                            self.contents
                                .push((req_copy, resp_copy), host, self.client.clone());
                        }
                        return Ok((
                            Request::from_parts(parts, Body::from(whole_body)),
                            Some(Response::from_parts(resp_parts, Body::from(resp_body))),
                        ));
                    }
                }

                // no fake response, just send plainly
                let req_copy = DumpedRequest::from_parts(&parts, &whole_body);
                self.pending.insert(ctx.tag, req_copy);
                Ok((Request::from_parts(parts, Body::from(whole_body)), None))
            }
        }
    }

    async fn modify_response(
        &self,
        resp: Response<Body>,
        ctx: &ModifierContext,
    ) -> anyhow::Result<Response<Body>> {
        let (mut parts, body) = resp.into_parts();
        let req = self
            .pending
            .remove(&ctx.tag)
            .ok_or_else(|| anyhow!("no id"))?
            .1;

        for mgr in self.result.each_payload().map(|(_, hdr)| hdr) {
            mgr.try_rewrite_response(req.uri.to_string().as_str(), &mut parts.headers)
                .await;
        }
        let host = match &ctx.conn_info.dest {
            NetworkAddr::Raw(addr) => addr.ip().to_string(),
            NetworkAddr::DomainName { domain_name, .. } => domain_name.clone(),
        };
        // For large body, we skip the manipulation
        match Self::read_at_most(body, self.size_limit).await? {
            ReadData::Full(whole_body) => {
                if self.result.should_capture() {
                    let resp_copy =
                        DumpedResponse::from_parts(&parts, BodyOrWarning::Body(whole_body.clone()));
                    self.contents
                        .push((req, resp_copy), host, self.client.clone());
                }
                Ok(Response::from_parts(parts, Body::from(whole_body)))
            }
            ReadData::Partial(partial_body, remaining) => {
                let stream = PartialReadStream {
                    has_read: Some(partial_body),
                    inner_body: remaining,
                };
                if self.result.should_capture() {
                    let warning =
                        format!("Too large data: exceeded limit {} bytes", self.size_limit);
                    let stored_resp =
                        DumpedResponse::from_parts(&parts, BodyOrWarning::Warning(warning));
                    self.contents
                        .push((req, stored_resp), host, self.client.clone());
                }
                Ok(Response::from_parts(parts, Body::wrap_stream(stream)))
            }
        }
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
