use bytes::Bytes;
use http::{HeaderMap, HeaderName};
use regex::Regex;
use rquickjs::class::Trace;
use rquickjs::{Class, Context, Ctx, FromJs, IntoJs, Object, Runtime, Value};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::Read;

#[derive(Debug, Clone)]
struct HttpData {
    url: String,
    method: String,
    status: Option<u16>,
    header: HashMap<String, String>,
    body: Option<String>,
}

impl<'js> FromJs<'js> for HttpData {
    fn from_js(_ctx: &Ctx<'js>, value: Value<'js>) -> rquickjs::Result<Self> {
        if let Some(obj) = value.clone().into_object() {
            let url = obj.get("url")?;
            let method = obj.get("method")?;
            let status = obj.get("status").ok();
            let header = obj.get("header")?;
            let body = obj.get("body").ok();
            Ok(HttpData {
                url,
                method,
                status,
                header,
                body,
            })
        } else {
            Err(rquickjs::Error::FromJs {
                from: value.type_of().as_str(),
                to: "HttpData",
                message: None,
            })
        }
    }
}

impl<'js> IntoJs<'js> for HttpData {
    fn into_js(self, ctx: &Ctx<'js>) -> rquickjs::Result<Value<'js>> {
        let obj = Object::new(ctx.clone())?;
        obj.set("url", self.url)?;
        obj.set("method", self.method)?;
        if let Some(s) = self.status {
            obj.set("status", s)?;
        }
        obj.set("header", self.header)?;
        if let Some(b) = self.body {
            obj.set("body", b)?;
        }
        Ok(obj.into())
    }
}

#[derive(Debug, Clone)]
enum ScriptType {
    Req,
    Resp,
    All,
}

#[derive(Debug)]
pub struct ScriptEngine {
    name: Option<String>,
    script_type: ScriptType,
    pattern: Option<Regex>,
    script: String,
}

impl ScriptEngine {
    pub fn new(
        name: Option<&str>,
        script_type: &str,
        pattern: Option<&str>,
        script: &str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            name: name.map(|s| s.to_string()),
            script_type: match script_type.to_ascii_lowercase().as_str() {
                "req" => ScriptType::Req,
                "resp" => ScriptType::Resp,
                "all" => ScriptType::All,
                s => return Err(anyhow::anyhow!("Invalid script type: {}", s)),
            },
            pattern: pattern.map(Regex::new).transpose()?,
            script: script.to_string(),
        })
    }

    fn run_js(
        &self,
        url: &str,
        data: Option<Bytes>,
        method: String,
        status: Option<u16>,
        headers: &HeaderMap,
        field: &str,
    ) -> Option<(Option<u16>, HeaderMap, Option<Bytes>)> {
        let runtime = Runtime::new().ok()?;
        let ctx = Context::full(&runtime).ok()?;
        let header = {
            let mut header = HashMap::new();
            for (k, v) in headers.iter() {
                let key = k.to_string();
                match header.entry(key) {
                    Entry::Vacant(e) => {
                        e.insert(v.to_str().ok()?.to_string());
                    }
                    Entry::Occupied(mut e) => e
                        .get_mut()
                        .push_str(format!(", {}", v.to_str().ok()?).as_str()),
                };
            }
            header
        };
        // decompress
        let body = if let Some(compress) = header.get("content-encoding") {
            data.and_then(|d| {
                let mut v = vec![];
                match compress.as_str() {
                    "gzip" => {
                        flate2::read::GzDecoder::new(d.as_ref())
                            .read_to_end(&mut v)
                            .ok()?;
                    }
                    "deflate" => {
                        flate2::read::DeflateDecoder::new(d.as_ref())
                            .read_to_end(&mut v)
                            .ok()?;
                    }
                    "br" => {
                        brotli::Decompressor::new(d.as_ref(), d.len())
                            .read_to_end(&mut v)
                            .ok()?;
                    }
                    _ => None?,
                }
                String::from_utf8(v).ok()
            })
        } else {
            data.and_then(|d| String::from_utf8(d.to_vec()).ok())
        };
        let js_data = HttpData {
            url: url.to_string(),
            method,
            header,
            status,
            body,
        };
        let eval_result = ctx.with(|ctx| -> Result<HttpData, rquickjs::Error> {
            // init console
            let cls = Class::instance(
                ctx.clone(),
                Console {
                    id: self.name.clone().unwrap_or_else(|| "DEFAULT".to_string()),
                },
            )?;
            ctx.globals().set("console", cls)?;

            // init data
            ctx.globals().set(field, js_data)?;

            match ctx.eval::<HttpData, _>(self.script.as_bytes()) {
                Ok(v) => Ok(v),
                Err(e) => {
                    if matches!(e, rquickjs::Error::Exception) {
                        let v = ctx.catch();
                        if v.type_of() == rquickjs::Type::Exception {
                            let v = v.as_exception().unwrap();
                            tracing::debug!(
                                "Script {} exception: {} {}",
                                self.name
                                    .clone()
                                    .map_or_else(String::default, |n| format!("\"{}\"", n)),
                                v.message().unwrap_or_else(|| "MISSING MSG".to_string()),
                                v.line()
                                    .map_or_else(String::default, |l| format!("in line {}", l))
                            );
                        }
                    }
                    Err(e)
                }
            }
        });
        let r = match eval_result {
            Err(e) => {
                tracing::warn!(
                    "Failed to run script {} for {}: {}",
                    self.name
                        .clone()
                        .map_or("".to_string(), |s| format!("\"{}\"", s)),
                    url,
                    e
                );
                return None;
            }
            Ok(r) => r,
        };
        // replace header
        let mut header = HeaderMap::new();
        for (k, v) in r.header {
            header.insert(HeaderName::from_bytes(k.as_bytes()).ok()?, v.parse().ok()?);
        }
        // recompress
        let body = if let Some(compress) = header.get("content-encoding") {
            r.body.and_then(|d| {
                let mut buf = vec![];
                match compress.to_str().ok()? {
                    "gzip" => {
                        let r =
                            flate2::read::GzEncoder::new(d.as_bytes(), flate2::Compression::none())
                                .read_to_end(&mut buf);
                        r.ok()?;
                    }
                    "deflate" => {
                        flate2::read::DeflateEncoder::new(
                            d.as_bytes(),
                            flate2::Compression::none(),
                        )
                        .read_to_end(&mut buf)
                        .ok()?;
                    }
                    "br" => {
                        brotli::CompressorReader::new(d.as_bytes(), d.as_bytes().len(), 0, 22)
                            .read_to_end(&mut buf)
                            .ok()?;
                    }
                    _ => None?,
                };
                Some(Bytes::from(buf))
            })
        } else {
            r.body.map(Bytes::from)
        };
        Some((r.status, header, body))
    }

    pub fn try_rewrite_req(
        &self,
        url: &str,
        parts: &mut http::request::Parts,
        data: Option<Bytes>,
    ) -> Option<Bytes> {
        if self.pattern.as_ref().map_or(true, |s| s.is_match(url)) {
            match self.script_type {
                ScriptType::Req | ScriptType::All => {
                    let method = parts.method.to_string();
                    let header = &parts.headers;
                    let (_, header, body) =
                        self.run_js(url, data, method, None, header, "$request")?;
                    parts.headers = header;
                    body.map(Bytes::from)
                }
                ScriptType::Resp => None,
            }
        } else {
            None
        }
    }

    pub fn try_rewrite_resp(
        &self,
        url: &str,
        method: &http::Method,
        parts: &mut http::response::Parts,
        data: Option<Bytes>,
    ) -> Option<Bytes> {
        if self.pattern.as_ref().map_or(true, |s| s.is_match(url)) {
            match self.script_type {
                ScriptType::Req => None,
                ScriptType::Resp | ScriptType::All => {
                    let header = &parts.headers;
                    let (status, header, body) = self.run_js(
                        url,
                        data,
                        method.to_string(),
                        Some(parts.status.as_u16()),
                        header,
                        "$response",
                    )?;
                    if let Some(status) = status.and_then(|s| http::StatusCode::from_u16(s).ok()) {
                        parts.status = status;
                    }
                    parts.headers = header;
                    body.map(Bytes::from)
                }
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Trace)]
#[rquickjs::class]
struct Console {
    id: String,
}

#[rquickjs::methods]
impl Console {
    pub fn log(&self, str: String) {
        tracing::info!("[js:{}]:{}", self.id, str);
    }
}

mod test {
    #[test]
    #[tracing_test::traced_test]
    fn test_req() {
        use crate::intercept::ScriptEngine;
        tracing::debug!("Started");
        let name = "test-req".to_string();
        let engine = ScriptEngine::new(
            Some(&name),
            "req",
            Some("https://www.google.com"),
            "\
        console.log('user-agent is '+$request.header['user-agent']);
        $request.header['user-agent'] = 'curl/1.2.3';
        $request.header['test'] = 'aaaa';
        $request.status = 502;
        console.log(JSON.stringify($request));
        $request
        ",
        )
        .unwrap();
        let mut hdr = http::HeaderMap::new();
        hdr.insert("user-agent", "Mozilla/5.0 Safari/16.1.0".parse().unwrap());
        let (_, hdr, _) = engine
            .run_js(
                "https://www.google.com",
                None,
                "post".to_string(),
                None,
                &hdr,
                "$request",
            )
            .unwrap();
        assert_eq!(hdr.get("user-agent").unwrap(), &"curl/1.2.3");
    }
}
