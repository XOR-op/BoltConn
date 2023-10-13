use bytes::Bytes;
use http::{HeaderMap, HeaderName};
use regex::Regex;
use rquickjs::class::{Trace, Tracer};
use rquickjs::{Class, Context, Object, Runtime};
use std::collections::hash_map::Entry;
use std::collections::HashMap;

#[derive(Debug, Clone)]
#[rquickjs::class]
struct HttpData {
    #[qjs(get, set)]
    url: String,
    #[qjs(get, set)]
    method: String,
    #[qjs(get, set)]
    header: HashMap<String, String>,
    #[qjs(get, set)]
    body: Option<String>,
}

impl<'js> Trace<'js> for HttpData {
    fn trace<'a>(&self, tracer: Tracer<'a, 'js>) {
        self.url.trace(tracer);
        self.method.trace(tracer);
        self.header.trace(tracer);
        if let Some(body) = &self.body {
            body.trace(tracer)
        }
    }
}

#[derive(Debug)]
pub struct ScriptEngine {
    name: Option<String>,
    pattern: Regex,
    script: String,
}

impl ScriptEngine {
    pub fn new(name: Option<&String>, pattern: &str, script: &str) -> anyhow::Result<Self> {
        Ok(Self {
            name: name.cloned(),
            pattern: Regex::new(pattern)?,
            script: script.to_string(),
        })
    }

    fn run_js(
        &self,
        url: &str,
        data: Option<Bytes>,
        method: String,
        headers: &HeaderMap,
        field: &str,
    ) -> Option<(HeaderMap, Option<String>)> {
        let runtime = Runtime::new().ok()?;
        let ctx = Context::full(&runtime).ok()?;
        let js_data = HttpData {
            url: url.to_string(),
            method,
            header: {
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
            },
            body: data.and_then(|d| String::from_utf8(d.to_vec()).ok()),
        };
        let r = match ctx.with(|ctx| -> Result<HttpData, rquickjs::Error> {
            // init console
            let cls = Class::instance(
                ctx.clone(),
                Console {
                    id: self.name.clone().unwrap_or_else(|| "DEFAULT".to_string()),
                },
            )?;
            ctx.globals().set("console", cls)?;

            // init data
            let data = Class::instance(ctx.clone(), js_data)?;
            let obj = Object::new(ctx.clone())?;
            obj.set(field, data)?;
            ctx.globals().set("data", obj)?;

            match ctx.eval::<HttpData, _>(self.script.as_bytes()) {
                Ok(v) => Ok(v),
                Err(e) => {
                    if matches!(e, rquickjs::Error::Exception) {
                        if let Ok(ex) = ctx.catch().get::<Object>() {
                            if let Some(ex) = ctx.json_stringify(ex).ok().flatten() {
                                tracing::trace!("Exception: {}", ex.to_string().unwrap())
                            } else {
                                tracing::trace!("Failed to parse exception")
                            }
                        }
                    }
                    Err(e)
                }
            }
        }) {
            Err(e) => {
                tracing::trace!(
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
        Some((header, r.body))
    }

    pub fn try_rewrite_req(
        &self,
        url: &str,
        parts: &mut http::request::Parts,
        data: Option<Bytes>,
    ) -> Option<Bytes> {
        let method = parts.method.to_string();
        let header = &parts.headers;
        let (header, body) = self.run_js(url, data, method, header, "request")?;
        parts.headers = header;
        body.map(Bytes::from)
    }

    pub fn try_rewrite_resp(
        &self,
        url: &str,
        method: &http::Method,
        parts: &mut http::response::Parts,
        data: Option<Bytes>,
    ) -> Option<Bytes> {
        let header = &parts.headers;
        let (header, body) = self.run_js(url, data, method.to_string(), header, "response")?;
        parts.headers = header;
        body.map(Bytes::from)
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
        tracing::info!("[js-{}]:{}", self.id, str);
    }
}
