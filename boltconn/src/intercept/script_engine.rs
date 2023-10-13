use bytes::Bytes;
use http::{HeaderMap, HeaderName};
use regex::Regex;
use rquickjs as js;
use rquickjs::{FromJs, IntoJs};
use std::collections::hash_map::Entry;
use std::collections::HashMap;

#[derive(IntoJs, FromJs)]
struct HttpData {
    url: String,
    method: String,
    header: HashMap<String, String>,
    body: Option<String>,
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
        let runtime = rquickjs::Runtime::new().ok()?;
        let ctx = js::Context::full(&runtime).ok()?;
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
        let r = match ctx.with(|ctx| -> Result<HttpData, js::Error> {
            let obj = js::Object::new(ctx)?;
            obj.set(field, js_data)?;
            ctx.globals().set("data", obj)?;
            let v: HttpData = ctx.eval(self.script.as_bytes())?;
            Ok(v)
        }) {
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
