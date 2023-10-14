use bytes::Bytes;
use http::{HeaderMap, HeaderName};
use regex::Regex;
use rquickjs::class::{Trace, Tracer};
use rquickjs::{Class, Context, Runtime};
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
    status: Option<u16>,
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
    pattern: Regex,
    script: String,
}

impl ScriptEngine {
    pub fn new(
        name: Option<&String>,
        script_type: &str,
        pattern: &str,
        script: &str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            name: name.cloned(),
            script_type: match script_type.to_ascii_lowercase().as_str() {
                "req" => ScriptType::Req,
                "resp" => ScriptType::Resp,
                "all" => ScriptType::All,
                s => return Err(anyhow::anyhow!("Invalid script type: {}", s)),
            },
            pattern: Regex::new(pattern)?,
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
    ) -> Option<(Option<u16>, HeaderMap, Option<String>)> {
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
            status,
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
            ctx.globals().set(field, data)?;

            match ctx.eval::<HttpData, _>(self.script.as_bytes()) {
                Ok(v) => Ok(v),
                Err(e) => {
                    if matches!(e, rquickjs::Error::Exception) {
                        let v = ctx.catch();
                        if v.type_of() == rquickjs::Type::Exception {
                            let v = v.as_exception().unwrap();
                            tracing::trace!(
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
            tracing::trace!("is {}", v.parse::<String>().ok()?);
            header.insert(HeaderName::from_bytes(k.as_bytes()).ok()?, v.parse().ok()?);
        }
        Some((r.status, header, r.body))
    }

    pub fn try_rewrite_req(
        &self,
        url: &str,
        parts: &mut http::request::Parts,
        data: Option<Bytes>,
    ) -> Option<Bytes> {
        match self.script_type {
            ScriptType::Req | ScriptType::All => {
                let method = parts.method.to_string();
                let header = &parts.headers;
                let (_, header, body) = self.run_js(url, data, method, None, header, "$request")?;
                parts.headers = header;
                body.map(Bytes::from)
            }
            ScriptType::Resp => None,
        }
    }

    pub fn try_rewrite_resp(
        &self,
        url: &str,
        method: &http::Method,
        parts: &mut http::response::Parts,
        data: Option<Bytes>,
    ) -> Option<Bytes> {
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
        tracing::trace!("Started");
        let name = "test-req".to_string();
        let engine = ScriptEngine::new(
            Some(&name),
            "req",
            "https://www.google.com",
            "\
        console.log('user-agent is '+$request.header['user-agent']);
        console.log(JSON.stringify($request.header));
        console.log(JSON.stringify($request));
        $request.header['user-agent'] = 'curl/1.2.3';
        $request.header['test'] = 'aaaa';
        $request.status = 502;
        console.log('status is '+$request.status);
        console.log(JSON.stringify($request));
        console.log($request.header['user-agent']);
        console.log(JSON.stringify($request.header));
        $request.header={'user-agent':'curl/1.2.4'};
        console.log(JSON.stringify($request));
        console.log($request.header['user-agent']);
        console.log(JSON.stringify($request.header));
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
