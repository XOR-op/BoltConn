use http::{HeaderMap, Request};
use hyper::Body;
use regex::Regex;

#[derive(Debug)]
pub struct ScriptEngine {
    pattern: Regex,
    script: String,
}

impl ScriptEngine {
    pub fn try_rewrite_req(&self, req: Request<Body>) -> anyhow::Result<Request<Body>> {
        todo!()
    }
}
