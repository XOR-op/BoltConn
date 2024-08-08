use http::Method;
use std::collections::HashSet;
use std::sync::Arc;
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

pub(super) async fn web_auth<B>(
    auth: Arc<Option<String>>,
    request: http::Request<B>,
    cors_allow: CorsAllow,
) -> Result<http::Request<B>, http::StatusCode> {
    // Validate websocket origin
    // The `origin` header will be set automatically by browser
    if request.headers().contains_key("Upgrade")
        && request.headers().contains_key("origin")
        && !cors_allow.validate(
            request
                .headers()
                .get("origin")
                .unwrap()
                .to_str()
                .map_err(|_| http::StatusCode::UNAUTHORIZED)?,
        )
    {
        return Err(http::StatusCode::UNAUTHORIZED);
    }

    if let Some(auth) = auth.as_ref() {
        let auth_header = request
            .headers()
            .get("api-key")
            .and_then(|h| h.to_str().ok());
        match auth_header {
            Some(header_val) if header_val == auth => Ok(request),
            _ => Err(http::StatusCode::UNAUTHORIZED),
        }
    } else {
        Ok(request)
    }
}

#[derive(Debug, Clone)]
pub(super) enum CorsAllow {
    Any,
    None,
    Some(Arc<HashSet<String>>),
}

impl CorsAllow {
    pub fn validate(&self, source: &str) -> bool {
        match self {
            CorsAllow::Any => true,
            CorsAllow::None => Self::is_local(source),
            CorsAllow::Some(set) => set.contains(source) || Self::is_local(source),
        }
    }

    pub fn is_local(source: &str) -> bool {
        source.starts_with("http://localhost")
            || source.starts_with("http://127.0.0.1")
            || source.starts_with("file://")
            || source.starts_with("https://localhost")
            || source.starts_with("https://127.0.0.1")
    }
}

pub(super) fn parse_cors_allow(cors_allowed_list: &[String]) -> CorsAllow {
    if !cors_allowed_list.is_empty() {
        let mut list = HashSet::new();
        for i in cors_allowed_list.iter() {
            if i == "*" {
                return CorsAllow::Any;
            } else {
                list.insert(i.clone());
            }
        }
        CorsAllow::Some(Arc::new(list))
    } else {
        CorsAllow::None
    }
}

pub(super) fn get_cors_layer(origin: AllowOrigin) -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_origin(origin)
        .allow_headers(AllowHeaders::any())
}
