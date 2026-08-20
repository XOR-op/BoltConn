use axum::Json;
use axum::body::Body;
use axum::response::{IntoResponse, Response};
use boltapi::{ApiError, ApiErrorCode};
use http::Method;
use http::StatusCode;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

pub(super) async fn web_auth<B>(
    auth: Arc<Option<String>>,
    request: http::Request<B>,
    cors_allow: CorsAllow,
) -> Result<http::Request<B>, http::StatusCode> {
    // websocket auth
    if request.headers().contains_key("Upgrade") {
        // Validate websocket origin
        // The `origin` header will be set automatically by browser
        if request.headers().contains_key("origin")
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
        // check `secret` in query parameters if needed
        return if let Some(auth) = auth.as_ref() {
            // we have `secret=...` in query parameters
            if let Some(query_pairs) = request
                .uri()
                .query()
                .map(|v| url::form_urlencoded::parse(v.as_bytes()).into_owned())
                // valid url encoded string
                && let Some(secret_param) = query_pairs
                    .into_iter()
                    .find(|(k, _)| k == "secret")
                    .map(|(_, v)| v)
                // matched
                && secret_param == *auth
            {
                Ok(request)
            } else {
                Err(http::StatusCode::UNAUTHORIZED)
            }
        } else {
            Ok(request)
        };
    }

    if let Some(auth) = auth.as_ref() {
        let auth_header = request
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok());
        match auth_header {
            Some(header_val) if header_val.starts_with("Bearer ") => {
                let token = &header_val[7..]; // Skip "Bearer " prefix
                if token == auth {
                    Ok(request)
                } else {
                    Err(http::StatusCode::UNAUTHORIZED)
                }
            }
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

pub(super) fn api_json<T>(result: Result<T, ApiError>) -> Response
where
    T: Serialize,
{
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => api_error_response(error),
    }
}

pub(super) fn api_empty(result: Result<(), ApiError>) -> Response {
    match result {
        // The API contract deliberately uses 200 with no response body for unit.
        Ok(()) => Response::new(Body::empty()),
        Err(error) => api_error_response(error),
    }
}

pub(super) fn invalid_request(message: impl std::fmt::Display) -> ApiError {
    ApiError {
        code: ApiErrorCode::InvalidRequest,
        message: crate::proxy::bounded_error_detail(&format!("invalid request: {message}")),
    }
}

fn api_error_response(mut error: ApiError) -> Response {
    error.message = crate::proxy::bounded_error_detail(&error.message);
    (api_error_status(error.code), Json(error)).into_response()
}

fn api_error_status(code: ApiErrorCode) -> StatusCode {
    match code {
        ApiErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
        ApiErrorCode::ConnNotFound
        | ApiErrorCode::LinkNotFound
        | ApiErrorCode::ResolverNotFound
        | ApiErrorCode::DnsMappingNotFound => StatusCode::NOT_FOUND,
        ApiErrorCode::ConnNotActive
        | ApiErrorCode::LinkNotInitialized
        | ApiErrorCode::LinkNotActive
        | ApiErrorCode::ResolverIdAmbiguous
        | ApiErrorCode::ResolverUnavailable => StatusCode::CONFLICT,
        ApiErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn api_errors_have_stable_status_and_json_payloads() {
        let cases = [
            (ApiErrorCode::InvalidRequest, StatusCode::BAD_REQUEST),
            (ApiErrorCode::ConnNotFound, StatusCode::NOT_FOUND),
            (ApiErrorCode::LinkNotFound, StatusCode::NOT_FOUND),
            (ApiErrorCode::ResolverNotFound, StatusCode::NOT_FOUND),
            (ApiErrorCode::DnsMappingNotFound, StatusCode::NOT_FOUND),
            (ApiErrorCode::ConnNotActive, StatusCode::CONFLICT),
            (ApiErrorCode::LinkNotInitialized, StatusCode::CONFLICT),
            (ApiErrorCode::LinkNotActive, StatusCode::CONFLICT),
            (ApiErrorCode::ResolverIdAmbiguous, StatusCode::CONFLICT),
            (ApiErrorCode::ResolverUnavailable, StatusCode::CONFLICT),
            (ApiErrorCode::Internal, StatusCode::INTERNAL_SERVER_ERROR),
        ];

        for (code, status) in cases {
            let response = api_json::<serde_json::Value>(Err(ApiError {
                code,
                message: "transport error".to_string(),
            }));
            assert_eq!(response.status(), status);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let decoded: ApiError = serde_json::from_slice(&body).unwrap();
            assert_eq!(decoded.code, code);
            assert_eq!(decoded.message, "transport error");
        }
    }

    #[tokio::test]
    async fn unit_success_is_200_with_an_empty_body() {
        let response = api_empty(Ok(()));
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[test]
    fn transport_errors_are_bounded() {
        let error = invalid_request(format!("{}\nunsafe", "x".repeat(1_000)));
        assert_eq!(error.code, ApiErrorCode::InvalidRequest);
        assert!(error.message.chars().count() <= 256);
        assert!(!error.message.chars().any(char::is_control));
    }
}
