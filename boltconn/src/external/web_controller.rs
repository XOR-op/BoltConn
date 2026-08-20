use crate::common::as_io_err;
use crate::dispatch::Dispatching;
use crate::external::web_common::{
    api_empty, api_json, get_cors_layer, invalid_request, parse_cors_allow, web_auth,
};
use crate::external::{Controller, StreamLoggerRecv};
use crate::proxy::error::SystemError;
use arc_swap::ArcSwap;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, ws::WebSocketUpgrade};
use axum::middleware::map_request;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use boltapi::{
    ApiError, ConnListRequest, DnsLookupRequest, GetInterceptRangeReq, SetGroupReqSchema,
    TrafficResp, TunStatusSchema,
};
use http::HeaderValue;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::cors::AllowOrigin;

pub type SharedDispatching = Arc<ArcSwap<Dispatching>>;

#[derive(Clone)]
pub struct WebController {
    secret: Option<String>,
    controller: Arc<Controller>,
}

impl WebController {
    pub fn new(secret: Option<String>, controller: Arc<Controller>) -> Self {
        Self { secret, controller }
    }

    pub async fn run(
        self,
        listen_addr: SocketAddr,
        cors_allowed_list: &[String],
    ) -> Result<(), SystemError> {
        let secret = Arc::new(self.secret.clone());
        let cors_vec = parse_cors_allow(cors_allowed_list);
        let wrapper = move |r| web_auth(secret.clone(), r, cors_vec.clone());

        let mut app = Router::new()
            .route("/ws/traffic", get(Self::ws_get_traffic))
            .route("/ws/conn", get(Self::ws_get_conn))
            .route("/ws/logs", get(Self::ws_get_logs))
            .route(
                "/tun",
                get(Self::get_tun_configure).put(Self::set_tun_configure),
            )
            .route("/traffic", get(Self::get_traffic))
            .route("/conn", get(Self::list_conn))
            .route("/conn/all", delete(Self::stop_all_conn))
            .route(
                "/conn/history-limit",
                get(Self::get_conn_history_limit).put(Self::set_conn_history_limit),
            )
            .route("/conn/:id", get(Self::show_conn).delete(Self::stop_conn))
            .route("/link", get(Self::list_link))
            .route("/link/:name", get(Self::show_link).delete(Self::stop_link))
            .route("/dns", get(Self::list_dns))
            .route("/dns/lookup", get(Self::lookup_dns))
            .route("/dns/mapping", get(Self::get_dns_mapping))
            .route("/dns/:id", get(Self::show_dns))
            .route("/sessions", get(Self::get_sessions))
            .route("/intercept/all", get(Self::get_intercept))
            .route("/intercept/range", get(Self::get_intercept_range))
            .route("/intercept/payload/:id", get(Self::get_intercept_payload))
            .route("/proxies", get(Self::get_all_proxies))
            .route(
                "/proxies/:group",
                get(Self::get_proxy_group).put(Self::set_selection),
            )
            .route("/speedtest/:group", get(Self::update_latency))
            .route("/reload", post(Self::reload))
            .route_layer(map_request(wrapper))
            .with_state(self);
        if let Some(origin) = parse_api_cors_origin(cors_allowed_list) {
            app = app.layer(get_cors_layer(origin));
        }

        let listener = TcpListener::bind(&listen_addr)
            .await
            .map_err(SystemError::Controller)?;
        axum::serve(listener, app.into_make_service())
            .await
            .map_err(|e| SystemError::Controller(as_io_err(e)))?;
        Ok(())
    }

    async fn get_tun_configure(State(server): State<Self>) -> Json<serde_json::Value> {
        Json(json!(server.controller.get_tun()))
    }

    async fn set_tun_configure(
        State(server): State<Self>,
        Json(status): Json<TunStatusSchema>,
    ) -> Json<serde_json::Value> {
        Json(json!(server.controller.set_tun(&status)))
    }

    async fn ws_get_logs(State(server): State<Self>, ws: WebSocketUpgrade) -> impl IntoResponse {
        let recv = server.controller.get_log_subscriber();
        ws.on_upgrade(move |socket| Self::ws_get_logs_inner(recv, socket))
    }

    async fn ws_get_logs_inner(mut recv: StreamLoggerRecv, mut socket: WebSocket) {
        while let Ok(log) = recv.recv().await {
            if socket.send(Message::Text(log)).await.is_err() {
                return;
            }
        }
    }

    async fn ws_get_conn(State(server): State<Self>, ws: WebSocketUpgrade) -> impl IntoResponse {
        ws.on_upgrade(move |socket| Self::ws_get_conn_inner(server, socket))
    }

    async fn ws_get_conn_inner(server: Self, mut socket: WebSocket) {
        loop {
            // Every frame replaces the client's complete active view; no stream
            // state is retained in the transport layer.
            let data = connection_stream_frame(&server.controller.active_conn_snapshot());
            if socket.send(Message::Text(data)).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn get_traffic(State(server): State<Self>) -> Json<serde_json::Value> {
        Json(json!(server.controller.get_traffic()))
    }

    async fn ws_get_traffic(State(server): State<Self>, ws: WebSocketUpgrade) -> impl IntoResponse {
        ws.on_upgrade(move |socket| Self::ws_get_traffic_inner(server, socket))
    }

    async fn ws_get_traffic_inner(server: Self, mut socket: WebSocket) {
        let TrafficResp {
            upload: mut last_upload,
            download: mut last_download,
            upload_speed: _,
            download_speed: _,
        } = server.controller.get_traffic();
        loop {
            // send traffic with 1 second interval
            let TrafficResp {
                upload,
                download,
                upload_speed: _,
                download_speed: _,
            } = server.controller.get_traffic();
            let data = json!(TrafficResp {
                upload,
                download,
                upload_speed: Some(upload - last_upload),
                download_speed: Some(download - last_download)
            })
            .to_string();
            last_upload = upload;
            last_download = download;
            if socket.send(Message::Text(data)).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn list_conn(
        State(server): State<Self>,
        request: Result<Query<ConnListRequest>, QueryRejection>,
    ) -> Response {
        api_json(match request {
            Ok(Query(request)) => Ok(server.controller.list_conn(request)),
            Err(error) => Err(invalid_request(error)),
        })
    }

    async fn show_conn(
        State(server): State<Self>,
        id: Result<Path<String>, PathRejection>,
    ) -> Response {
        api_json(parse_conn_id(id).and_then(|id| server.controller.show_conn(id)))
    }

    async fn stop_all_conn(State(server): State<Self>) -> Response {
        api_json(Ok(server.controller.stop_all_conn()))
    }

    async fn stop_conn(
        State(server): State<Self>,
        id: Result<Path<String>, PathRejection>,
    ) -> Response {
        api_json(parse_conn_id(id).and_then(|id| server.controller.stop_conn(id)))
    }

    async fn get_conn_history_limit(State(server): State<Self>) -> Response {
        api_json(Ok(server.controller.get_conn_history_limit()))
    }

    async fn set_conn_history_limit(
        State(server): State<Self>,
        limit: Result<Json<u32>, JsonRejection>,
    ) -> Response {
        match limit {
            Ok(Json(limit)) => api_json(Ok(server.controller.set_conn_history_limit(limit).await)),
            Err(error) => api_json::<u32>(Err(invalid_request(error))),
        }
    }

    async fn list_link(State(server): State<Self>) -> Response {
        api_json(Ok(server.controller.list_link().await))
    }

    async fn show_link(
        State(server): State<Self>,
        name: Result<Path<String>, PathRejection>,
    ) -> Response {
        let result = match name {
            Ok(Path(name)) => server.controller.show_link(name).await,
            Err(error) => Err(invalid_request(error)),
        };
        api_json(result)
    }

    async fn stop_link(
        State(server): State<Self>,
        name: Result<Path<String>, PathRejection>,
    ) -> Response {
        let result = match name {
            Ok(Path(name)) => server.controller.stop_link(name).await,
            Err(error) => Err(invalid_request(error)),
        };
        api_empty(result)
    }

    async fn list_dns(State(server): State<Self>) -> Response {
        api_json(Ok(server.controller.list_dns()))
    }

    async fn show_dns(
        State(server): State<Self>,
        id: Result<Path<String>, PathRejection>,
    ) -> Response {
        api_json(match id {
            Ok(Path(id)) => server.controller.show_dns(id),
            Err(error) => Err(invalid_request(error)),
        })
    }

    async fn lookup_dns(
        State(server): State<Self>,
        request: Result<Query<DnsLookupRequest>, QueryRejection>,
    ) -> Response {
        let result = match request {
            Ok(Query(request)) => server.controller.lookup_dns(request).await,
            Err(error) => Err(invalid_request(error)),
        };
        api_json(result)
    }

    async fn get_dns_mapping(
        State(server): State<Self>,
        request: Result<Query<DnsMappingRequest>, QueryRejection>,
    ) -> Response {
        api_json(match request {
            Ok(Query(request)) => server.controller.get_dns_mapping(request.fake_ip),
            Err(error) => Err(invalid_request(error)),
        })
    }

    async fn get_sessions(State(server): State<Self>) -> Json<serde_json::Value> {
        Json(json!(server.controller.get_sessions()))
    }

    async fn get_intercept(State(server): State<Self>) -> Json<serde_json::Value> {
        Json(json!(server.controller.get_intercept()))
    }

    async fn get_intercept_range(
        State(server): State<Self>,
        Query(params): Query<GetInterceptRangeReq>,
    ) -> Json<serde_json::Value> {
        Json(json!(server.controller.get_intercept_range(&params)))
    }

    async fn get_intercept_payload(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let id = {
            let Some(start) = params.get("id") else {
                return Json(serde_json::Value::Null);
            };
            if let Ok(s) = start.parse::<usize>() {
                s
            } else {
                return Json(serde_json::Value::Null);
            }
        };
        match server.controller.get_intercept_payload(id) {
            Some(result) => Json(json!(result)),
            None => Json(serde_json::Value::Null),
        }
    }

    async fn get_all_proxies(State(server): State<Self>) -> Json<serde_json::Value> {
        Json(json!(server.controller.get_all_proxies()))
    }

    async fn get_proxy_group(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let group = {
            let Some(group) = params.get("group") else {
                return Json(serde_json::Value::Null);
            };
            group.clone()
        };
        Json(json!(server.controller.get_proxy_group(group)))
    }

    async fn set_selection(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
        Json(args): Json<SetGroupReqSchema>,
    ) -> Json<serde_json::Value> {
        let group = {
            let Some(group) = params.get("group") else {
                return Json(serde_json::Value::Null);
            };
            group.clone()
        };
        Json(json!(
            server.controller.set_selection(group, args.selected).await
        ))
    }

    async fn update_latency(
        State(server): State<WebController>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let group = {
            let Some(group) = params.get("group") else {
                return Json(serde_json::Value::Bool(false));
            };
            group.clone()
        };
        server.controller.update_latency(group).await;
        Json(serde_json::Value::Bool(true))
    }

    async fn reload(State(server): State<Self>) -> Json<serde_json::Value> {
        Json(json!(server.controller.reload().await))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsMappingRequest {
    #[serde(rename = "fake-ip")]
    fake_ip: IpAddr,
}

fn parse_conn_id(id: Result<Path<String>, PathRejection>) -> Result<u64, ApiError> {
    let Path(id) = id.map_err(invalid_request)?;
    id.parse::<u64>().map_err(invalid_request)
}

fn connection_stream_frame(snapshot: &boltapi::Snapshot<boltapi::ConnSummary>) -> String {
    // Snapshot schemas contain no fallible custom serializers, so this cannot
    // fail for an in-memory controller value.
    serde_json::to_string(snapshot).expect("connection snapshot must serialize")
}

pub(super) fn parse_api_cors_origin(cors_allowed_list: &[String]) -> Option<AllowOrigin> {
    if !cors_allowed_list.is_empty() {
        let mut list = vec![];
        for i in cors_allowed_list.iter() {
            if i == "*" {
                return Some(AllowOrigin::any());
            } else {
                list.push(HeaderValue::from_str(i.as_str()).ok()?)
            }
        }
        Some(AllowOrigin::list(list))
    } else {
        None
    }
}

#[cfg(test)]
mod observability_transport_tests {
    use super::*;
    use axum::body::Body;
    use http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn echo_link_name(Path(name): Path<String>) -> String {
        name
    }

    async fn echo_dns_query(request: Result<Query<DnsLookupRequest>, QueryRejection>) -> Response {
        api_json(match request {
            Ok(Query(request)) => Ok(request),
            Err(error) => Err(invalid_request(error)),
        })
    }

    async fn echo_dns_mapping_query(
        request: Result<Query<DnsMappingRequest>, QueryRejection>,
    ) -> Response {
        api_json(match request {
            Ok(Query(request)) => Ok(request.fake_ip),
            Err(error) => Err(invalid_request(error)),
        })
    }

    #[tokio::test]
    async fn link_names_are_percent_decoded_as_one_path_segment() {
        let app = Router::new().route("/link/:name", get(echo_link_name));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/link/wg%20us%2Fprimary%2Bbackup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"wg us/primary+backup");
    }

    #[tokio::test]
    async fn dns_query_uses_shared_request_and_rejects_unknown_fields() {
        let app = Router::new().route("/dns/lookup", get(echo_dns_query));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/dns/lookup?domain=example.com&resolver=0123456789ab")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let request: DnsLookupRequest = serde_json::from_slice(&body).unwrap();
        assert_eq!(request.domain, "example.com");
        assert_eq!(request.resolver_id.as_deref(), Some("0123456789ab"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/dns/lookup?domain=example.com&unexpected=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let error: ApiError = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.code, boltapi::ApiErrorCode::InvalidRequest);
    }

    #[tokio::test]
    async fn fake_ip_query_uses_the_hyphenated_wire_key() {
        let app = Router::new().route("/dns/mapping", get(echo_dns_mapping_query));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/dns/mapping?fake-ip=198.18.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<IpAddr>(&body).unwrap(),
            "198.18.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn invalid_connection_ids_use_the_stable_request_error() {
        let error = parse_conn_id(Ok(Path("not-a-number".to_string()))).unwrap_err();
        assert_eq!(error.code, boltapi::ApiErrorCode::InvalidRequest);
        assert!(error.message.contains("invalid digit"));
    }

    #[test]
    fn connection_stream_frames_are_full_snapshot_envelopes() {
        let frame = connection_stream_frame(&boltapi::Snapshot::<boltapi::ConnSummary> {
            observed_at_ms: 42,
            items: Vec::new(),
        });
        let snapshot: boltapi::Snapshot<boltapi::ConnSummary> =
            serde_json::from_str(&frame).unwrap();
        assert_eq!(snapshot.observed_at_ms, 42);
        assert!(snapshot.items.is_empty());
    }
}
