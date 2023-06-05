use crate::dispatch::Dispatching;
use crate::external::{Controller, StreamLoggerRecv};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ws::WebSocketUpgrade, Path, Query, State};
use axum::middleware::map_request;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use boltapi::{GetInterceptRangeReq, SetGroupReqSchema, TrafficResp, TunStatusSchema};
use http::{HeaderValue, Method};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

pub type SharedDispatching = Arc<RwLock<Arc<Dispatching>>>;

#[derive(Clone)]
pub struct ApiServer {
    secret: Option<String>,
    controller: Arc<Controller>,
}

impl ApiServer {
    pub fn new(secret: Option<String>, controller: Arc<Controller>) -> Self {
        Self { secret, controller }
    }

    pub async fn run(self, port: u16, cors_allowed_list: &[String]) {
        let secret = Arc::new(self.secret.clone());
        let cors_vec = parse_cors_allow(cors_allowed_list);
        let wrapper = move |r| Self::auth(secret.clone(), r, cors_vec.clone());

        let mut app = Router::new()
            .route("/ws/traffic", get(Self::ws_get_traffic))
            .route("/ws/logs", get(Self::ws_get_logs))
            .route(
                "/tun",
                get(Self::get_tun_configure).put(Self::set_tun_configure),
            )
            .route("/traffic", get(Self::get_traffic))
            .route(
                "/connections",
                get(Self::get_all_conn).delete(Self::stop_all_conn),
            )
            .route("/connections/:id", delete(Self::stop_conn))
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
            app = app.layer(
                CorsLayer::new()
                    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                    .allow_origin(origin)
                    .allow_headers(AllowHeaders::any()),
            );
        }

        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    async fn auth<B>(
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

    async fn get_all_conn(State(server): State<Self>) -> Json<serde_json::Value> {
        Json(json!(server.controller.get_all_conns()))
    }

    async fn stop_all_conn(State(server): State<Self>) {
        server.controller.stop_all_conn().await
    }

    async fn stop_conn(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let id = {
            let Some(id) = params.get("id")else { return Json(serde_json::Value::Bool(false)); };
            if let Ok(s) = id.parse::<usize>() {
                s
            } else {
                return Json(serde_json::Value::Bool(false));
            }
        };
        Json(json!(server.controller.stop_conn(id).await))
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
            let Some(start) = params.get("id")else { return Json(serde_json::Value::Null); };
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
        Json(json!(server.controller.get_all_proxies().await))
    }

    async fn get_proxy_group(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let group = {
            let Some(group) = params.get("group")else { return Json(serde_json::Value::Null); };
            group.clone()
        };
        Json(json!(server.controller.get_proxy_group(group).await))
    }

    async fn set_selection(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
        Json(args): Json<SetGroupReqSchema>,
    ) -> Json<serde_json::Value> {
        let group = {
            let Some(group) = params.get("group") else { return Json(serde_json::Value::Null); };
            group.clone()
        };
        Json(json!(
            server.controller.set_selection(group, args.selected).await
        ))
    }

    async fn update_latency(
        State(server): State<ApiServer>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let group = {
            let Some(group) = params.get("group") else { return Json(serde_json::Value::Bool(false)); };
            group.clone()
        };
        server.controller.update_latency(group).await;
        Json(serde_json::Value::Bool(true))
    }

    async fn reload(State(server): State<Self>) {
        server.controller.reload().await
    }
}

fn parse_api_cors_origin(cors_allowed_list: &[String]) -> Option<AllowOrigin> {
    if !cors_allowed_list.is_empty() {
        let mut list = vec![];
        for i in cors_allowed_list.iter() {
            if i == "*" {
                return Some(AllowOrigin::any());
            } else {
                list.push(HeaderValue::from_str(i.as_str()).ok()?)
            }
        }
        Some(AllowOrigin::list(list.into_iter()))
    } else {
        None
    }
}

#[derive(Debug, Clone)]
enum CorsAllow {
    Any,
    None,
    Some(Arc<HashSet<String>>),
}

impl CorsAllow {
    fn validate(&self, source: &str) -> bool {
        match self {
            CorsAllow::Any => true,
            CorsAllow::None => Self::is_local(source),
            CorsAllow::Some(set) => set.contains(source) || Self::is_local(source),
        }
    }

    fn is_local(source: &str) -> bool {
        source.starts_with("http://localhost")
            || source.starts_with("http://127.0.0.1")
            || source.starts_with("file://")
            || source.starts_with("https://localhost")
            || source.starts_with("https://127.0.0.1")
    }
}

fn parse_cors_allow(cors_allowed_list: &[String]) -> CorsAllow {
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
