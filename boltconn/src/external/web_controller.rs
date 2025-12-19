use crate::common::as_io_err;
use crate::dispatch::Dispatching;
use crate::external::web_common::{get_cors_layer, parse_cors_allow, web_auth};
use crate::external::{Controller, StreamLoggerRecv};
use crate::proxy::error::SystemError;
use arc_swap::ArcSwap;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, ws::WebSocketUpgrade};
use axum::middleware::map_request;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use boltapi::{GetInterceptRangeReq, SetGroupReqSchema, TrafficResp, TunStatusSchema};
use http::HeaderValue;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
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
            .route("/ws/connections", get(Self::ws_get_connections))
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
            .route("/dns/mapping/:fake_ip", get(Self::fake_ip_to_real))
            .route("/dns/lookup/:domain", get(Self::real_lookup))
            .route("/speedtest/:group", get(Self::update_latency))
            .route(
                "/connections/log_limit",
                get(Self::get_conn_log_limit).put(Self::set_conn_log_limit),
            )
            .route("/reload", post(Self::reload))
            .route("/connections/master", get(Self::get_master_conn_stat))
            .route("/connections/master/:id", delete(Self::stop_master_conn))
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

    async fn ws_get_connections(
        State(server): State<Self>,
        ws: WebSocketUpgrade,
    ) -> impl IntoResponse {
        ws.on_upgrade(move |socket| Self::ws_get_connections_inner(server, socket))
    }

    async fn ws_get_connections_inner(server: Self, mut socket: WebSocket) {
        loop {
            let data = json!(server.controller.get_active_conns()).to_string();
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

    async fn get_all_conn(State(server): State<Self>) -> Json<serde_json::Value> {
        Json(json!(server.controller.get_all_conns()))
    }

    async fn stop_all_conn(State(server): State<Self>) {
        server.controller.stop_all_conn()
    }

    async fn stop_conn(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let id = {
            let Some(id) = params.get("id") else {
                return Json(serde_json::Value::Bool(false));
            };
            if let Ok(s) = id.parse::<u64>() {
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

    async fn get_master_conn_stat(State(server): State<Self>) -> Json<serde_json::Value> {
        Json(json!(server.controller.get_master_conn_stat().await))
    }

    async fn stop_master_conn(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
    ) {
        let id = {
            let Some(id) = params.get("id") else { return };
            id.clone()
        };
        server.controller.stop_master_conn(id).await
    }

    async fn fake_ip_to_real(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        Json(json!(server.controller.fake_ip_to_real(
            match params.get("fake_ip") {
                Some(ip) => ip.clone(),
                None => return Json(serde_json::Value::Null),
            }
        )))
    }

    async fn real_lookup(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        Json(json!(
            server
                .controller
                .real_lookup(match params.get("domain_name") {
                    Some(domain_name) => domain_name.clone(),
                    None => return Json(serde_json::Value::Null),
                })
                .await
        ))
    }

    async fn set_conn_log_limit(
        State(server): State<Self>,
        Json(limit): Json<u32>,
    ) -> Json<serde_json::Value> {
        server.controller.set_conn_log_limit(limit).await;
        Json(serde_json::Value::Null)
    }

    async fn get_conn_log_limit(State(server): State<Self>) -> Json<serde_json::Value> {
        Json(json!(server.controller.get_conn_log_limit()))
    }

    async fn reload(State(server): State<Self>) {
        server.controller.reload().await
    }
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
