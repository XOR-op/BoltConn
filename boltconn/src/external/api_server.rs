use crate::config::LinkedState;
use crate::dispatch::{Dispatching, GeneralProxy, Latency};
use crate::external::{StreamLoggerHandle, StreamLoggerRecv};
use crate::network::configure::TunConfigure;
use crate::platform::process::ProcessInfo;
use crate::proxy::{
    latency_test, AgentCenter, Dispatcher, DumpedRequest, DumpedResponse, HttpCapturer,
    SessionManager,
};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ws::WebSocketUpgrade, Path, Query, State};
use axum::middleware::map_request;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use boltapi::{
    GetGroupRespSchema, GetInterceptDataResp, GetInterceptRangeReq, ProxyData, SetGroupReqSchema,
    TrafficResp, TunStatusSchema,
};
use serde_json::json;
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::RwLock;

pub type SharedDispatching = Arc<RwLock<Arc<Dispatching>>>;

#[derive(Clone)]
pub struct ApiServer {
    secret: Option<String>,
    manager: Arc<SessionManager>,
    stat_center: Arc<AgentCenter>,
    http_capturer: Option<Arc<HttpCapturer>>,
    dispatcher: Arc<Dispatcher>,
    dispatching: SharedDispatching,
    tun_configure: Arc<Mutex<TunConfigure>>,
    reload_sender: Arc<tokio::sync::mpsc::Sender<()>>,
    state: Arc<Mutex<LinkedState>>,
    stream_logger: StreamLoggerHandle,
    speedtest_url: Arc<Mutex<String>>,
}

impl ApiServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret: Option<String>,
        manager: Arc<SessionManager>,
        stat_center: Arc<AgentCenter>,
        http_capturer: Option<Arc<HttpCapturer>>,
        dispatcher: Arc<Dispatcher>,
        dispatching: SharedDispatching,
        global_setting: Arc<Mutex<TunConfigure>>,
        reload_sender: tokio::sync::mpsc::Sender<()>,
        state: LinkedState,
        stream_logger: StreamLoggerHandle,
        speedtest_url: Arc<Mutex<String>>,
    ) -> Self {
        Self {
            secret,
            manager,
            stat_center,
            http_capturer,
            tun_configure: global_setting,
            dispatcher,
            dispatching,
            reload_sender: Arc::new(reload_sender),
            state: Arc::new(Mutex::new(state)),
            stream_logger,
            speedtest_url,
        }
    }

    pub async fn run(self, port: u16) {
        let secret = Arc::new(self.secret.clone());
        let wrapper = move |r| Self::auth(secret.clone(), r);
        let app = Router::new()
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
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    pub async fn replace_dispatching(&self, dispatching: Arc<Dispatching>) {
        *self.dispatching.write().await = dispatching;
    }

    async fn auth<B>(
        auth: Arc<Option<String>>,
        request: http::Request<B>,
    ) -> Result<http::Request<B>, http::StatusCode> {
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
        Json(json!(TunStatusSchema {
            enabled: server.tun_configure.lock().unwrap().get_status()
        }))
    }

    async fn set_tun_configure(
        State(server): State<Self>,
        Json(status): Json<TunStatusSchema>,
    ) -> Json<serde_json::Value> {
        Json(json!(if status.enabled {
            server.tun_configure.lock().unwrap().enable().is_ok()
        } else {
            server.tun_configure.lock().unwrap().disable();
            true
        }))
    }

    async fn ws_get_logs(State(server): State<Self>, ws: WebSocketUpgrade) -> impl IntoResponse {
        let recv = server.stream_logger.subscribe();
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
        Json(json!(TrafficResp {
            upload: server.stat_center.get_upload().load(Ordering::Relaxed),
            download: server.stat_center.get_download().load(Ordering::Relaxed),
            upload_speed: None,
            download_speed: None,
        }))
    }

    async fn ws_get_traffic(State(server): State<Self>, ws: WebSocketUpgrade) -> impl IntoResponse {
        ws.on_upgrade(move |socket| Self::ws_get_traffic_inner(server, socket))
    }

    async fn ws_get_traffic_inner(server: Self, mut socket: WebSocket) {
        let mut last_upload = server.stat_center.get_upload().load(Ordering::Relaxed);
        let mut last_download = server.stat_center.get_download().load(Ordering::Relaxed);
        loop {
            // send traffic with 1 second interval
            let upload = server.stat_center.get_upload().load(Ordering::Relaxed);
            let download = server.stat_center.get_download().load(Ordering::Relaxed);
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
        let list = server.stat_center.get_copy().await;
        let mut result = Vec::new();
        for (idx, entry) in list.iter().enumerate() {
            let info = entry.read().await;
            let conn = boltapi::ConnectionSchema {
                conn_id: idx as u64,
                destination: info.dest.to_string(),
                protocol: info.session_proto.to_string(),
                proxy: format!("{:?}", info.rule).to_ascii_lowercase(),
                process: info.process_info.as_ref().map(|i| i.name.clone()),
                upload: info.upload_traffic,
                download: info.download_traffic,
                start_time: info
                    .start_time
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                active: !info.done,
            };
            result.push(conn);
        }
        Json(json!(result))
    }

    async fn stop_all_conn(State(server): State<Self>) {
        let list = server.stat_center.get_copy().await;
        for entry in list {
            let mut info = entry.write().await;
            info.abort().await;
        }
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
        if let Some(ele) = server.stat_center.get_nth(id).await {
            ele.write().await.abort().await;
            return Json(serde_json::Value::Bool(true));
        }
        Json(serde_json::Value::Bool(false))
    }

    async fn get_sessions(State(server): State<Self>) -> Json<serde_json::Value> {
        let all_tcp = server.manager.get_all_tcp_sessions();
        let all_udp = server.manager.get_all_udp_sessions();
        let mut result = Vec::new();
        for x in all_tcp {
            let elapsed = x.last_time.elapsed().as_secs();
            let session = boltapi::SessionSchema {
                pair: format!(
                    "{}->{}:{}",
                    x.source_addr.port(),
                    x.dest_addr.ip(),
                    x.dest_addr.port()
                ),
                time: pretty_time(elapsed),
                tcp_open: Some(x.available.load(Ordering::Relaxed)),
            };
            result.push(session);
        }
        for x in all_udp {
            let elapsed = x.last_time.elapsed().as_secs();
            let session = boltapi::SessionSchema {
                pair: format!("{}:", x.source_addr.port(),),
                time: pretty_time(elapsed),
                tcp_open: None,
            };
            result.push(session);
        }
        Json(json!(result))
    }

    fn collect_captured(
        list: Vec<(String, Option<ProcessInfo>, DumpedRequest, DumpedResponse)>,
    ) -> Json<serde_json::Value> {
        let mut result = Vec::new();
        for (idx, (host, proc, req, resp)) in list.into_iter().enumerate() {
            let item = boltapi::HttpInterceptSchema {
                intercept_id: idx as u64,
                client: proc.map(|proc| proc.name),
                uri: {
                    let s = req.uri.to_string();
                    if s.starts_with("https://") || s.starts_with("http://") {
                        // http2
                        s
                    } else {
                        // http1.1, with no host in uri field
                        host + s.as_str()
                    }
                },
                method: req.method.to_string(),
                status: resp.status.as_u16(),
                size: resp.body.len() as u64,
                time: pretty_latency(resp.time - req.time),
            };
            result.push(item);
        }
        Json(json!(result))
    }

    async fn get_intercept(State(server): State<Self>) -> Json<serde_json::Value> {
        if let Some(capturer) = &server.http_capturer {
            let list = capturer.get_copy();
            Self::collect_captured(list)
        } else {
            Json(serde_json::Value::Null)
        }
    }

    async fn get_intercept_range(
        State(server): State<Self>,
        Query(params): Query<GetInterceptRangeReq>,
    ) -> Json<serde_json::Value> {
        if let Some(capturer) = &server.http_capturer {
            if let Some(list) =
                capturer.get_range_copy(params.start as usize, params.end.map(|p| p as usize))
            {
                return Self::collect_captured(list);
            }
        }
        Json(serde_json::Value::Null)
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
        if let Some(capturer) = &server.http_capturer {
            if let Some(list) = capturer.get_range_copy(id, Some(id + 1)) {
                if list.len() == 1 {
                    let (_, _, req, resp) = list.get(0).unwrap();
                    let result = GetInterceptDataResp {
                        req_header: req
                            .headers
                            .iter()
                            .map(|(k, v)| {
                                format!("{}: {}", k, v.to_str().unwrap_or("INVALID NON-ASCII DATA"))
                            })
                            .collect(),
                        req_body: req.body.to_vec(),
                        resp_header: resp
                            .headers
                            .iter()
                            .map(|(k, v)| {
                                format!("{}: {}", k, v.to_str().unwrap_or("INVALID NON-ASCII DATA"))
                            })
                            .collect(),
                        resp_body: resp.body.to_vec(),
                    };
                    return Json(json!(result));
                }
            }
        }
        Json(serde_json::Value::Null)
    }

    async fn get_all_proxies(State(server): State<Self>) -> Json<serde_json::Value> {
        let list = server.dispatching.read().await.get_group_list();
        let mut result = Vec::new();
        for g in list.iter() {
            let item = GetGroupRespSchema {
                name: g.get_name(),
                selected: pretty_proxy(&g.get_selection()).name,
                list: g.get_members().iter().map(pretty_proxy).collect(),
            };
            result.push(item);
        }
        Json(json!(result))
    }

    async fn get_proxy_group(
        State(server): State<Self>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let group = {
            let Some(group) = params.get("group")else { return Json(serde_json::Value::Null); };
            group.clone()
        };
        let list = server.dispatching.read().await.get_group_list();
        let mut result = Vec::new();
        for g in list.iter() {
            if g.get_name() == group {
                let item = GetGroupRespSchema {
                    name: group,
                    selected: pretty_proxy(&g.get_selection()).name,
                    list: g.get_members().iter().map(pretty_proxy).collect(),
                };
                result.push(item);
                break;
            }
        }
        Json(json!(result))
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
        let r = server
            .dispatching
            .read()
            .await
            .set_group_selection(group.as_str(), args.selected.as_str())
            .is_ok();
        if r {
            let mut state = server.state.lock().unwrap();
            if let Some(val) = state.state.group_selection.get_mut(&group) {
                *val = args.selected;
            } else {
                state.state.group_selection.insert(group, args.selected);
            }
            if let Ok(content) = serde_yaml::to_string(&state.state) {
                let content = "# This file is managed by BoltConn. Do not edit unless you know what you are doing.\n".to_string() + content.as_str();
                fn inner(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
                    let mut file = std::fs::File::create(path)?;
                    file.write_all(contents)?;
                    file.flush()
                }
                if let Err(e) = inner(&state.state_path, content.as_bytes()) {
                    tracing::error!(
                        "Write state to {} failed: {}",
                        state.state_path.to_string_lossy(),
                        e
                    );
                }
            }
        }

        Json(json!(r))
    }

    async fn update_latency(
        State(server): State<ApiServer>,
        Path(params): Path<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let group = {
            let Some(group) = params.get("group") else { return Json(serde_json::Value::Bool(false)); };
            group.clone()
        };
        tracing::trace!("Start speedtest for group {}", group);
        let speedtest_url = server.speedtest_url.lock().unwrap().clone();
        let list = server.dispatching.read().await.get_group_list();
        for g in list.iter() {
            if g.get_name() == group {
                // update all latency inside the group
                let mut handles = vec![];
                for p in g.get_members() {
                    if let GeneralProxy::Single(p) = p {
                        if let Ok(h) = latency_test(
                            server.dispatcher.as_ref(),
                            p.clone(),
                            speedtest_url.as_str(),
                            Duration::from_secs(2),
                        )
                        .await
                        {
                            handles.push(h);
                        } else {
                            p.set_latency(Latency::Failed)
                        }
                    }
                }
                for h in handles {
                    let _ = h.await;
                }
                break;
            }
        }
        Json(serde_json::Value::Bool(true))
    }

    async fn reload(State(server): State<Self>) {
        let _ = server.reload_sender.send(()).await;
    }
}

fn pretty_proxy(g: &GeneralProxy) -> ProxyData {
    match g {
        GeneralProxy::Single(p) => ProxyData {
            name: p.get_name(),
            proto: p.get_impl().simple_description(),
            latency: match p.get_latency() {
                Latency::Unknown => None,
                Latency::Value(ms) => Some(format!("{ms} ms")),
                Latency::Failed => Some("Failed".to_string()),
            },
        },
        GeneralProxy::Group(g) => ProxyData {
            name: g.get_name(),
            proto: "group".to_string(),
            latency: None,
        },
    }
}

fn pretty_time(elapsed: u64) -> String {
    if elapsed < 60 {
        format!("{} seconds ago", elapsed)
    } else if elapsed < 60 * 60 {
        format!("{} mins ago", elapsed / 60)
    } else {
        format!("{} hours ago", elapsed / 3600)
    }
}

fn pretty_latency(elapsed: Duration) -> String {
    let ms = elapsed.as_millis();
    if ms < 1000 {
        format!("{}ms", ms)
    } else {
        format!("{:.2}s", ms as f64 / 1000.0)
    }
}
