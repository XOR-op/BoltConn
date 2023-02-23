use crate::config::LinkedState;
use crate::dispatch::{Dispatching, GeneralProxy};
use crate::platform::process::ProcessInfo;
use crate::proxy::{AgentCenter, DumpedRequest, DumpedResponse, HttpCapturer, SessionManager};
use axum::extract::{Path, Query, State};
use axum::middleware::map_request;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use boltapi::{GetGroupRespSchema, GetMitmDataResp, GetMitmRangeReq, ProxyData, SetGroupReqSchema};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::RwLock;

pub type SharedDispatching = Arc<RwLock<Arc<Dispatching>>>;

#[derive(Clone)]
pub struct ApiServer {
    secret: Option<String>,
    manager: Arc<SessionManager>,
    stat_center: Arc<AgentCenter>,
    http_capturer: Option<Arc<HttpCapturer>>,
    dispatching: SharedDispatching,
    reload_sender: Arc<tokio::sync::mpsc::Sender<()>>,
    state: Arc<Mutex<LinkedState>>,
}

impl ApiServer {
    pub fn new(
        secret: Option<String>,
        manager: Arc<SessionManager>,
        stat_center: Arc<AgentCenter>,
        http_capturer: Option<Arc<HttpCapturer>>,
        dispatching: SharedDispatching,
        reload_sender: tokio::sync::mpsc::Sender<()>,
        state: LinkedState,
    ) -> Self {
        Self {
            secret,
            manager,
            stat_center,
            http_capturer,
            dispatching,
            reload_sender: Arc::new(reload_sender),
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub async fn run(self, port: u16) {
        let secret = Arc::new(self.secret.clone());
        let wrapper = move |r| Self::auth(secret.clone(), r);
        let app = Router::new()
            .route("/logs", get(Self::get_logs))
            .route(
                "/connections",
                get(Self::get_all_conn).delete(Self::stop_all_conn),
            )
            .route("/connections/:id", delete(Self::stop_conn))
            .route("/sessions", get(Self::get_sessions))
            .route("/mitm/all", get(Self::get_mitm))
            .route("/mitm/range", get(Self::get_mitm_range))
            .route("/mitm/payload/:id", get(Self::get_mitm_payload))
            .route(
                "/groups",
                get(Self::get_group_list).put(Self::set_selection),
            )
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

    async fn get_logs(State(_server): State<Self>) -> Json<serde_json::Value> {
        Json(serde_json::Value::Null)
    }

    async fn get_all_conn(State(server): State<Self>) -> Json<serde_json::Value> {
        let list = server.stat_center.get_copy().await;
        let mut result = Vec::new();
        for entry in list {
            let info = entry.read().await;
            let elapsed = info.start_time.elapsed().as_secs();
            let conn = boltapi::ConnectionSchema {
                destination: info.dest.to_string(),
                protocol: info.session_proto.to_string(),
                proxy: format!("{:?}", info.rule).to_ascii_lowercase(),
                process: info.process_info.as_ref().map(|i| i.name.clone()),
                upload: pretty_size(info.upload_traffic),
                download: pretty_size(info.download_traffic),
                time: pretty_time(elapsed),
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
                pair: format!(
                    "{}->{}:{}",
                    x.source_addr.port(),
                    x.dest_addr.ip(),
                    x.dest_addr.port()
                ),
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
        for (host, proc, req, resp) in list {
            let item = boltapi::HttpMitmSchema {
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
                size: pretty_size(resp.body.len()),
                time: pretty_latency(resp.time - req.time),
            };
            result.push(item);
        }
        Json(json!(result))
    }

    async fn get_mitm(State(server): State<Self>) -> Json<serde_json::Value> {
        if let Some(capturer) = &server.http_capturer {
            let list = capturer.get_copy();
            Self::collect_captured(list)
        } else {
            Json(serde_json::Value::Null)
        }
    }

    async fn get_mitm_range(
        State(server): State<Self>,
        Query(params): Query<GetMitmRangeReq>,
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

    async fn get_mitm_payload(
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
                    let result = GetMitmDataResp {
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

    async fn get_group_list(State(server): State<Self>) -> Json<serde_json::Value> {
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

    async fn set_selection(
        State(server): State<Self>,
        Json(args): Json<SetGroupReqSchema>,
    ) -> Json<serde_json::Value> {
        let r = server
            .dispatching
            .read()
            .await
            .set_group_selection(args.group.as_str(), args.selected.as_str())
            .is_ok();
        if r {
            let mut state = server.state.lock().unwrap();
            if let Some(val) = state.state.group_selection.get_mut(&args.group) {
                *val = args.selected;
                if let Ok(content) = serde_yaml::to_string(&state.state) {
                    let content = "# This file is managed by BoltConn. Do not edit unless you know what you are doing.\n".to_string() + content.as_str();
                    let _ = std::fs::write(&state.state_path, content);
                }
            }
        }

        Json(json!(r))
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
        },
        GeneralProxy::Group(g) => ProxyData {
            name: g.get_name(),
            proto: "group".to_string(),
        },
    }
}

fn pretty_size(data: usize) -> String {
    if data < 1024 {
        format!("{} Bytes", data)
    } else if data < 1024 * 1024 {
        format!("{} KB", data / 1024)
    } else {
        format!("{} MB", data / 1024 / 1024)
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
