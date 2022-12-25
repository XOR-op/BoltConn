use crate::config::{LinkedState, RawState};
use crate::dispatch::{Dispatching, GeneralProxy};
use crate::platform::process::ProcessInfo;
use crate::proxy::{AgentCenter, DumpedRequest, DumpedResponse, HttpCapturer, SessionManager};
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router, ServiceExt};
use boltapi::{
    GetCapturedDataReq, GetCapturedDataResp, GetCapturedRangeReq, GetGroupRespSchema,
    SetGroupReqSchema,
};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct ApiServer {
    manager: Arc<SessionManager>,
    stat_center: Arc<AgentCenter>,
    http_capturer: Option<Arc<HttpCapturer>>,
    dispatching: Arc<Dispatching>,
    state: Arc<Mutex<LinkedState>>,
}

impl ApiServer {
    pub fn new(
        manager: Arc<SessionManager>,
        stat_center: Arc<AgentCenter>,
        http_capturer: Option<Arc<HttpCapturer>>,
        dispatching: Arc<Dispatching>,
        state: LinkedState,
    ) -> Self {
        Self {
            manager,
            stat_center,
            http_capturer,
            dispatching,
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub async fn run(self, port: u16) {
        let app = Router::new()
            .route("/logs", get(Self::get_logs))
            .route("/active", get(Self::get_active_conn))
            .route("/sessions", get(Self::get_sessions))
            .route("/captured/all", get(Self::get_captured))
            .route("/captured/range", get(Self::get_captured_range))
            .route("/captured/detail/:id", get(Self::get_captured_data))
            .route(
                "/groups",
                get(Self::get_group_list).put(Self::set_selection),
            )
            .with_state(self);
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    async fn get_logs(State(_server): State<Self>) -> Json<serde_json::Value> {
        Json(serde_json::Value::Null)
    }

    async fn get_active_conn(State(server): State<Self>) -> Json<serde_json::Value> {
        let list = server.stat_center.get_copy();
        let mut result = Vec::new();
        for entry in list {
            let info = entry.read().unwrap();

            let elapsed = info.start_time.elapsed().as_secs();
            let conn = boltapi::ConnectionSchema {
                destination: info.dest.to_string(),
                protocol: info.session_proto.to_string(),
                proxy: format!("{:?}", info.rule).to_ascii_lowercase(),
                process: info.process_info.as_ref().map(|ref i| i.name.clone()),
                upload: pretty_size(info.upload_traffic),
                download: pretty_size(info.download_traffic),
                time: pretty_time(elapsed),
            };
            result.push(conn);
        }
        Json(json!(result))
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
            let item = boltapi::HttpCaptureSchema {
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

    async fn get_captured(State(server): State<Self>) -> Json<serde_json::Value> {
        if let Some(capturer) = &server.http_capturer {
            let list = capturer.get_copy();
            Self::collect_captured(list)
        } else {
            Json(serde_json::Value::Null)
        }
    }

    async fn get_captured_range(
        State(server): State<Self>,
        Query(params): Query<GetCapturedRangeReq>,
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

    async fn get_captured_data(
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
            if let Some(list) = capturer.get_range_copy(id as usize, Some((id + 1) as usize)) {
                if list.len() == 1 {
                    let (_, _, req, resp) = list.get(0).unwrap();
                    let result = GetCapturedDataResp {
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
        let list = server.dispatching.get_group_list();
        let mut result = Vec::new();
        for g in list.iter() {
            let item = GetGroupRespSchema {
                name: g.get_name(),
                selected: pretty_proxy(g.get_selection()),
                list: g
                    .get_members()
                    .iter()
                    .map(|p| pretty_proxy(p.clone()))
                    .collect(),
            };
            result.push(item);
        }
        Json(json!(result))
    }

    async fn set_selection(
        State(server): State<Self>,
        Json(args): Json<SetGroupReqSchema>,
    ) -> Json<serde_json::Value> {
        let r = match server
            .dispatching
            .set_group_selection(args.group.as_str(), args.selected.as_str())
        {
            Ok(_) => true,
            Err(_) => false,
        };
        if r {
            let mut state = server.state.lock().unwrap();
            if let Some(val) = state.state.group_selection.get_mut(&args.group) {
                *val = args.selected;
                if let Ok(content) = serde_yaml::to_string(&state.state) {
                    let _ = std::fs::write(&state.state_path, content);
                }
            }
        }

        Json(json!(r))
    }
}

fn pretty_proxy(g: GeneralProxy) -> String {
    match g {
        GeneralProxy::Single(p) => "(P)".to_string() + p.get_name().as_str(),
        GeneralProxy::Group(g) => "(G)".to_string() + g.get_name().as_str(),
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
