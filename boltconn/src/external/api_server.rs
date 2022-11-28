use crate::proxy::{HttpCapturer, SessionManager, StatCenter};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router, ServiceExt};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct ApiServer {
    manager: Arc<SessionManager>,
    stat_center: Arc<StatCenter>,
    http_capturer: Option<Arc<HttpCapturer>>,
}

impl ApiServer {
    pub fn new(
        manager: Arc<SessionManager>,
        stat_center: Arc<StatCenter>,
        http_capturer: Option<Arc<HttpCapturer>>,
    ) -> Self {
        Self {
            manager,
            stat_center,
            http_capturer,
        }
    }

    pub async fn run(self, port: u16) {
        let app = Router::new()
            .route("/logs", get(Self::get_logs))
            .route("/active", get(Self::get_active_conn))
            .route("/sessions", get(Self::get_sessions))
            .route("/captured", get(Self::get_captured))
            .with_state(self);
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    async fn get_logs(State(server): State<Self>) -> Json<serde_json::Value> {
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
        let _all_udp = server.manager.get_all_udp_sessions();
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
        Json(json!(result))
    }

    async fn get_captured(State(server): State<Self>) -> Json<serde_json::Value> {
        if let Some(capturer) = &server.http_capturer {
            let list = capturer.get_copy();
            let mut result = Vec::new();
            for (host, req, resp) in list {
                let item = boltapi::HttpCaptureSchema {
                    uri: host + req.uri.to_string().as_str(),
                    method: req.method.to_string(),
                    status: resp.status.as_u16(),
                    size: pretty_size(resp.body.len()),
                    time: pretty_latency(resp.time - req.time),
                };
                result.push(item);
            }
            Json(json!(result))
        } else {
            Json(serde_json::Value::Null)
        }
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
