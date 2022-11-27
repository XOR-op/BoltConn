use crate::proxy::{SessionManager, StatCenter};
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
}

impl ApiServer {
    pub fn new(manager: Arc<SessionManager>, stat_center: Arc<StatCenter>) -> Self {
        Self {
            manager,
            stat_center,
        }
    }

    pub async fn run(self, port: u16) {
        let app = Router::new()
            .route("/logs", get(Self::get_logs))
            .route("/active", get(Self::get_active_conn))
            .route("/sessions", get(Self::get_sessions))
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
            let mut map = serde_json::Map::new();
            let info = entry.read().unwrap();
            map.insert("Destination".to_string(), json!(info.dest.to_string()));
            map.insert(
                "Protocol".to_string(),
                json!(info.session_proto.to_string()),
            );
            map.insert(
                "Proxy".to_string(),
                json!(format!("{:?}", info.rule).to_ascii_lowercase()),
            );
            if let Some(proc) = &info.process_info {
                map.insert("Process".to_string(), json!(proc.name));
            }
            map.insert(
                "Upload".to_string(),
                json!(pretty_size(info.upload_traffic)),
            );
            map.insert(
                "Download".to_string(),
                json!(pretty_size(info.download_traffic)),
            );
            let elapsed = info.start_time.elapsed().as_secs();
            map.insert("Time".to_string(), json!(pretty_time(elapsed)));
            result.push(map);
        }
        Json(json!(result))
    }

    async fn get_sessions(State(server): State<Self>) -> Json<serde_json::Value> {
        let all_tcp = server.manager.get_all_tcp_sessions();
        let _all_udp = server.manager.get_all_udp_sessions();
        let mut result = Vec::new();
        for x in all_tcp {
            let mut map = serde_json::Map::new();
            map.insert(
                "Pair".to_string(),
                json!(format!(
                    "{}->{}:{}",
                    x.source_addr.port(),
                    x.dest_addr.ip(),
                    x.dest_addr.port()
                )),
            );
            let elapsed = x.last_time.elapsed().as_secs();
            map.insert("Time".to_string(), json!(pretty_time(elapsed)));
            map.insert(
                "Available".to_string(),
                json!(x.available.load(Ordering::Relaxed)),
            );
            result.push(map);
        }
        Json(json!(result))
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
