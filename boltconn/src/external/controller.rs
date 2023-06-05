use crate::config::LinkedState;
use crate::dispatch::{GeneralProxy, Latency};
use crate::external::{SharedDispatching, StreamLoggerRecv, StreamLoggerSend};
use crate::network::configure::TunConfigure;
use crate::proxy::{
    latency_test, BodyOrWarning, ContextManager, Dispatcher, HttpCapturer, HttpInterceptData,
    SessionManager,
};
use boltapi::{
    ConnectionSchema, GetGroupRespSchema, GetInterceptDataResp, GetInterceptRangeReq,
    HttpInterceptSchema, ProxyData, SessionSchema, TrafficResp, TunStatusSchema,
};
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

#[derive(Clone)]
pub struct Controller {
    manager: Arc<SessionManager>,
    stat_center: Arc<ContextManager>,
    http_capturer: Option<Arc<HttpCapturer>>,
    dispatcher: Arc<Dispatcher>,
    dispatching: SharedDispatching,
    tun_configure: Arc<std::sync::Mutex<TunConfigure>>,
    reload_sender: Arc<tokio::sync::mpsc::Sender<()>>,
    state: Arc<std::sync::Mutex<LinkedState>>,
    stream_logger: StreamLoggerSend,
    speedtest_url: Arc<std::sync::Mutex<String>>,
}

impl Controller {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manager: Arc<SessionManager>,
        stat_center: Arc<ContextManager>,
        http_capturer: Option<Arc<HttpCapturer>>,
        dispatcher: Arc<Dispatcher>,
        dispatching: SharedDispatching,
        global_setting: Arc<std::sync::Mutex<TunConfigure>>,
        reload_sender: tokio::sync::mpsc::Sender<()>,
        state: LinkedState,
        stream_logger: StreamLoggerSend,
        speedtest_url: Arc<std::sync::Mutex<String>>,
    ) -> Self {
        Self {
            manager,
            stat_center,
            http_capturer,
            tun_configure: global_setting,
            dispatcher,
            dispatching,
            reload_sender: Arc::new(reload_sender),
            state: Arc::new(std::sync::Mutex::new(state)),
            stream_logger,
            speedtest_url,
        }
    }

    pub fn get_tun(&self) -> TunStatusSchema {
        TunStatusSchema {
            enabled: self.tun_configure.lock().unwrap().get_status(),
        }
    }

    pub fn set_tun(&self, status: &TunStatusSchema) -> bool {
        if status.enabled {
            self.tun_configure.lock().unwrap().enable().is_ok()
        } else {
            self.tun_configure.lock().unwrap().disable(true);
            true
        }
    }

    pub fn get_log_subscriber(&self) -> StreamLoggerRecv {
        self.stream_logger.subscribe()
    }

    pub fn get_traffic(&self) -> TrafficResp {
        TrafficResp {
            upload: self.stat_center.get_upload().load(Ordering::Relaxed),
            download: self.stat_center.get_download().load(Ordering::Relaxed),
            upload_speed: None,
            download_speed: None,
        }
    }

    pub fn get_all_conns(&self) -> Vec<ConnectionSchema> {
        let (list, offset) = self.stat_center.get_copy();
        let mut result = Vec::new();
        for (idx, info) in list.iter().enumerate() {
            let conn = ConnectionSchema {
                conn_id: (idx + offset) as u64,
                destination: info.dest.to_string(),
                protocol: info.session_proto.write().unwrap().to_string(),
                proxy: format!("{:?}", info.rule).to_ascii_lowercase(),
                process: info.process_info.as_ref().map(|i| i.name.clone()),
                upload: info.upload_traffic.load(Ordering::Relaxed),
                download: info.download_traffic.load(Ordering::Relaxed),
                start_time: info
                    .start_time
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                active: !info.done.load(Ordering::Relaxed),
            };
            result.push(conn);
        }
        result
    }

    pub async fn stop_all_conn(&self) {
        let (list, _) = self.stat_center.get_copy();
        for entry in list {
            entry.abort().await;
        }
    }

    pub async fn stop_conn(&self, id: usize) -> bool {
        if let Some(ele) = self.stat_center.get_nth(id).await {
            ele.abort().await;
            true
        } else {
            false
        }
    }

    pub fn get_sessions(&self) -> Vec<SessionSchema> {
        let all_tcp = self.manager.get_all_tcp_sessions();
        let all_udp = self.manager.get_all_udp_sessions();
        let mut result = Vec::new();
        for x in all_tcp {
            let elapsed = x.last_time.elapsed().as_secs();
            let session = SessionSchema {
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
            let session = SessionSchema {
                pair: format!("{}:", x.source_addr.port(),),
                time: pretty_time(elapsed),
                tcp_open: None,
            };
            result.push(session);
        }
        result
    }

    fn collect_interception(
        list: Vec<HttpInterceptData>,
        offset: usize,
    ) -> Vec<HttpInterceptSchema> {
        let mut result = Vec::new();
        for (idx, data) in list.into_iter().enumerate() {
            let uri = data.get_full_uri();
            let item = boltapi::HttpInterceptSchema {
                intercept_id: (idx + offset) as u64,
                client: data.process_info.map(|proc| proc.name),
                uri,
                method: data.req.method.to_string(),
                status: data.resp.status.as_u16(),
                size: data.resp.body_len(),
                time: pretty_latency(data.resp.time - data.req.time),
            };
            result.push(item);
        }
        result
    }

    pub fn get_intercept(&self) -> Vec<HttpInterceptSchema> {
        if let Some(capturer) = &self.http_capturer {
            let (list, offset) = capturer.get_copy();
            Self::collect_interception(list, offset)
        } else {
            vec![]
        }
    }

    pub fn get_intercept_range(&self, params: &GetInterceptRangeReq) -> Vec<HttpInterceptSchema> {
        if let Some(capturer) = &self.http_capturer {
            if let Some((list, offset)) =
                capturer.get_range_copy(params.start as usize, params.end.map(|p| p as usize))
            {
                return Self::collect_interception(list, offset);
            }
        }
        vec![]
    }

    pub fn get_intercept_payload(&self, id: usize) -> Option<GetInterceptDataResp> {
        if let Some(capturer) = &self.http_capturer {
            if let Some((list, _)) = capturer.get_range_copy(id, Some(id + 1)) {
                if list.len() == 1 {
                    let HttpInterceptData {
                        host: _,
                        process_info: _,
                        req,
                        resp,
                    } = list.get(0).unwrap();
                    let (body, warning) = match &resp.body {
                        BodyOrWarning::Body(b) => (b.to_vec(), None),
                        BodyOrWarning::Warning(w) => (vec![], Some(w.clone())),
                    };
                    let result = GetInterceptDataResp {
                        req_header: req.collect_headers(),
                        req_body: req.body.to_vec(),
                        resp_header: resp.collect_headers(),
                        resp_body: body,
                        warning,
                    };
                    return Some(result);
                }
            }
        }
        None
    }

    pub async fn get_all_proxies(&self) -> Vec<GetGroupRespSchema> {
        let list = self.dispatching.read().await.get_group_list();
        let mut result = Vec::new();
        for g in list.iter() {
            let item = GetGroupRespSchema {
                name: g.get_name(),
                selected: pretty_proxy(&g.get_selection()).name,
                list: g.get_members().iter().map(pretty_proxy).collect(),
            };
            result.push(item);
        }
        result
    }

    pub async fn get_proxy_group(&self, group: String) -> Vec<GetGroupRespSchema> {
        let list = self.dispatching.read().await.get_group_list();
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
        result
    }

    pub async fn set_selection(&self, group: String, selected: String) -> bool {
        let r = self
            .dispatching
            .read()
            .await
            .set_group_selection(group.as_str(), selected.as_str())
            .is_ok();
        if r {
            let mut state = self.state.lock().unwrap();
            if let Some(val) = state.state.group_selection.get_mut(&group) {
                *val = selected;
            } else {
                state.state.group_selection.insert(group, selected);
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
        r
    }

    pub async fn update_latency(&self, group: String) {
        tracing::trace!("Start speedtest for group {}", group);
        let speedtest_url = self.speedtest_url.lock().unwrap().clone();
        let list = self.dispatching.read().await.get_group_list();
        for g in list.iter() {
            if g.get_name() == group {
                let iface = g.get_direct_interface();
                // update all latency inside the group
                let mut handles = vec![];
                for p in g.get_members() {
                    if let GeneralProxy::Single(p) = p {
                        if let Ok(h) = latency_test(
                            self.dispatcher.as_ref(),
                            p.clone(),
                            speedtest_url.as_str(),
                            Duration::from_secs(2),
                            iface.clone(),
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
    }

    pub async fn reload(&self) {
        let _ = self.reload_sender.send(()).await;
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
