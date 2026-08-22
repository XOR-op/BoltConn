use crate::common::call_chan::CallParameter;
use crate::config::{LinkedState, RuleConfigLine};
use crate::dispatch::{GeneralProxy, Latency};
use crate::external::{SharedDispatching, StreamLoggerRecv, StreamLoggerSend};
use crate::network::configure::TunConfigure;
use crate::network::dns::Dns;
use crate::platform::process::ParentProcess;
use crate::proxy::{
    ConnHandle, ConnRecordSnapshot, ContextManager, Dispatcher, HttpCapturer, HttpInterceptData,
    MappingSessionManager, latency_test,
};
use boltapi::{
    ApiError, ApiErrorCode, ConnDetail, ConnListRequest, ConnOrigin, ConnStopResult, ConnSummary,
    DnsLookupDetail, DnsLookupRequest, DnsLookupResponse, DnsOutcome, DnsResolverDetail,
    DnsResolverSummary, FakeIpMapping, GetGroupRespSchema, GetInterceptDataResp,
    GetInterceptRangeReq, HttpInterceptSchema, LinkDetail, LinkEvidence, LinkReason, LinkSummary,
    ProcessParentSchema, ProcessSchema, ProxyData, SessionSchema, Snapshot, Traffic, TrafficResp,
    TunStatusSchema,
};
use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Controller {
    manager: Arc<MappingSessionManager>,
    dns: Arc<Dns>,
    stat_center: Arc<ContextManager>,
    http_capturer: Option<Arc<HttpCapturer>>,
    dispatcher: Arc<Dispatcher>,
    dispatching: SharedDispatching,
    tun_configure: Arc<std::sync::Mutex<TunConfigure>>,
    reload_sender: Arc<tokio::sync::mpsc::Sender<CallParameter<(), bool>>>,
    state: Arc<tokio::sync::Mutex<LinkedState>>,
    stream_logger: StreamLoggerSend,
    speedtest_url: Arc<std::sync::RwLock<String>>,
}

impl Controller {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manager: Arc<MappingSessionManager>,
        dns: Arc<Dns>,
        stat_center: Arc<ContextManager>,
        http_capturer: Option<Arc<HttpCapturer>>,
        dispatcher: Arc<Dispatcher>,
        dispatching: SharedDispatching,
        global_setting: Arc<std::sync::Mutex<TunConfigure>>,
        reload_sender: tokio::sync::mpsc::Sender<CallParameter<(), bool>>,
        state: Arc<tokio::sync::Mutex<LinkedState>>,
        stream_logger: StreamLoggerSend,
        speedtest_url: Arc<std::sync::RwLock<String>>,
    ) -> Self {
        Self {
            manager,
            dns,
            stat_center,
            http_capturer,
            tun_configure: global_setting,
            dispatcher,
            dispatching,
            reload_sender: Arc::new(reload_sender),
            state,
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
            self.tun_configure.lock().unwrap().disable(true).is_ok()
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

    pub fn list_conn(&self, request: ConnListRequest) -> Snapshot<ConnSummary> {
        let observed_at_ms = now_ms();
        connection_snapshot_at(self.stat_center.as_ref(), request, observed_at_ms, false)
    }

    /// Full replacement snapshot used by both HTTP and UDS streams.
    pub fn active_conn_snapshot(&self) -> Snapshot<ConnSummary> {
        let observed_at_ms = now_ms();
        connection_snapshot_at(
            self.stat_center.as_ref(),
            ConnListRequest::default(),
            observed_at_ms,
            true,
        )
    }

    pub fn show_conn(&self, id: u64) -> Result<ConnDetail, ApiError> {
        show_connection_at(self.stat_center.as_ref(), id, now_ms())
    }

    pub fn stop_conn(&self, id: u64) -> Result<ConnStopResult, ApiError> {
        stop_connection(self.stat_center.as_ref(), id)
    }

    pub fn stop_all_conn(&self) -> ConnStopResult {
        stop_all_connections(self.stat_center.as_ref())
    }

    pub fn get_conn_history_limit(&self) -> u32 {
        self.stat_center.get_conn_history_limit()
    }

    pub async fn set_conn_history_limit(&self, limit: u32) -> u32 {
        let mut state = self.state.lock().await;
        self.stat_center.set_conn_history_limit(limit);
        // Retain the existing persisted key; only the runtime/API terminology
        // changed from a log limit to terminal connection history.
        state.state.log_limit = Some(limit);
        Self::flush_state(&state);
        self.stat_center.get_conn_history_limit()
    }

    pub async fn list_link(&self) -> Snapshot<LinkSummary> {
        self.dispatcher.refresh_link_evidence().await;
        let observed_at_ms = now_ms();
        let mut snapshot = self.dispatcher.link_table().snapshot(observed_at_ms);
        for summary in &mut snapshot.items {
            sanitize_link_summary(summary);
        }
        snapshot
    }

    pub async fn show_link(&self, name: String) -> Result<LinkDetail, ApiError> {
        self.dispatcher.refresh_link_evidence().await;
        let observed_at_ms = now_ms();
        let mut detail = self
            .dispatcher
            .link_table()
            .detail_result(&name, observed_at_ms)
            .map_err(sanitize_api_error)?;
        sanitize_link_detail(&mut detail);
        Ok(detail)
    }

    pub async fn stop_link(&self, name: String) -> Result<(), ApiError> {
        self.dispatcher
            .stop_link(&name)
            .await
            .map_err(sanitize_api_error)
    }

    pub fn list_dns(&self) -> Snapshot<DnsResolverSummary> {
        let observed_at_ms = now_ms();
        let mut items = self.dns.resolver_snapshot_at(observed_at_ms).items;
        items.extend(
            self.dispatcher
                .link_table()
                .dns_resolver_summaries(observed_at_ms),
        );
        crate::network::dns::sort_resolver_summaries(&mut items);
        for summary in &mut items {
            sanitize_dns_outcome(summary.last_result.as_mut());
        }
        Snapshot {
            observed_at_ms,
            items,
        }
    }

    pub fn show_dns(&self, id_prefix: String) -> Result<DnsResolverDetail, ApiError> {
        let observed_at_ms = now_ms();
        let global = self.dns.resolver_snapshot_at(observed_at_ms).items;
        let link_table = self.dispatcher.link_table();
        let link = link_table.dns_resolver_summaries(observed_at_ms);
        let (id, owner) = resolve_observed_resolver_prefix(&global, &link, &id_prefix)?;
        let mut detail = match owner {
            ResolverOwner::Global => self
                .dns
                .resolver_detail_at(&id, observed_at_ms)
                .map_err(sanitize_api_error)?,
            ResolverOwner::Link => link_table
                .dns_resolver_detail(&id, observed_at_ms)
                .ok_or_else(|| resolver_unavailable(&id))?,
        };
        sanitize_dns_detail(&mut detail);
        Ok(detail)
    }

    pub async fn lookup_dns(
        &self,
        mut request: DnsLookupRequest,
    ) -> Result<DnsLookupResponse, ApiError> {
        crate::network::dns::validate_diagnostic_domain(&request.domain)?;
        let lookup = if let Some(prefix) = request.resolver_id.take() {
            let link_table = self.dispatcher.link_table();
            let global_ids = self.dns.resolver_ids();
            let link_ids = link_table.dns_resolver_ids();
            let (id, owner) = resolve_live_resolver_prefix(&global_ids, &link_ids, &prefix)?;
            match owner {
                ResolverOwner::Global => self
                    .dns
                    .diagnostic_lookup_detail(DnsLookupRequest {
                        domain: request.domain,
                        resolver_id: Some(id.clone()),
                    })
                    .await
                    .map_err(|error| resolver_race_error(error, &id))?,
                ResolverOwner::Link => link_table
                    .diagnostic_dns_lookup(&id, request.domain)
                    .await
                    .map_err(sanitize_api_error)?,
            }
        } else {
            self.dns
                .diagnostic_lookup_detail(request)
                .await
                .map_err(sanitize_api_error)?
        };
        let observed_at_ms = now_ms();
        let mut response = DnsLookupResponse {
            observed_at_ms,
            lookup,
        };
        sanitize_dns_lookup(&mut response.lookup);
        Ok(response)
    }

    pub fn get_dns_mapping(&self, fake_ip: IpAddr) -> Result<FakeIpMapping, ApiError> {
        self.dns
            .fake_ip_mapping(fake_ip)
            .map_err(sanitize_api_error)
    }

    fn to_process_schema(info: &crate::platform::process::ProcessInfo) -> ProcessSchema {
        let mut parents = Vec::new();
        let mut current = &info.parent;
        loop {
            match current {
                ParentProcess::None => break,
                ParentProcess::Ppid(ppid) => {
                    parents.push(ProcessParentSchema {
                        pid: *ppid,
                        name: None,
                        path: None,
                        cmdline: None,
                        cwd: None,
                    });
                    break;
                }
                ParentProcess::Process(p) => {
                    parents.push(ProcessParentSchema {
                        pid: p.pid,
                        name: Some(p.name.clone()),
                        path: Some(p.path.clone()),
                        cmdline: Some(p.cmdline.clone()),
                        cwd: Some(p.cwd.clone()),
                    });
                    current = &p.parent;
                }
            }
        }

        ProcessSchema {
            pid: info.pid,
            path: info.path.clone(),
            name: info.name.clone(),
            cmdline: info.cmdline.clone(),
            cwd: info.cwd.clone(),
            parents,
            tag: info.tag.clone(),
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
            let elapsed = x.activity.idle_duration().as_secs();
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
                start_time: data.req.time.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                duration: pretty_latency(
                    data.resp
                        .time
                        .duration_since(data.req.time)
                        .unwrap_or_default(),
                ),
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
        if let Some(capturer) = &self.http_capturer
            && let Some((list, offset)) =
                capturer.get_range_copy(params.start as usize, params.end.map(|p| p as usize))
        {
            return Self::collect_interception(list, offset);
        }

        vec![]
    }

    pub fn get_intercept_payload(&self, id: usize) -> Option<GetInterceptDataResp> {
        if let Some(capturer) = &self.http_capturer
            && let Some((list, _)) = capturer.get_range_copy(id, Some(id + 1))
            && list.len() == 1
        {
            let HttpInterceptData {
                host: _,
                process_info: _,
                req,
                resp,
            } = list.first().unwrap();
            let result = GetInterceptDataResp {
                req_header: req.collect_headers(),
                req_body: req.body.to_captured_schema(),
                resp_header: resp.collect_headers(),
                resp_body: resp.body.to_captured_schema(),
            };
            return Some(result);
        }
        None
    }

    pub fn get_all_proxies(&self) -> Vec<GetGroupRespSchema> {
        let list = self.dispatching.load().get_group_list();
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

    pub fn get_proxy_group(&self, group: String) -> Vec<GetGroupRespSchema> {
        let list = self.dispatching.load().get_group_list();
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
        let mut state = self.state.lock().await;
        if self
            .dispatching
            .load()
            .set_group_selection(group.as_str(), selected.as_str())
            .await
            .is_ok()
        {
            if let Some(val) = state.state.group_selection.get_mut(&group) {
                *val = selected;
            } else {
                state.state.group_selection.insert(group, selected);
            }
            Self::flush_state(&state);
            true
        } else {
            false
        }
    }

    pub async fn add_temporary_rule(&self, rule_literal: String) -> bool {
        let mut state = self.state.lock().await;
        let old = state.state.temporary_list.clone().unwrap_or_default();
        let mut list = vec![RuleConfigLine::Simple(rule_literal.clone())];
        list.extend(old);

        if let Err(e) = self.dispatching.load().update_temporary_list(&list) {
            tracing::debug!("Adding rule {} failed: {}", rule_literal, e);
            false
        } else {
            state.state.temporary_list = Some(list);
            Self::flush_state(&state);
            true
        }
    }

    pub async fn delete_temporary_rule(&self, rule_literal_prefix: String) -> bool {
        let mut state = self.state.lock().await;
        let mut list = state.state.temporary_list.clone().unwrap_or_default();
        let Ok(new_rule) = serde_yaml::from_str::<serde_yaml::Sequence>(
            (String::from("[") + rule_literal_prefix.as_str() + "]").as_str(),
        ) else {
            return false;
        };
        let mut has_changed = false;
        list.retain(|line| {
            if let RuleConfigLine::Simple(line) = &line {
                let Ok(parsed_line) = serde_yaml::from_str::<serde_yaml::Sequence>(
                    (String::from("[") + line + "]").as_str(),
                ) else {
                    has_changed = true;
                    return false;
                };
                if (parsed_line.len() == new_rule.len() && parsed_line == new_rule)
                    || (parsed_line.len() == new_rule.len() + 1
                        && parsed_line.as_slice()[..parsed_line.len() - 1] == new_rule)
                {
                    has_changed = true;
                    return false;
                }
            }
            true
        });
        if !has_changed {
            return false;
        }

        if self.dispatching.load().update_temporary_list(&list).is_ok() {
            state.state.temporary_list = if list.is_empty() { None } else { Some(list) };
            Self::flush_state(&state);
            true
        } else {
            false
        }
    }

    pub async fn list_temporary_rule(&self) -> Vec<String> {
        let state = self.state.lock().await;
        state
            .state
            .temporary_list
            .as_ref()
            .map(|list| {
                list.iter()
                    .filter_map(|item| {
                        if let RuleConfigLine::Simple(line) = item {
                            Some(line.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn clear_temporary_rule(&self) {
        let mut state = self.state.lock().await;
        let _ = self.dispatching.load().update_temporary_list(&[]);
        state.state.temporary_list = None;
        Self::flush_state(&state);
    }

    fn flush_state(state: &LinkedState) {
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

    pub async fn update_latency(&self, group: String) {
        tracing::trace!("Start speedtest for group {}", group);
        let speedtest_url = self.speedtest_url.read().unwrap().clone();
        let list = self.dispatching.load().get_group_list();
        for g in list.iter() {
            if g.get_name() == group {
                let iface = g.get_direct_interface();
                // update all latency inside the group
                let mut handles = vec![];
                let mut tested_proxy = HashSet::new();
                for p in g.get_members() {
                    let p = match p {
                        GeneralProxy::Single(p) => p,
                        GeneralProxy::Group(g) => &g.get_proxy(),
                    };
                    if tested_proxy.contains(&p.get_name()) {
                        continue;
                    }
                    tested_proxy.insert(p.get_name());
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
                for h in handles {
                    let _ = h.await;
                }
                break;
            }
        }
    }

    pub async fn reload(&self) -> bool {
        let (call_param, call_fut) = CallParameter::new(());
        if self.reload_sender.send(call_param).await.is_ok() {
            call_fut.await.unwrap_or(false)
        } else {
            false
        }
    }
}

fn connection_snapshot_at(
    manager: &ContextManager,
    request: ConnListRequest,
    observed_at_ms: u64,
    active_only: bool,
) -> Snapshot<ConnSummary> {
    let mut connections = if let Some(link) = request.link {
        manager.get_active_for_link(&link)
    } else if active_only {
        manager.active_records()
    } else {
        let mut connections = manager.active_records();
        connections.extend(manager.terminal_records());
        connections
    };
    connections.sort_unstable_by_key(ConnHandle::id);
    connections.dedup_by_key(|connection| connection.id());
    Snapshot {
        observed_at_ms,
        items: connections
            .into_iter()
            .map(|connection| conn_summary(&connection.snapshot(), observed_at_ms))
            .collect(),
    }
}

fn show_connection_at(
    manager: &ContextManager,
    id: u64,
    observed_at_ms: u64,
) -> Result<ConnDetail, ApiError> {
    let connection = manager.get(id).ok_or_else(|| {
        api_error(
            ApiErrorCode::ConnNotFound,
            format!("connection {id} was not found"),
        )
    })?;
    Ok(conn_detail(connection.snapshot(), observed_at_ms))
}

fn stop_connection(manager: &ContextManager, id: u64) -> Result<ConnStopResult, ApiError> {
    let connection = manager.get(id).ok_or_else(|| {
        api_error(
            ApiErrorCode::ConnNotFound,
            format!("connection {id} was not found"),
        )
    })?;
    if connection.done() {
        return Err(api_error(
            ApiErrorCode::ConnNotActive,
            format!("connection {id} is already closed"),
        ));
    }
    if manager.stop(id) {
        Ok(ConnStopResult {
            stopped_connections: 1,
        })
    } else if manager.get(id).is_some() {
        Err(api_error(
            ApiErrorCode::ConnNotActive,
            format!("connection {id} is already closed"),
        ))
    } else {
        // With history disabled, a completion racing the stop can immediately
        // evict the record; it is then indistinguishable from any evicted ID.
        Err(api_error(
            ApiErrorCode::ConnNotFound,
            format!("connection {id} was not found"),
        ))
    }
}

fn stop_all_connections(manager: &ContextManager) -> ConnStopResult {
    let stopped_connections = manager
        .active_records()
        .into_iter()
        .filter(|connection| connection.abort())
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    ConnStopResult {
        stopped_connections,
    }
}

fn conn_summary(snapshot: &ConnRecordSnapshot, observed_at_ms: u64) -> ConnSummary {
    let target = snapshot
        .state
        .flow
        .identified
        .as_ref()
        .map(|identified| identified.target.clone())
        .unwrap_or_else(|| snapshot.state.flow.accepted.clone());
    let origin = snapshot
        .start
        .conn_info
        .process_info
        .as_ref()
        .map(|process| ConnOrigin::Process {
            name: process.name.clone(),
            tag: process.tag.clone(),
        })
        .unwrap_or_else(|| ConnOrigin::Network {
            source_ip: snapshot.start.conn_info.src.ip(),
        });
    ConnSummary {
        id: snapshot.start.id,
        state: snapshot.state.state,
        started_at_ms: snapshot.start.started_at_ms,
        duration_ms: snapshot
            .state
            .ended_at_ms
            .unwrap_or(observed_at_ms)
            .saturating_sub(snapshot.start.started_at_ms),
        origin,
        protocol: snapshot.state.session_protocol,
        target,
        via: snapshot
            .state
            .route
            .as_ref()
            .map(|route| route.selected.clone()),
        traffic: Traffic {
            upload_bytes: snapshot.upload_bytes,
            download_bytes: snapshot.download_bytes,
        },
        result: snapshot
            .state
            .termination
            .as_ref()
            .map(|termination| termination.code),
    }
}

fn conn_detail(snapshot: ConnRecordSnapshot, observed_at_ms: u64) -> ConnDetail {
    let summary = conn_summary(&snapshot, observed_at_ms);
    let mut termination = snapshot.state.termination;
    if let Some(termination) = &mut termination {
        sanitize_text(&mut termination.detail);
    }
    let mut dns = snapshot.state.dns;
    for lookup in &mut dns.lookups {
        sanitize_dns_lookup(lookup);
    }
    ConnDetail {
        observed_at_ms,
        summary,
        established_at_ms: snapshot.state.established_at_ms,
        ended_at_ms: snapshot.state.ended_at_ms,
        flow: snapshot.state.flow,
        process: snapshot
            .start
            .conn_info
            .process_info
            .as_ref()
            .map(Controller::to_process_schema),
        route: snapshot.state.route,
        dns,
        links: snapshot.state.links,
        termination,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolverOwner {
    Global,
    Link,
}

fn resolve_observed_resolver_prefix(
    global: &[DnsResolverSummary],
    link: &[DnsResolverSummary],
    prefix: &str,
) -> Result<(String, ResolverOwner), ApiError> {
    resolve_resolver_prefix(
        global
            .iter()
            .map(|summary| (summary.id.as_str(), ResolverOwner::Global))
            .chain(
                link.iter()
                    .map(|summary| (summary.id.as_str(), ResolverOwner::Link)),
            ),
        prefix,
    )
}

fn resolve_live_resolver_prefix(
    global: &[String],
    link: &[String],
    prefix: &str,
) -> Result<(String, ResolverOwner), ApiError> {
    resolve_resolver_prefix(
        global
            .iter()
            .map(|id| (id.as_str(), ResolverOwner::Global))
            .chain(link.iter().map(|id| (id.as_str(), ResolverOwner::Link))),
        prefix,
    )
}

fn resolve_resolver_prefix<'a>(
    candidates: impl Iterator<Item = (&'a str, ResolverOwner)>,
    prefix: &str,
) -> Result<(String, ResolverOwner), ApiError> {
    if prefix.is_empty() {
        return Err(resolver_not_found(prefix));
    }
    let mut matches = candidates
        .filter(|(id, _)| id.starts_with(prefix))
        .map(|(id, owner)| (id.to_string(), owner))
        .collect::<Vec<_>>();
    matches.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    matches.dedup();
    match matches.as_slice() {
        [] => Err(resolver_not_found(prefix)),
        [resolved] => Ok(resolved.clone()),
        _ => Err(api_error(
            ApiErrorCode::ResolverIdAmbiguous,
            format!("resolver ID prefix {prefix:?} is ambiguous"),
        )),
    }
}

fn resolver_not_found(prefix: &str) -> ApiError {
    api_error(
        ApiErrorCode::ResolverNotFound,
        format!("resolver ID prefix {prefix:?} was not found"),
    )
}

fn resolver_unavailable(id: &str) -> ApiError {
    api_error(
        ApiErrorCode::ResolverUnavailable,
        format!("resolver {id} is not available in the live runtime"),
    )
}

fn resolver_race_error(error: ApiError, id: &str) -> ApiError {
    if error.code == ApiErrorCode::ResolverNotFound {
        resolver_unavailable(id)
    } else {
        sanitize_api_error(error)
    }
}

fn api_error(code: ApiErrorCode, message: String) -> ApiError {
    ApiError {
        code,
        message: crate::proxy::bounded_error_detail(&message),
    }
}

fn sanitize_api_error(mut error: ApiError) -> ApiError {
    error.message = crate::proxy::bounded_error_detail(&error.message);
    error
}

fn sanitize_text(detail: &mut Option<String>) {
    if let Some(detail) = detail {
        *detail = crate::proxy::bounded_error_detail(detail);
    }
}

fn sanitize_link_reason(reason: &mut Option<LinkReason>) {
    if let Some(reason) = reason {
        sanitize_text(&mut reason.detail);
    }
}

fn sanitize_link_summary(summary: &mut LinkSummary) {
    sanitize_link_reason(&mut summary.reason);
}

fn sanitize_link_detail(detail: &mut LinkDetail) {
    sanitize_link_summary(&mut detail.summary);
    match &mut detail.evidence {
        LinkEvidence::Wireguard { .. } => {}
        LinkEvidence::Ssh { probe, .. } => {
            if let Some(probe) = probe {
                sanitize_link_reason(&mut probe.last_error);
            }
        }
        LinkEvidence::Anytls {
            problematic_session,
            ..
        } => {
            if let Some(session) = problematic_session {
                sanitize_text(&mut session.reason.detail);
            }
        }
    }
    if let Some(lookup) = &mut detail.dns.latest_lookup {
        sanitize_dns_lookup(lookup);
    }
}

fn sanitize_dns_outcome(outcome: Option<&mut DnsOutcome>) {
    if let Some(DnsOutcome::Error { detail, .. }) = outcome {
        sanitize_text(detail);
    }
}

fn sanitize_dns_lookup(lookup: &mut DnsLookupDetail) {
    sanitize_dns_outcome(Some(&mut lookup.result));
    for attempt in &mut lookup.attempts {
        sanitize_dns_outcome(Some(&mut attempt.result));
    }
}

fn sanitize_dns_detail(detail: &mut DnsResolverDetail) {
    sanitize_dns_outcome(detail.summary.last_result.as_mut());
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn pretty_proxy(g: &GeneralProxy) -> ProxyData {
    let latency_to_str = |latency: Latency| match latency {
        Latency::Unknown => None,
        Latency::Value(ms) => Some(format!("{ms} ms")),
        Latency::Failed => Some("Failed".to_string()),
    };
    match g {
        GeneralProxy::Single(p) => ProxyData {
            name: p.get_name(),
            proto: p.get_impl().simple_description(),
            latency: latency_to_str(p.get_latency()),
        },
        GeneralProxy::Group(g) => ProxyData {
            name: g.get_name(),
            proto: "group".to_string(),
            latency: latency_to_str(g.get_proxy().get_latency()),
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

#[cfg(test)]
mod observability_tests {
    use super::*;
    use crate::dispatch::{ConnInfo, InboundInfo};
    use crate::platform::process::{NetworkType, ProcessInfo};
    use crate::proxy::{ConnAbortHandle, NetworkAddr};
    use boltapi::{
        ConfigSourceLocation, ConnResultCode, ConnStage, DnsEndpoint, DnsProtocol, DnsScope,
        RouteDecision, RouteEgress, RouteSelection, RuleOrigin,
    };

    fn process() -> ProcessInfo {
        ProcessInfo {
            pid: 42,
            parent: ParentProcess::Ppid(1),
            path: "/usr/bin/curl".to_string(),
            name: "curl".to_string(),
            cmdline: "curl https://example.com".to_string(),
            cwd: "/tmp".to_string(),
            tag: Some("api-test".to_string()),
        }
    }

    fn begin_connection(
        manager: &ContextManager,
        port: u16,
        process_info: Option<ProcessInfo>,
    ) -> ConnHandle {
        let target = NetworkAddr::Socket {
            address: "192.0.2.10:443".parse().unwrap(),
        };
        manager.begin(
            ConnInfo {
                src: format!("127.0.0.1:{port}").parse().unwrap(),
                dst: target.clone(),
                local_ip: None,
                inbound: InboundInfo::Tun,
                resolved_dst: None,
                connection_type: NetworkType::Tcp,
                process_info,
            },
            target,
            None,
            ConnAbortHandle::placeholder(),
        )
    }

    #[test]
    fn connection_projection_is_ordered_and_preserves_terminal_invariants() {
        let manager = ContextManager::new(10);
        let first = begin_connection(&manager, 10_001, Some(process()));
        let second = begin_connection(&manager, 10_002, None);
        assert!(first.set_identified_target(
            NetworkAddr::Domain {
                name: "example.com".to_string(),
                port: 443,
            },
            boltapi::IdentificationSource::TlsSni,
        ));
        assert!(first.set_route(RouteDecision {
            matched_rule: "domain(example.com)".to_string(),
            origin: RuleOrigin::Config {
                location: ConfigSourceLocation {
                    path: "config.yml".to_string(),
                    document_path: "rules[0]".to_string(),
                },
            },
            expanded_from: Vec::new(),
            selected: RouteSelection {
                group: Some("US".to_string()),
                selected: "ssh-us".to_string(),
            },
        }));
        first.more_upload(11);
        first.more_download(17);
        let unsafe_detail = format!("{}{}", "x".repeat(300), "\nunsafe");
        assert!(second.finish(
            ConnResultCode::ConnectError,
            Some(ConnStage::Connecting),
            Some(unsafe_detail),
        ));

        let observed_at_ms = first.metadata().started_at_ms.saturating_add(500);
        let snapshot =
            connection_snapshot_at(&manager, ConnListRequest::default(), observed_at_ms, false);
        assert_eq!(
            snapshot
                .items
                .iter()
                .map(|item| item.id)
                .collect::<Vec<_>>(),
            vec![first.id(), second.id()]
        );
        let first_summary = &snapshot.items[0];
        assert_eq!(
            first_summary.duration_ms,
            observed_at_ms.saturating_sub(first.metadata().started_at_ms)
        );
        assert!(matches!(
            &first_summary.origin,
            ConnOrigin::Process { name, tag }
                if name == "curl" && tag.as_deref() == Some("api-test")
        ));
        assert!(matches!(
            &first_summary.target,
            NetworkAddr::Domain { name, port } if name == "example.com" && *port == 443
        ));
        assert_eq!(first_summary.via.as_ref().unwrap().selected, "ssh-us");
        assert_eq!(first_summary.traffic.upload_bytes, 11);
        assert!(first_summary.result.is_none());
        assert_eq!(
            connection_snapshot_at(&manager, ConnListRequest::default(), observed_at_ms, true,)
                .items
                .iter()
                .map(|item| item.id)
                .collect::<Vec<_>>(),
            vec![first.id()]
        );

        let second_snapshot = second.snapshot();
        let ended_at_ms = second_snapshot.state.ended_at_ms.unwrap();
        let detail = show_connection_at(&manager, second.id(), ended_at_ms + 100).unwrap();
        assert_eq!(
            detail.summary.duration_ms,
            ended_at_ms.saturating_sub(second.metadata().started_at_ms)
        );
        assert_eq!(detail.summary.result, Some(ConnResultCode::ConnectError));
        assert_eq!(
            detail.termination.as_ref().unwrap().code,
            detail.summary.result.unwrap()
        );
        let detail_text = detail
            .termination
            .as_ref()
            .unwrap()
            .detail
            .as_deref()
            .unwrap();
        assert!(detail_text.chars().count() <= 256);
        assert!(!detail_text.chars().any(char::is_control));
        assert!(detail.established_at_ms.is_none());
        assert!(detail.process.is_none());
    }

    #[test]
    fn connection_stop_errors_distinguish_missing_and_inactive_records() {
        let manager = ContextManager::new(10);
        assert_eq!(
            stop_connection(&manager, 99).unwrap_err().code,
            ApiErrorCode::ConnNotFound
        );
        let first = begin_connection(&manager, 10_001, None);
        assert_eq!(
            stop_connection(&manager, first.id())
                .unwrap()
                .stopped_connections,
            1
        );
        assert_eq!(
            stop_connection(&manager, first.id()).unwrap_err().code,
            ApiErrorCode::ConnNotActive
        );

        begin_connection(&manager, 10_002, None);
        begin_connection(&manager, 10_003, None);
        assert_eq!(stop_all_connections(&manager).stopped_connections, 2);
        assert!(manager.active_records().is_empty());
    }

    fn resolver_summary(id: &str, scope: DnsScope) -> DnsResolverSummary {
        DnsResolverSummary {
            id: id.to_string(),
            scopes: vec![scope],
            protocol: DnsProtocol::Udp,
            endpoint: DnsEndpoint::Network {
                addresses: Vec::new(),
            },
            via: RouteEgress::Direct,
            lookups: 1,
            p50_latency_ms: Some(10),
            last_result: None,
            last_active_at_ms: Some(1),
        }
    }

    #[test]
    fn resolver_prefixes_share_one_namespace_and_rows_follow_scope_order() {
        let global = vec![resolver_summary("abc000", DnsScope::Global { order: 2 })];
        let link = vec![resolver_summary(
            "abd000",
            DnsScope::Link {
                name: "wg-us".to_string(),
            },
        )];
        assert_eq!(
            resolve_observed_resolver_prefix(&global, &link, "abc").unwrap(),
            ("abc000".to_string(), ResolverOwner::Global)
        );
        assert_eq!(
            resolve_observed_resolver_prefix(&global, &link, "ab")
                .unwrap_err()
                .code,
            ApiErrorCode::ResolverIdAmbiguous
        );
        let oversized_missing = "z".repeat(1_000);
        let error =
            resolve_observed_resolver_prefix(&global, &link, &oversized_missing).unwrap_err();
        assert_eq!(error.code, ApiErrorCode::ResolverNotFound);
        assert!(error.message.chars().count() <= 256);

        let mut rows = vec![
            link[0].clone(),
            resolver_summary(
                "policy",
                DnsScope::Policy {
                    matchers: vec!["*.corp".to_string()],
                },
            ),
            global[0].clone(),
            resolver_summary("global-one", DnsScope::Global { order: 1 }),
        ];
        crate::network::dns::sort_resolver_summaries(&mut rows);
        assert_eq!(
            rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            vec!["global-one", "abc000", "policy", "abd000"]
        );
    }
}
