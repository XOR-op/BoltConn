use crate::common::StreamOutboundTrait;
use crate::common::cbor::CborCodec;
use crate::external::Controller;
use crate::proxy::error::SystemError;
use boltapi::multiplex::rpc_multiplex_twoway;
use boltapi::rpc::{ClientStreamServiceClient, ControlService};
use boltapi::{
    ApiError, ConnDetail, ConnListRequest, ConnStopResult, ConnSummary, DnsLookupRequest,
    DnsLookupResponse, DnsResolverDetail, DnsResolverSummary, FakeIpMapping, GetGroupRespSchema,
    GetInterceptDataResp, GetInterceptRangeReq, HttpInterceptSchema, LinkDetail, LinkSummary,
    Snapshot, TrafficResp, TunStatusSchema,
};
use futures::{FutureExt, StreamExt};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tarpc::context::Context;
use tarpc::server::{BaseChannel, Channel};
use tarpc::tokio_util::codec::LengthDelimitedCodec;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

pub struct UnixListenerGuard {
    path: String,
    // The option is used only for destruction. It's not possible to move out of the listener.
    #[cfg(unix)]
    listener: Option<UnixListener>,
    #[cfg(windows)]
    listener: tokio::sync::Mutex<NamedPipeServer>,
}

impl UnixListenerGuard {
    pub fn new(path: &str) -> Result<Self, SystemError> {
        #[cfg(unix)]
        {
            use crate::common::{UnwrapInfallible, as_io_err};
            use crate::platform::get_user_info;
            use std::path::PathBuf;
            use std::str::FromStr;
            let path = PathBuf::from_str(path).infallible();
            let listener = UnixListener::bind(&path).map_err(SystemError::Controller)?;
            if let Some(user_info) = get_user_info() {
                user_info
                    .chown(&path)
                    .map_err(|e| SystemError::Controller(as_io_err(e)))?;
            }
            Ok(Self {
                path: path.to_string_lossy().to_string(),
                listener: Some(listener),
            })
        }
        #[cfg(windows)]
        {
            let listener = ServerOptions::new()
                .first_pipe_instance(true)
                .create(path)
                .map_err(SystemError::Controller)?;
            Ok(Self {
                path: path.to_string(),
                listener: tokio::sync::Mutex::new(listener),
            })
        }
    }

    pub async fn accept(&self) -> io::Result<impl StreamOutboundTrait> {
        #[cfg(unix)]
        return Ok(self.listener.as_ref().unwrap().accept().await?.0);
        #[cfg(windows)]
        {
            use std::mem;
            let mut listener_guard = self.listener.lock().await;
            listener_guard.connect().await?;
            // ensure there are always at least one server alive
            let mut new_listener = ServerOptions::new().create(&self.path)?;
            // swap the listener so the established connection can be returned
            mem::swap(&mut *listener_guard, &mut new_listener);
            Ok(new_listener)
        }
    }
}

impl Drop for UnixListenerGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            self.listener = None;
            if let Err(e) = std::fs::remove_file(&self.path) {
                tracing::warn!("Error when removing unix domain socket: {}", e)
            }
        }
    }
}

#[derive(Clone)]
pub struct UdsController {
    controller: Arc<Controller>,
}

impl UdsController {
    pub fn new(controller: Arc<Controller>) -> Self {
        Self { controller }
    }

    pub async fn run(self, listener: Arc<UnixListenerGuard>) -> io::Result<()> {
        let mut codec_builder = LengthDelimitedCodec::builder();
        codec_builder.max_frame_length(boltapi::rpc::MAX_CODEC_FRAME_LENGTH);
        loop {
            let conn = listener.accept().await?;
            let framed = codec_builder.new_framed(conn);
            let transport = tarpc::serde_transport::new(framed, CborCodec::default());
            let (server_t, client_t, in_task, out_task) = rpc_multiplex_twoway(transport);
            tokio::spawn(in_task);
            tokio::spawn(out_task);

            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            let client = ClientStreamServiceClient::new(Default::default(), client_t).spawn();
            tokio::spawn(
                UdsRpcBackClient {
                    client,
                    controller: self.controller.clone(),
                }
                .run(receiver),
            );

            tokio::spawn(
                BaseChannel::with_defaults(server_t)
                    .execute(
                        UdsRpcServer {
                            controller: self.controller.clone(),
                            sender,
                        }
                        .serve(),
                    )
                    .for_each(|rpc| tokio::spawn(rpc).map(|_| ())),
            );
        }
    }
}

#[derive(Clone, Debug)]
enum ClientRequests {
    Traffic(u64),
    ConnectionStream(u64),
    Logs(u64),
}

struct UdsRpcBackClient {
    client: ClientStreamServiceClient,
    controller: Arc<Controller>,
}

impl UdsRpcBackClient {
    pub async fn run(self, mut receiver: tokio::sync::mpsc::UnboundedReceiver<ClientRequests>) {
        let me = Arc::new(self);
        let mut will_continue = true;
        while will_continue {
            will_continue = match receiver.recv().await {
                Some(req) => {
                    me.clone().process_request(req).await;
                    true
                }
                _ => false,
            };
        }
    }

    async fn process_request(self: Arc<Self>, req: ClientRequests) {
        match req {
            ClientRequests::Traffic(ctx_id) => {
                // spawn traffic processing coroutine
                tokio::spawn(async move {
                    let TrafficResp {
                        upload: mut last_upload,
                        download: mut last_download,
                        upload_speed: _,
                        download_speed: _,
                    } = self.controller.get_traffic();
                    let mut interval_ms = 1000;

                    loop {
                        let TrafficResp {
                            upload,
                            download,
                            upload_speed: _,
                            download_speed: _,
                        } = self.controller.get_traffic();
                        let up_speed = (upload - last_upload) * 1000 / interval_ms;
                        let down_speed = (download - last_download) * 1000 / interval_ms;
                        interval_ms = if up_speed > 0 || down_speed > 0 {
                            500
                        } else {
                            1000
                        };
                        let data = TrafficResp {
                            upload,
                            download,
                            upload_speed: Some(up_speed),
                            download_speed: Some(down_speed),
                        };
                        last_upload = upload;
                        last_download = download;
                        if !self
                            .client
                            .post_traffic(Context::current(), data)
                            .await
                            .is_ok_and(|x| x == ctx_id)
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
                    }
                });
            }
            ClientRequests::ConnectionStream(ctx_id) => {
                tokio::spawn(async move {
                    let interval_ms = 1000;
                    loop {
                        let snapshot = self.controller.active_conn_snapshot();
                        if !self
                            .client
                            .post_connections(Context::current(), snapshot)
                            .await
                            .is_ok_and(|x| x == ctx_id)
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
                    }
                });
            }
            ClientRequests::Logs(ctx_id) => {
                let mut log_receiver = self.controller.get_log_subscriber();
                tokio::spawn(async move {
                    while let Ok(log) = log_receiver.recv().await {
                        if !self
                            .client
                            .post_log(Context::current(), log)
                            .await
                            .is_ok_and(|x| x == ctx_id)
                        {
                            break;
                        }
                    }
                });
            }
        }
    }
}

#[derive(Clone)]
struct UdsRpcServer {
    controller: Arc<Controller>,
    sender: tokio::sync::mpsc::UnboundedSender<ClientRequests>,
}

impl ControlService for UdsRpcServer {
    async fn get_all_proxies(self, _ctx: Context) -> Vec<GetGroupRespSchema> {
        self.controller.get_all_proxies()
    }

    async fn get_proxy_group(self, _ctx: Context, group: String) -> Vec<GetGroupRespSchema> {
        self.controller.get_proxy_group(group)
    }

    async fn set_proxy_for(self, _ctx: Context, group: String, proxy: String) -> bool {
        self.controller.set_selection(group, proxy).await
    }

    async fn update_group_latency(self, _ctx: Context, group: String) -> bool {
        self.controller.update_latency(group).await;
        true
    }

    async fn get_all_interceptions(self, _ctx: Context) -> Vec<HttpInterceptSchema> {
        self.controller.get_intercept()
    }

    async fn get_range_interceptions(
        self,
        _ctx: Context,
        start: u32,
        end: Option<u32>,
    ) -> Vec<HttpInterceptSchema> {
        self.controller
            .get_intercept_range(&GetInterceptRangeReq { start, end })
    }

    async fn get_intercepted_payload(self, _ctx: Context, id: u32) -> Option<GetInterceptDataResp> {
        self.controller.get_intercept_payload(id as usize)
    }

    async fn list_conn(self, _ctx: Context, request: ConnListRequest) -> Snapshot<ConnSummary> {
        self.controller.list_conn(request)
    }

    async fn show_conn(self, _ctx: Context, id: u64) -> Result<ConnDetail, ApiError> {
        self.controller.show_conn(id)
    }

    async fn stop_conn(self, _ctx: Context, id: u64) -> Result<ConnStopResult, ApiError> {
        self.controller.stop_conn(id)
    }

    async fn stop_all_conn(self, _ctx: Context) -> ConnStopResult {
        self.controller.stop_all_conn()
    }

    async fn get_conn_history_limit(self, _ctx: Context) -> u32 {
        self.controller.get_conn_history_limit()
    }

    async fn set_conn_history_limit(self, _ctx: Context, limit: u32) -> u32 {
        self.controller.set_conn_history_limit(limit).await
    }

    async fn list_link(self, _ctx: Context) -> Snapshot<LinkSummary> {
        self.controller.list_link().await
    }

    async fn show_link(self, _ctx: Context, name: String) -> Result<LinkDetail, ApiError> {
        self.controller.show_link(name).await
    }

    async fn stop_link(self, _ctx: Context, name: String) -> Result<(), ApiError> {
        self.controller.stop_link(name).await
    }

    async fn list_dns(self, _ctx: Context) -> Snapshot<DnsResolverSummary> {
        self.controller.list_dns()
    }

    async fn show_dns(self, _ctx: Context, id: String) -> Result<DnsResolverDetail, ApiError> {
        self.controller.show_dns(id)
    }

    async fn lookup_dns(
        self,
        _ctx: Context,
        request: DnsLookupRequest,
    ) -> Result<DnsLookupResponse, ApiError> {
        self.controller.lookup_dns(request).await
    }

    async fn get_dns_mapping(
        self,
        _ctx: Context,
        fake_ip: IpAddr,
    ) -> Result<FakeIpMapping, ApiError> {
        self.controller.get_dns_mapping(fake_ip)
    }

    async fn add_temporary_rule(self, _ctx: Context, rule_literal: String) -> bool {
        self.controller.add_temporary_rule(rule_literal).await
    }

    async fn delete_temporary_rule(self, _ctx: Context, rule_literal_prefix: String) -> bool {
        self.controller
            .delete_temporary_rule(rule_literal_prefix)
            .await
    }

    async fn list_temporary_rule(self, _ctx: Context) -> Vec<String> {
        self.controller.list_temporary_rule().await
    }

    async fn clear_temporary_rule(self, _ctx: Context) {
        self.controller.clear_temporary_rule().await
    }

    async fn get_tun(self, _ctx: Context) -> TunStatusSchema {
        self.controller.get_tun()
    }

    async fn set_tun(self, _ctx: Context, enabled: TunStatusSchema) -> bool {
        self.controller.set_tun(&enabled)
    }

    async fn get_traffic(self, _ctx: Context) -> TrafficResp {
        self.controller.get_traffic()
    }

    async fn reload(self, _ctx: Context) -> bool {
        self.controller.reload().await
    }

    async fn request_traffic_stream(self, _ctx: Context, ctx_id: u64) {
        let _ = self.sender.send(ClientRequests::Traffic(ctx_id));
    }

    async fn request_connection_stream(self, _ctx: Context, ctx_id: u64) {
        let _ = self.sender.send(ClientRequests::ConnectionStream(ctx_id));
    }

    async fn request_log_stream(self, _ctx: Context, ctx_id: u64) {
        let _ = self.sender.send(ClientRequests::Logs(ctx_id));
    }
}
