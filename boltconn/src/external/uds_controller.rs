use crate::external::Controller;
use crate::platform::get_user_info;
use boltapi::multiplex::rpc_multiplex_twoway;
use boltapi::rpc::{ClientStreamServiceClient, ControlService};
use boltapi::{
    ConnectionSchema, GetGroupRespSchema, GetInterceptDataResp, GetInterceptRangeReq,
    HttpInterceptSchema, TrafficResp, TunStatusSchema,
};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tarpc::context::Context;
use tarpc::server::{BaseChannel, Channel};
use tarpc::tokio_serde::formats::Bincode;
use tarpc::tokio_util::codec::LengthDelimitedCodec;
use tokio::net::UnixListener;

pub struct UnixListenerGuard {
    path: PathBuf,
    listener: Option<UnixListener>,
}

impl UnixListenerGuard {
    pub fn new<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let listener = UnixListener::bind(&path)?;
        let (_, uid, gid) =
            get_user_info().ok_or(anyhow::anyhow!("Cannot get user before sudo"))?;
        nix::unistd::chown(&path, Some(uid.into()), Some(gid.into()))?;
        Ok(Self {
            path,
            listener: Some(listener),
        })
    }
    pub fn get_listener(&self) -> &UnixListener {
        self.listener.as_ref().unwrap()
    }
}

impl Drop for UnixListenerGuard {
    fn drop(&mut self) {
        self.listener = None;
        if let Err(e) = std::fs::remove_file(&self.path) {
            tracing::error!("Error when removing unix domain socket: {}", e)
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
        let codec_builder = LengthDelimitedCodec::builder();
        loop {
            let (conn, _addr) = listener.get_listener().accept().await?;
            let framed = codec_builder.new_framed(conn);
            let transport = tarpc::serde_transport::new(framed, Bincode::default());
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
                BaseChannel::with_defaults(server_t).execute(
                    UdsRpcServer {
                        controller: self.controller.clone(),
                        sender,
                    }
                    .serve(),
                ),
            );
        }
    }
}

#[derive(Clone, Debug)]
enum ClientRequests {
    EnableTraffic(u64),
    EnableLogs(u64),
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
            ClientRequests::EnableTraffic(ctx_id) => {
                // spawn traffic processing coroutine
                tokio::spawn(async move {
                    let tra = self.controller.get_traffic();
                    let mut last_upload = tra.upload;
                    let mut last_download = tra.download;

                    loop {
                        let TrafficResp {
                            upload,
                            download,
                            upload_speed: _,
                            download_speed: _,
                        } = self.controller.get_traffic();
                        let data = TrafficResp {
                            upload,
                            download,
                            upload_speed: Some(upload - last_upload),
                            download_speed: Some(download - last_download),
                        };
                        last_upload = upload;
                        last_download = download;
                        if self
                            .client
                            .post_traffic(Context::current(), data)
                            .await
                            .is_ok_and(|x| x == ctx_id)
                        {
                            break;
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                });
            }
            ClientRequests::EnableLogs(ctx_id) => {
                let mut log_receiver = self.controller.get_log_subscriber();
                tokio::spawn(async move {
                    while let Ok(log) = log_receiver.recv().await {
                        if self
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

#[tarpc::server]
impl ControlService for UdsRpcServer {
    async fn get_all_proxies(self, _ctx: Context) -> Vec<GetGroupRespSchema> {
        self.controller.get_all_proxies().await
    }

    async fn get_proxy_group(self, _ctx: Context, group: String) -> Vec<GetGroupRespSchema> {
        self.controller.get_proxy_group(group).await
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

    async fn get_all_conns(self, _ctx: Context) -> Vec<ConnectionSchema> {
        self.controller.get_all_conns()
    }

    async fn stop_all_conns(self, _ctx: Context) {
        self.controller.stop_all_conn().await
    }

    async fn stop_conn(self, _ctx: Context, id: u32) -> bool {
        self.controller.stop_conn(id as usize).await
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

    async fn reload(self, _ctx: Context) {
        self.controller.reload().await
    }

    async fn request_traffic_stream(self, _ctx: Context, ctx_id: u64) {
        let _ = self.sender.send(ClientRequests::EnableTraffic(ctx_id));
    }

    async fn request_log_stream(self, _ctx: Context, ctx_id: u64) {
        let _ = self.sender.send(ClientRequests::EnableLogs(ctx_id));
    }
}
