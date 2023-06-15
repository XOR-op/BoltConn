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
use tokio::sync::Mutex;

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
                    traffic_id: Arc::new(Default::default()),
                    log_id: Arc::new(Default::default()),
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
    Traffic(bool),
    Logs(bool),
}

struct UdsRpcBackClient {
    client: ClientStreamServiceClient,
    controller: Arc<Controller>,
    // avoid ABA problem
    traffic_id: Arc<Mutex<Option<u32>>>,
    log_id: Arc<Mutex<Option<u32>>>,
}

impl UdsRpcBackClient {
    pub async fn run(self, mut receiver: tokio::sync::mpsc::UnboundedReceiver<ClientRequests>) {
        let me = Arc::new(self);
        let mut last_traffic_id = 0;
        let mut last_log_id = 0;
        let mut will_continue = true;
        while will_continue {
            will_continue = match receiver.recv().await {
                Some(req) => {
                    me.clone()
                        .process_request(req, &mut last_traffic_id, &mut last_log_id)
                        .await;
                    true
                }
                _ => false,
            };
        }
    }

    async fn process_request(
        self: Arc<Self>,
        req: ClientRequests,
        last_traffic_id: &mut u32,
        last_log_id: &mut u32,
    ) {
        match req {
            ClientRequests::Traffic(enable) => {
                let mut last_traffic = self.traffic_id.lock().await;
                if last_traffic.is_none() && enable {
                    let saved_id = *last_traffic_id;
                    *last_traffic = Some(saved_id);
                    *last_traffic_id += 1;
                    drop(last_traffic);
                    // spawn traffic processing coroutine
                    tokio::spawn(async move {
                        let tra = self.controller.get_traffic();
                        let mut last_upload = tra.upload;
                        let mut last_download = tra.download;

                        loop {
                            let last_traffic_guard = self.traffic_id.lock().await;
                            match *last_traffic_guard {
                                Some(id) if id == saved_id => {
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
                                    let _ =
                                        self.client.post_traffic(Context::current(), data).await;
                                    drop(last_traffic_guard);
                                    tokio::time::sleep(Duration::from_secs(1)).await;
                                }
                                _ => break,
                            }
                        }
                    });
                } else if !enable {
                    *last_traffic = None;
                }
            }
            ClientRequests::Logs(enable) => {
                let mut guard = self.log_id.lock().await;
                if guard.is_none() && enable {
                    let saved_id = *last_log_id;
                    *guard = Some(saved_id);
                    *last_log_id += 1;
                    let mut log_receiver = self.controller.get_log_subscriber();
                    drop(guard);
                    tokio::spawn(async move {
                        while let Ok(log) = log_receiver.recv().await {
                            let log_guard = self.log_id.lock().await;
                            match *log_guard {
                                Some(id) if id == saved_id => {
                                    let _ = self.client.post_log(Context::current(), log).await;
                                }
                                _ => break,
                            }
                        }
                    });
                } else if !enable {
                    *guard = None
                }
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

    async fn request_traffic_stream(self, _ctx: Context, enable: bool) {
        let _ = self.sender.send(ClientRequests::Traffic(enable));
    }

    async fn request_log_stream(self, _ctx: Context, enable: bool) {
        let _ = self.sender.send(ClientRequests::Logs(enable));
    }
}
