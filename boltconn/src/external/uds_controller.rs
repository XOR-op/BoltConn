use crate::external::Controller;
use boltapi::rpc::ControlService;
use boltapi::{
    ConnectionSchema, GetGroupRespSchema, GetInterceptDataResp, GetInterceptRangeReq,
    HttpInterceptSchema, TrafficResp, TunStatusSchema,
};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            listener: Some(UnixListener::bind(path)?),
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

            let fut = BaseChannel::with_defaults(transport).execute(self.clone().serve());
            tokio::spawn(fut);
        }
    }
}

#[tarpc::server]
impl ControlService for UdsController {
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
}
