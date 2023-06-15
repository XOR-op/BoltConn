use anyhow::Result;
use boltapi::multiplex::rpc_multiplex_twoway;
use boltapi::rpc::ControlServiceClient;
use boltapi::{
    ConnectionSchema, GetGroupRespSchema, GetInterceptDataResp, HttpInterceptSchema,
    TunStatusSchema,
};
use std::path::PathBuf;
use tarpc::context::Context;
use tarpc::tokio_serde::formats::Bincode;
use tarpc::tokio_util::codec::LengthDelimitedCodec;
use tarpc::transport::channel::UnboundedChannel;
use tokio::net::UnixStream;

pub struct UdsConnector {
    client: ControlServiceClient,
}

impl UdsConnector {
    pub async fn new(bind_addr: PathBuf) -> Result<Self> {
        let conn = UnixStream::connect(bind_addr).await?;
        let transport = tarpc::serde_transport::new(
            LengthDelimitedCodec::builder().new_framed(conn),
            Bincode::default(),
        );
        let (placeholder, client_t, in_task, out_task) = rpc_multiplex_twoway(transport);
        // dirty hack to make rustc infer correct type
        fn infer_generic_type(_: UnboundedChannel<tarpc::ClientMessage<()>, tarpc::Response<()>>) {}
        infer_generic_type(placeholder);

        tokio::spawn(in_task);
        tokio::spawn(out_task);
        let client = ControlServiceClient::new(Default::default(), client_t).spawn();

        Ok(Self { client })
    }

    pub async fn get_group_list(&self) -> Result<Vec<GetGroupRespSchema>> {
        let resp = self.client.get_all_proxies(Context::current()).await?;
        Ok(resp)
    }

    pub async fn set_proxy_for(&self, group: String, proxy: String) -> Result<bool> {
        Ok(self
            .client
            .set_proxy_for(Context::current(), group, proxy)
            .await?)
    }

    pub async fn get_connections(&self) -> Result<Vec<ConnectionSchema>> {
        Ok(self.client.get_all_conns(Context::current()).await?)
    }
    pub async fn stop_connections(&self, nth: Option<usize>) -> Result<bool> {
        Ok(match nth {
            None => {
                self.client.stop_all_conns(Context::current()).await?;
                true
            }
            Some(id) => self.client.stop_conn(Context::current(), id as u32).await?,
        })
    }

    pub async fn get_tun(&self) -> Result<TunStatusSchema> {
        Ok(self.client.get_tun(Context::current()).await?)
    }

    pub async fn set_tun(&self, enabled: TunStatusSchema) -> Result<()> {
        self.client.set_tun(Context::current(), enabled).await?;
        Ok(())
    }

    pub async fn intercept(
        &self,
        range: Option<(u32, Option<u32>)>,
    ) -> Result<Vec<HttpInterceptSchema>> {
        Ok(match range {
            None => {
                self.client
                    .get_all_interceptions(Context::current())
                    .await?
            }
            Some((start, end)) => {
                self.client
                    .get_range_interceptions(Context::current(), start, end)
                    .await?
            }
        })
    }

    pub async fn get_intercept_payload(&self, id: u32) -> Result<GetInterceptDataResp> {
        self.client
            .get_intercepted_payload(Context::current(), id)
            .await?
            .ok_or(anyhow::anyhow!("No response"))
    }

    pub async fn reload_config(&self) -> Result<()> {
        Ok(self.client.reload(Context::current()).await?)
    }
}
