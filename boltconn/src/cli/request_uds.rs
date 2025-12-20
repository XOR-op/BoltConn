use anyhow::Result;
use boltapi::multiplex::rpc_multiplex_twoway;
use boltapi::rpc::{ClientStreamServiceRequest, ClientStreamServiceResponse, ControlServiceClient};
use boltapi::{
    ConnectionSchema, GetGroupRespSchema, GetInterceptDataResp, HttpInterceptSchema,
    MasterConnectionStatus, TunStatusSchema,
};
use tarpc::context::Context;
use tarpc::tokio_util::codec::LengthDelimitedCodec;
use tarpc::transport::channel::UnboundedChannel;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(windows)]
use tokio::net::windows::named_pipe::ClientOptions;
use tokio_serde::formats::Cbor;

pub struct UdsConnector {
    client: ControlServiceClient,
}

impl UdsConnector {
    pub async fn new(
        bind_addr: &str,
    ) -> Result<(
        Self,
        UnboundedChannel<
            tarpc::ClientMessage<ClientStreamServiceRequest>,
            tarpc::Response<ClientStreamServiceResponse>,
        >,
    )> {
        #[cfg(unix)]
        let conn = UnixStream::connect(bind_addr).await?;
        #[cfg(windows)]
        let conn = ClientOptions::new().open(bind_addr)?;
        let transport = tarpc::serde_transport::new(
            LengthDelimitedCodec::builder()
                .max_frame_length(boltapi::rpc::MAX_CODEC_FRAME_LENGTH)
                .new_framed(conn),
            Cbor::default(),
        );
        let (server_t, client_t, in_task, out_task) = rpc_multiplex_twoway(transport);

        tokio::spawn(in_task);
        tokio::spawn(out_task);
        let client = ControlServiceClient::new(Default::default(), client_t).spawn();

        Ok((Self { client }, server_t))
    }

    pub async fn get_group_list(&self) -> Result<Vec<GetGroupRespSchema>> {
        let resp = self.client.get_all_proxies(Context::current()).await?;
        Ok(resp)
    }

    pub async fn get_proxy_for(&self, group: &str) -> Result<Option<GetGroupRespSchema>> {
        let resp = self
            .client
            .get_proxy_group(Context::current(), group.to_string())
            .await?;
        Ok(resp.first().cloned())
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

    pub async fn real_lookup(&self, domain: String) -> Result<String> {
        self.client
            .real_lookup(Context::current(), domain)
            .await?
            .ok_or(anyhow::anyhow!("No DNS record"))
    }

    pub async fn fake_ip_to_real(&self, fake_ip: String) -> Result<String> {
        self.client
            .fake_ip_to_real(Context::current(), fake_ip)
            .await?
            .ok_or(anyhow::anyhow!("No fake IP mapping"))
    }

    pub async fn add_temporary_rule(&self, rule_literal: String) -> Result<bool> {
        Ok(self
            .client
            .add_temporary_rule(Context::current(), rule_literal)
            .await?)
    }

    pub async fn delete_temporary_rule(&self, rule_literal_prefix: String) -> Result<bool> {
        Ok(self
            .client
            .delete_temporary_rule(Context::current(), rule_literal_prefix)
            .await?)
    }

    pub async fn list_temporary_rule(&self) -> Result<Vec<String>> {
        Ok(self.client.list_temporary_rule(Context::current()).await?)
    }

    pub async fn clear_temporary_rule(&self) -> Result<()> {
        Ok(self.client.clear_temporary_rule(Context::current()).await?)
    }

    pub async fn set_conn_log_limit(&self, limit: u32) -> Result<()> {
        Ok(self
            .client
            .set_conn_log_limit(Context::current(), limit)
            .await?)
    }

    pub async fn get_conn_log_limit(&self) -> Result<u32> {
        Ok(self.client.get_conn_log_limit(Context::current()).await?)
    }

    pub async fn get_log_stream(&self, ctx_id: u64) -> Result<()> {
        Ok(self
            .client
            .request_log_stream(Context::current(), ctx_id)
            .await?)
    }

    pub async fn reload_config(&self) -> Result<bool> {
        Ok(self.client.reload(Context::current()).await?)
    }

    pub async fn get_master_conn_stat(&self) -> Result<Vec<MasterConnectionStatus>> {
        Ok(self.client.get_master_conn_stat(Context::current()).await?)
    }

    pub async fn stop_master_conn(&self, id: String) -> Result<()> {
        Ok(self.client.stop_master_conn(Context::current(), id).await?)
    }
}
