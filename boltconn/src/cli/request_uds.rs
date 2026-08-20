use crate::cli::request::api_error;
use anyhow::Result;
use boltapi::multiplex::rpc_multiplex_twoway;
use boltapi::rpc::{ClientStreamServiceRequest, ClientStreamServiceResponse, ControlServiceClient};
use boltapi::{
    ApiError, ConnDetail, ConnListRequest, ConnStopResult, ConnSummary, DnsLookupRequest,
    DnsLookupResponse, DnsResolverDetail, DnsResolverSummary, FakeIpMapping, GetGroupRespSchema,
    GetInterceptDataResp, HttpInterceptSchema, LinkDetail, LinkSummary, Snapshot, TunStatusSchema,
};
use std::net::IpAddr;
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

    pub async fn list_conn(&self, request: ConnListRequest) -> Result<Snapshot<ConnSummary>> {
        Ok(self.client.list_conn(Context::current(), request).await?)
    }

    pub async fn show_conn(&self, id: u64) -> Result<ConnDetail> {
        map_api_result(self.client.show_conn(Context::current(), id).await?)
    }

    pub async fn stop_conn(&self, id: u64) -> Result<ConnStopResult> {
        map_api_result(self.client.stop_conn(Context::current(), id).await?)
    }

    pub async fn stop_all_conn(&self) -> Result<ConnStopResult> {
        Ok(self.client.stop_all_conn(Context::current()).await?)
    }

    pub async fn get_conn_history_limit(&self) -> Result<u32> {
        Ok(self
            .client
            .get_conn_history_limit(Context::current())
            .await?)
    }

    pub async fn set_conn_history_limit(&self, limit: u32) -> Result<u32> {
        Ok(self
            .client
            .set_conn_history_limit(Context::current(), limit)
            .await?)
    }

    pub async fn list_link(&self) -> Result<Snapshot<LinkSummary>> {
        Ok(self.client.list_link(Context::current()).await?)
    }

    pub async fn show_link(&self, name: String) -> Result<LinkDetail> {
        map_api_result(self.client.show_link(Context::current(), name).await?)
    }

    pub async fn stop_link(&self, name: String) -> Result<()> {
        map_api_result(self.client.stop_link(Context::current(), name).await?)
    }

    pub async fn list_dns(&self) -> Result<Snapshot<DnsResolverSummary>> {
        Ok(self.client.list_dns(Context::current()).await?)
    }

    pub async fn show_dns(&self, id: String) -> Result<DnsResolverDetail> {
        map_api_result(self.client.show_dns(Context::current(), id).await?)
    }

    pub async fn lookup_dns(&self, request: DnsLookupRequest) -> Result<DnsLookupResponse> {
        map_api_result(self.client.lookup_dns(Context::current(), request).await?)
    }

    pub async fn get_dns_mapping(&self, fake_ip: IpAddr) -> Result<FakeIpMapping> {
        map_api_result(
            self.client
                .get_dns_mapping(Context::current(), fake_ip)
                .await?,
        )
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
            .ok_or_else(|| anyhow::anyhow!("No response"))
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

    pub async fn get_log_stream(&self, ctx_id: u64) -> Result<()> {
        Ok(self
            .client
            .request_log_stream(Context::current(), ctx_id)
            .await?)
    }

    pub async fn reload_config(&self) -> Result<bool> {
        Ok(self.client.reload(Context::current()).await?)
    }
}

fn map_api_result<T>(result: std::result::Result<T, ApiError>) -> Result<T> {
    result.map_err(api_error)
}

#[cfg(test)]
mod observability_tests {
    use super::*;
    use crate::cli::request::ControlApiError;
    use boltapi::ApiErrorCode;

    #[test]
    fn uds_result_preserves_stable_api_error() {
        let error = map_api_result::<()>(Err(ApiError {
            code: ApiErrorCode::LinkNotActive,
            message: "link is already stopped".to_string(),
        }))
        .unwrap_err();
        let api_error = error.downcast_ref::<ControlApiError>().unwrap();
        assert_eq!(api_error.code, ApiErrorCode::LinkNotActive);
        assert_eq!(
            error.to_string(),
            "link_not_active: link is already stopped"
        );
    }
}
