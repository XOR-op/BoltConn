use crate::cli::request::api_error;
use anyhow::{Result, anyhow};
use boltapi::{
    ApiError, ConnDetail, ConnListRequest, ConnStopResult, ConnSummary, DnsLookupRequest,
    DnsLookupResponse, DnsResolverDetail, DnsResolverSummary, FakeIpMapping, GetGroupRespSchema,
    GetInterceptDataResp, HttpInterceptSchema, LinkDetail, LinkSummary, Snapshot, TunStatusSchema,
};
use serde::de::DeserializeOwned;
use std::net::IpAddr;

pub struct WebConnector {
    url: String,
    client: reqwest::Client,
}

impl WebConnector {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_group_list(&self) -> Result<Vec<GetGroupRespSchema>> {
        let data = reqwest::get(self.route("/proxies")).await?.text().await?;
        let result: Vec<GetGroupRespSchema> = serde_json::from_str(data.as_str())?;
        Ok(result)
    }

    pub async fn get_proxy_for(&self, group: &str) -> Result<Option<GetGroupRespSchema>> {
        let data = reqwest::get(self.route(format!("/proxies/{}", group).as_str()))
            .await?
            .text()
            .await?;
        let result: Vec<GetGroupRespSchema> = serde_json::from_str(data.as_str())?;
        Ok(result.first().cloned())
    }

    pub async fn set_proxy_for(&self, group: String, proxy: String) -> Result<bool> {
        let req = boltapi::SetGroupReqSchema { selected: proxy };
        let result = reqwest::Client::new()
            .put(self.route(format!("/proxies/{}", group).as_str()))
            .json(&req)
            .send()
            .await?
            .text()
            .await?;
        Ok(result.as_str() == "true")
    }

    pub async fn list_conn(&self, request: ConnListRequest) -> Result<Snapshot<ConnSummary>> {
        let mut url = self.resource_url(&["conn"])?;
        if let Some(link) = request.link {
            url.query_pairs_mut().append_pair("link", &link);
        }
        Self::decode_json(self.client().get(url).send().await?).await
    }

    pub async fn show_conn(&self, id: u64) -> Result<ConnDetail> {
        Self::decode_json(
            self.client()
                .get(self.resource_url(&["conn", &id.to_string()])?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn stop_conn(&self, id: u64) -> Result<ConnStopResult> {
        Self::decode_json(
            self.client()
                .delete(self.resource_url(&["conn", &id.to_string()])?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn stop_all_conn(&self) -> Result<ConnStopResult> {
        Self::decode_json(
            self.client()
                .delete(self.resource_url(&["conn", "all"])?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn get_conn_history_limit(&self) -> Result<u32> {
        Self::decode_json(
            self.client()
                .get(self.resource_url(&["conn", "history-limit"])?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn set_conn_history_limit(&self, limit: u32) -> Result<u32> {
        Self::decode_json(
            self.client()
                .put(self.resource_url(&["conn", "history-limit"])?)
                .json(&limit)
                .send()
                .await?,
        )
        .await
    }

    pub async fn list_link(&self) -> Result<Snapshot<LinkSummary>> {
        Self::decode_json(
            self.client()
                .get(self.resource_url(&["link"])?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn show_link(&self, name: &str) -> Result<LinkDetail> {
        Self::decode_json(
            self.client()
                .get(self.resource_url(&["link", name])?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn stop_link(&self, name: &str) -> Result<()> {
        Self::decode_empty(
            self.client()
                .delete(self.resource_url(&["link", name])?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn list_dns(&self) -> Result<Snapshot<DnsResolverSummary>> {
        Self::decode_json(
            self.client()
                .get(self.resource_url(&["dns"])?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn show_dns(&self, id: &str) -> Result<DnsResolverDetail> {
        Self::decode_json(
            self.client()
                .get(self.resource_url(&["dns", id])?)
                .send()
                .await?,
        )
        .await
    }

    pub async fn lookup_dns(&self, request: DnsLookupRequest) -> Result<DnsLookupResponse> {
        let mut url = self.resource_url(&["dns", "lookup"])?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("domain", &request.domain);
            if let Some(resolver_id) = request.resolver_id {
                query.append_pair("resolver", &resolver_id);
            }
        }
        Self::decode_json(self.client().get(url).send().await?).await
    }

    pub async fn get_dns_mapping(&self, fake_ip: IpAddr) -> Result<FakeIpMapping> {
        let mut url = self.resource_url(&["dns", "mapping"])?;
        url.query_pairs_mut()
            .append_pair("fake-ip", &fake_ip.to_string());
        Self::decode_json(self.client().get(url).send().await?).await
    }

    pub async fn get_tun(&self) -> Result<TunStatusSchema> {
        let data = reqwest::get(self.route("/tun")).await?.text().await?;
        let result: TunStatusSchema = serde_json::from_str(data.as_str())?;
        Ok(result)
    }

    pub async fn set_tun(&self, enabled: TunStatusSchema) -> Result<()> {
        reqwest::Client::new()
            .put(self.route("/tun"))
            .json(&enabled)
            .send()
            .await?;
        Ok(())
    }

    pub async fn intercept(
        &self,
        range: Option<(u32, Option<u32>)>,
    ) -> Result<Vec<HttpInterceptSchema>> {
        let uri = match range {
            None => self.route("/intercept/all"),
            Some((s, Some(e))) => {
                self.route(format!("/intercept/range?start={}&end={}", s, e).as_str())
            }
            Some((s, None)) => self.route(format!("/intercept/range?start={}", s).as_str()),
        };
        let data = reqwest::get(uri).await?.text().await?;
        let result: Vec<HttpInterceptSchema> = serde_json::from_str(data.as_str())?;
        Ok(result)
    }

    pub async fn get_intercept_payload(&self, id: u32) -> Result<GetInterceptDataResp> {
        let data = reqwest::get(self.route(format!("/intercept/payload/{}", id).as_str()))
            .await?
            .text()
            .await?;
        let result: GetInterceptDataResp = serde_json::from_str(data.as_str())?;
        Ok(result)
    }

    pub async fn reload_config(&self) -> Result<bool> {
        let res = reqwest::Client::new()
            .post(self.route("/reload"))
            .send()
            .await?;
        let result: bool = serde_json::from_str(res.text().await?.as_str())?;
        Ok(result)
    }

    fn route(&self, s: &str) -> String {
        format!("{}{}", self.url, s)
    }

    fn client(&self) -> &reqwest::Client {
        &self.client
    }

    fn resource_url(&self, segments: &[&str]) -> Result<reqwest::Url> {
        let mut url = reqwest::Url::parse(&self.url)?;
        url.set_query(None);
        url.set_fragment(None);
        url.path_segments_mut()
            .map_err(|_| anyhow!("controller URL cannot contain path segments"))?
            .pop_if_empty()
            .extend(segments.iter().copied());
        Ok(url)
    }

    async fn decode_json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
        let status = response.status();
        let body = response.bytes().await?;
        if status.is_success() {
            return Ok(serde_json::from_slice(&body)?);
        }
        Err(Self::response_error(status, &body))
    }

    async fn decode_empty(response: reqwest::Response) -> Result<()> {
        let status = response.status();
        let body = response.bytes().await?;
        if status.is_success() {
            if body.is_empty() {
                return Ok(());
            }
            return Err(anyhow!("controller returned a non-empty unit response"));
        }
        Err(Self::response_error(status, &body))
    }

    fn response_error(status: reqwest::StatusCode, body: &[u8]) -> anyhow::Error {
        serde_json::from_slice::<ApiError>(body)
            .map_or_else(|_| anyhow!("controller returned HTTP {status}"), api_error)
    }
}

#[cfg(test)]
mod observability_tests {
    use super::*;
    use crate::cli::request::ControlApiError;
    use boltapi::ApiErrorCode;

    fn connector() -> WebConnector {
        WebConnector::new("http://127.0.0.1:8080/api/".to_string())
    }

    #[test]
    fn resource_paths_and_queries_encode_user_values() {
        let connector = connector();
        let url = connector
            .resource_url(&["link", "wg us/primary?#"])
            .unwrap();
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:8080/api/link/wg%20us%2Fprimary%3F%23"
        );

        let mut lookup = connector.resource_url(&["dns", "lookup"]).unwrap();
        lookup
            .query_pairs_mut()
            .append_pair("domain", "a+b.example")
            .append_pair("resolver", "abc/123");
        assert_eq!(lookup.path(), "/api/dns/lookup");
        assert_eq!(
            lookup.query().unwrap(),
            "domain=a%2Bb.example&resolver=abc%2F123"
        );
    }

    #[tokio::test]
    async fn non_success_response_preserves_stable_api_error() {
        let response: reqwest::Response = http::Response::builder()
            .status(http::StatusCode::CONFLICT)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(reqwest::Body::from(
                serde_json::to_vec(&ApiError {
                    code: ApiErrorCode::ResolverIdAmbiguous,
                    message: "resolver prefix is ambiguous".to_string(),
                })
                .unwrap(),
            ))
            .unwrap()
            .into();
        let error = WebConnector::decode_json::<serde_json::Value>(response)
            .await
            .unwrap_err();
        let api_error = error.downcast_ref::<ControlApiError>().unwrap();
        assert_eq!(api_error.code, ApiErrorCode::ResolverIdAmbiguous);
        assert_eq!(
            error.to_string(),
            "resolver_id_ambiguous: resolver prefix is ambiguous"
        );
    }

    #[tokio::test]
    async fn unit_response_requires_the_contractual_empty_body() {
        let empty: reqwest::Response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(reqwest::Body::default())
            .unwrap()
            .into();
        WebConnector::decode_empty(empty).await.unwrap();

        let nonempty: reqwest::Response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(reqwest::Body::from("null"))
            .unwrap()
            .into();
        assert!(WebConnector::decode_empty(nonempty).await.is_err());
    }
}
