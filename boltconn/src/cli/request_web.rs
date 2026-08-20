use anyhow::{Result, anyhow};
use boltapi::{
    ConnStopResult, ConnSummary, DnsLookupResponse, FakeIpMapping, GetGroupRespSchema,
    GetInterceptDataResp, HttpInterceptSchema, LinkSummary, Snapshot, TunStatusSchema,
};

pub struct WebConnector {
    pub url: String,
}

impl WebConnector {
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

    pub async fn get_connections(&self) -> Result<Snapshot<ConnSummary>> {
        let data = reqwest::get(self.route("/conn"))
            .await?
            .error_for_status()?
            .text()
            .await?;
        let result: Snapshot<ConnSummary> = serde_json::from_str(data.as_str())?;
        Ok(result)
    }

    pub async fn stop_connections(&self, nth: Option<usize>) -> Result<ConnStopResult> {
        let path = nth.map_or_else(|| "/conn/all".to_string(), |id| format!("/conn/{id}"));
        let response = reqwest::Client::new()
            .delete(self.route(&path))
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json().await?)
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

    pub async fn get_master_conn_stat(&self) -> Result<Vec<LinkSummary>> {
        let data = reqwest::get(self.route("/link"))
            .await?
            .error_for_status()?
            .text()
            .await?;
        let result: Snapshot<LinkSummary> = serde_json::from_str(data.as_str())?;
        Ok(result.items)
    }

    pub async fn stop_master_conn(&self, id: String) -> Result<()> {
        reqwest::Client::new()
            .delete(self.route_segment("/link", &id)?)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn real_lookup(&self, domain: String) -> Result<String> {
        let mut url = reqwest::Url::parse(&self.route("/dns/lookup"))?;
        url.query_pairs_mut().append_pair("domain", &domain);
        let response: DnsLookupResponse =
            reqwest::get(url).await?.error_for_status()?.json().await?;
        response
            .lookup
            .answers
            .iter()
            .find(|answer| answer.selected)
            .or_else(|| response.lookup.answers.first())
            .map(|answer| answer.address.to_string())
            .ok_or_else(|| anyhow!("DNS lookup returned no address"))
    }

    pub async fn fake_ip_to_real(&self, fake_ip: String) -> Result<String> {
        let mut url = reqwest::Url::parse(&self.route("/dns/mapping"))?;
        url.query_pairs_mut().append_pair("fake-ip", &fake_ip);
        let mapping: FakeIpMapping = reqwest::get(url).await?.error_for_status()?.json().await?;
        Ok(mapping.domain)
    }

    pub async fn set_conn_log_limit(&self, limit: u32) -> Result<()> {
        reqwest::Client::new()
            .put(self.route("/conn/history-limit"))
            .json(&limit)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn get_conn_log_limit(&self) -> Result<u32> {
        let data = reqwest::get(self.route("/conn/history-limit"))
            .await?
            .error_for_status()?
            .text()
            .await?;
        let result: u32 = serde_json::from_str(data.as_str())?;
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

    fn route_segment(&self, base: &str, segment: &str) -> Result<reqwest::Url> {
        let mut url = reqwest::Url::parse(&self.route(base))?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("controller URL cannot contain path segments"))?
            .push(segment);
        Ok(url)
    }
}
