use anyhow::Result;
use boltapi::{
    ConnectionSchema, GetGroupRespSchema, GetInterceptDataResp, HttpInterceptSchema,
    TunStatusSchema,
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

    pub async fn get_connections(&self) -> Result<Vec<ConnectionSchema>> {
        let data = reqwest::get(self.route("/connections"))
            .await?
            .text()
            .await?;
        let result: Vec<ConnectionSchema> = serde_json::from_str(data.as_str())?;
        Ok(result)
    }

    pub async fn stop_connections(&self, nth: Option<usize>) -> Result<bool> {
        Ok(match nth {
            None => {
                reqwest::Client::new()
                    .delete(self.route("/connections"))
                    .send()
                    .await?;
                true
            }
            Some(id) => {
                let data = reqwest::Client::new()
                    .delete(self.route(format!("/connections/{}", id).as_str()))
                    .send()
                    .await?
                    .text()
                    .await?;
                data.as_str() == "true"
            }
        })
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

    pub async fn real_lookup(&self, domain: String) -> Result<String> {
        let data = reqwest::get(self.route(format!("/dns/lookup/{}", domain).as_str()))
            .await?
            .text()
            .await?;
        Ok(data)
    }

    pub async fn fake_ip_to_real(&self, fake_ip: String) -> Result<String> {
        let data = reqwest::get(self.route(format!("/dns/mapping/{}", fake_ip).as_str()))
            .await?
            .text()
            .await?;
        Ok(data)
    }

    pub async fn set_conn_log_limit(&self, limit: u32) -> Result<()> {
        reqwest::Client::new()
            .put(self.route("/connections/log_limit"))
            .json(&limit)
            .send()
            .await?;
        Ok(())
    }

    pub async fn get_conn_log_limit(&self) -> Result<u32> {
        let data = reqwest::get(self.route("/connections/log_limit"))
            .await?
            .text()
            .await?;
        let result: u32 = serde_json::from_str(data.as_str())?;
        Ok(result)
    }

    pub async fn reload_config(&self) -> Result<()> {
        reqwest::Client::new()
            .post(self.route("/reload"))
            .send()
            .await?;
        Ok(())
    }

    fn route(&self, s: &str) -> String {
        format!("{}{}", self.url, s)
    }
}
