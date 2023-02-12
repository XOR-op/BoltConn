use crate::config::{safe_join_path, RawProxyLocalCfg};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::task::JoinHandle;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
// not deny_unknown_fields, in order to achieve compatibility
pub enum ProxyProvider {
    #[serde(alias = "file")]
    File { path: String },
    #[serde(alias = "http")]
    Http {
        url: String,
        path: String,
        interval: u32,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawProxyProviderCfg {
    pub name: String,
    #[serde(flatten)]
    pub cfg: RawProxyLocalCfg,
}

impl RawProxyProviderCfg {
    pub fn get_name(&self) -> &String {
        &self.name
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProxySchema {
    pub proxies: Vec<RawProxyProviderCfg>,
}

pub async fn read_proxy_schema(
    config_path: &Path,
    providers: &HashMap<String, ProxyProvider>,
    force_update: bool,
) -> anyhow::Result<HashMap<String, ProxySchema>> {
    let mut table = HashMap::new();
    // concurrently download rules
    let tasks: Vec<JoinHandle<anyhow::Result<(String, ProxySchema)>>> = providers
        .clone()
        .into_iter()
        .map(|(name, item)| {
            let root_path = config_path.to_path_buf();
            tokio::spawn(async move {
                match item {
                    ProxyProvider::File { path } => {
                        let content: ProxySchema = serde_yaml::from_str(
                            fs::read_to_string(safe_join_path(&root_path, &path)?)?.as_str(),
                        )?;
                        Ok((name.clone(), content))
                    }
                    ProxyProvider::Http { url, path, .. } => {
                        let full_path = safe_join_path(&root_path, &path)?;
                        let content: ProxySchema = if !force_update && full_path.as_path().exists()
                        {
                            serde_yaml::from_str(fs::read_to_string(full_path.as_path())?.as_str())?
                        } else {
                            let resp = reqwest::get(url).await?;
                            let text = resp.text().await?;
                            let content: ProxySchema = serde_yaml::from_str(text.as_str())?;
                            // security: `full_path` should be (layers of) subdir of `root_path`,
                            //           so arbitrary write should not happen
                            fs::write(full_path.as_path(), text)?;
                            content
                        };
                        Ok((name.clone(), content))
                    }
                }
            })
        })
        .collect();
    for task in tasks {
        let (name, content) = task.await??;
        table.insert(name, content);
    }
    Ok(table)
}
