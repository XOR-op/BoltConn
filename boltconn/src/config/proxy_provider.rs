use crate::config::{load_remote_config, safe_join_path, RawProxyLocalCfg};
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
    let tasks: HashMap<String, JoinHandle<anyhow::Result<ProxySchema>>> = providers
        .clone()
        .into_iter()
        .map(|(name, item)| {
            let root_path = config_path.to_path_buf();
            (
                name,
                tokio::spawn(async move {
                    match item {
                        ProxyProvider::File { path } => {
                            let content: ProxySchema = serde_yaml::from_str(
                                fs::read_to_string(safe_join_path(&root_path, &path)?)?.as_str(),
                            )?;
                            Ok(content)
                        }
                        ProxyProvider::Http { url, path, .. } => {
                            load_remote_config(url, path, &root_path, force_update).await
                        }
                    }
                }),
            )
        })
        .collect();
    for (name, task) in tasks {
        let content = match task.await? {
            Ok(c) => c,
            Err(e) => return Err(anyhow::anyhow!("In proxy provider {}: {}", name, e)),
        };
        table.insert(name, content);
    }
    Ok(table)
}
