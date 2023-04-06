use crate::config::{
    config::{default_rule_provider, default_str_vec},
    safe_join_path, RuleProvider,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::task::JoinHandle;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ModuleSchema {
    #[serde(alias = "rule-local")]
    pub rule_local: Vec<String>,
    #[serde(alias = "rule-provider", default = "default_rule_provider")]
    pub rule_provider: HashMap<String, RuleProvider>,
    #[serde(alias = "intercept-rule", default = "default_str_vec")]
    pub intercept_rule: Vec<String>,
    #[serde(alias = "rewrite-rule", default = "default_str_vec")]
    pub rewrite: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ModuleLocation {
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
pub struct ModuleConfig {
    pub name: String,
    #[serde(flatten)]
    pub content: ModuleLocation,
}

pub async fn read_module_schema(
    config_path: &Path,
    modules: &[ModuleConfig],
    force_update: bool,
) -> anyhow::Result<Vec<ModuleSchema>> {
    let mut list = Vec::new();
    // concurrently download rules
    let tasks: Vec<JoinHandle<anyhow::Result<ModuleSchema>>> = modules
        .iter()
        .cloned()
        .map(|cfg| {
            let root_path = config_path.to_path_buf();
            tokio::spawn(async move {
                match &cfg.content {
                    ModuleLocation::File { path } => {
                        let content: ModuleSchema = serde_yaml::from_str(
                            fs::read_to_string(safe_join_path(&root_path, path)?)?.as_str(),
                        )?;
                        Ok(content)
                    }
                    ModuleLocation::Http { url, path, .. } => {
                        let full_path = safe_join_path(&root_path, path)?;
                        let content: ModuleSchema = if !force_update && full_path.as_path().exists()
                        {
                            serde_yaml::from_str(fs::read_to_string(full_path.as_path())?.as_str())?
                        } else {
                            let resp = reqwest::get(url).await?;
                            let text = resp.text().await?;
                            let content: ModuleSchema = serde_yaml::from_str(text.as_str())?;
                            fs::write(full_path.as_path(), text)?;
                            content
                        };
                        Ok(content)
                    }
                }
            })
        })
        .collect();
    for (idx, task) in tasks.into_iter().enumerate() {
        let content = match task.await? {
            Ok(c) => c,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "In file {}: {}",
                    modules.get(idx).unwrap().name,
                    e
                ))
            }
        };
        list.push(content);
    }
    Ok(list)
}
