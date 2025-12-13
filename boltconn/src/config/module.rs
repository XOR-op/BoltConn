use crate::config::interception::InterceptionConfig;
use crate::config::{
    ConfigError, FileError, RuleConfigLine, RuleProvider, config::default_interception_vec,
    config::default_rule_provider, safe_join_path,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::task::JoinHandle;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ModuleSchema {
    #[serde(alias = "rule-local", default = "default_rule_local")]
    pub rule_local: Vec<RuleConfigLine>,
    #[serde(alias = "rule-provider", default = "default_rule_provider")]
    pub rule_provider: HashMap<String, RuleProvider>,
    #[serde(default = "default_interception_vec")]
    pub interception: Vec<InterceptionConfig>,
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
) -> Result<Vec<ModuleSchema>, ConfigError> {
    let mut list = Vec::new();
    // concurrently download rules
    #[allow(clippy::redundant_iter_cloned)]
    // false positive in https://github.com/rust-lang/rust-clippy/issues/16012
    let tasks: Vec<JoinHandle<Result<ModuleSchema, ConfigError>>> = modules
        .iter()
        .cloned()
        .map(|cfg| {
            let root_path = config_path.to_path_buf();
            tokio::spawn(async move {
                match &cfg.content {
                    ModuleLocation::File { path } => {
                        let io_error = |e| FileError::Io(path.clone(), e);
                        let content: ModuleSchema = serde_yaml::from_str(
                            fs::read_to_string(safe_join_path(&root_path, path).map_err(io_error)?)
                                .map_err(io_error)?
                                .as_str(),
                        )
                        .map_err(|e| FileError::Serde(path.clone(), e))?;
                        Ok(content)
                    }
                    ModuleLocation::Http { url, path, .. } => {
                        let io_error = |e| FileError::Io(path.clone(), e);
                        let serde_error = |e| FileError::Serde(url.clone(), e);
                        let http_error = |e| FileError::Http(url.clone(), e);

                        let full_path = safe_join_path(&root_path, path).map_err(io_error)?;
                        let content: ModuleSchema = if !force_update && full_path.as_path().exists()
                        {
                            serde_yaml::from_str(
                                fs::read_to_string(full_path.as_path())
                                    .map_err(io_error)?
                                    .as_str(),
                            )
                            .map_err(serde_error)?
                        } else {
                            let resp = reqwest::get(url).await.map_err(http_error)?;
                            let text = resp.text().await.map_err(http_error)?;
                            let content: ModuleSchema =
                                serde_yaml::from_str(text.as_str()).map_err(serde_error)?;
                            fs::write(full_path.as_path(), text).map_err(io_error)?;
                            content
                        };
                        Ok(content)
                    }
                }
            })
        })
        .collect();
    for task in tasks.into_iter() {
        let content = match task.await? {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        list.push(content);
    }
    Ok(list)
}

fn default_rule_local() -> Vec<RuleConfigLine> {
    Default::default()
}
