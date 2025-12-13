use crate::config;
use crate::config::{ConfigError, FileError, load_remote_config};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::task::JoinHandle;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
// not deny_unknown_fields, in order to achieve compatibility
pub enum RuleLocation {
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
#[serde(tag = "type")]
pub struct RuleProvider {
    #[serde(default = "default_classical")]
    pub behavior: ProviderBehavior,
    #[serde(flatten)]
    pub location: RuleLocation,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProviderBehavior {
    #[serde(alias = "domain")]
    Domain,
    #[serde(alias = "ipcidr")]
    IpCidr,
    #[serde(alias = "classical")]
    Classical,
}

fn default_classical() -> ProviderBehavior {
    ProviderBehavior::Classical
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawRuleSchema {
    pub payload: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuleSchema {
    pub behavior: ProviderBehavior,
    pub payload: Vec<String>,
}

pub async fn read_rule_schema(
    config_path: &Path,
    providers: &HashMap<String, RuleProvider>,
    force_update: bool,
) -> Result<HashMap<String, RuleSchema>, ConfigError> {
    let mut table = HashMap::new();
    // concurrently download rules
    let tasks: HashMap<String, JoinHandle<Result<RuleSchema, ConfigError>>> = providers
        .clone()
        .into_iter()
        .map(|(name, item)| {
            let root_path = config_path.to_path_buf();
            (
                name,
                tokio::spawn(async move {
                    let io_error = |e| FileError::Io(root_path.to_string_lossy().to_string(), e);
                    let serde_error =
                        |e| FileError::Serde(root_path.to_string_lossy().to_string(), e);

                    match item.location {
                        RuleLocation::File { path } => {
                            let content: RawRuleSchema = serde_yaml::from_str(
                                fs::read_to_string(
                                    config::safe_join_path(&root_path, &path).map_err(io_error)?,
                                )
                                .map_err(io_error)?
                                .as_str(),
                            )
                            .map_err(serde_error)?;
                            Ok(RuleSchema {
                                behavior: item.behavior,
                                payload: content.payload,
                            })
                        }
                        RuleLocation::Http { url, path, .. } => {
                            let content: RawRuleSchema =
                                load_remote_config(&url, &path, &root_path, force_update).await?;
                            Ok(RuleSchema {
                                behavior: item.behavior,
                                payload: content.payload,
                            })
                        }
                    }
                }),
            )
        })
        .collect();
    for (name, task) in tasks {
        let content = match task.await? {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        table.insert(name, content);
    }
    Ok(table)
}
