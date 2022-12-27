use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{PathBuf};
use std::str::FromStr;
use tokio::task::JoinHandle;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
// not deny_unknown_fields, in order to achieve compatibility
pub enum RuleProvider {
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
#[serde(deny_unknown_fields)]
pub struct RuleSchema {
    pub payload: Vec<String>,
}

pub async fn read_schema(
    config_path: &str,
    providers: &HashMap<String, RuleProvider>,
    force_update: bool,
) -> anyhow::Result<HashMap<String, RuleSchema>> {
    let mut table = HashMap::new();
    // concurrently download rules
    let config_path = PathBuf::from_str(config_path).unwrap();
    // println!("{:?}", fs::canonicalize(config_path.as_path()));
    let tasks: Vec<JoinHandle<anyhow::Result<(String, RuleSchema)>>> = providers
        .clone()
        .into_iter()
        .map(|(name, item)| {
            let relative_path = config_path.clone();
            tokio::spawn(async move {
                match item {
                    RuleProvider::File { path } => {
                        let content: RuleSchema = serde_yaml::from_str(
                            fs::read_to_string(relative_path.join(path))?.as_str(),
                        )?;
                        Ok((name.clone(), content))
                    }
                    RuleProvider::Http { url, path, .. } => {
                        let full_path = relative_path.join(path);
                        let content: RuleSchema = if !force_update && full_path.as_path().exists() {
                            serde_yaml::from_str(fs::read_to_string(full_path.as_path())?.as_str())?
                        } else {
                            let resp = reqwest::get(url).await?;
                            let text = resp.text().await?;
                            let content: RuleSchema = serde_yaml::from_str(text.as_str())?;
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
