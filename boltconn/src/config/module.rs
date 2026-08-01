use crate::config::interception::InterceptionConfig;
use crate::config::{
    ConfigError, FileError, FragmentSequenceEntry, RuleConfigLine, RuleProvider, safe_join_path,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Topic-oriented content exported by a module.
///
/// Ordered exports are inert until referenced by the corresponding root section.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ModuleDocument {
    #[serde(default)]
    pub rules: Vec<FragmentSequenceEntry<RuleConfigLine>>,
    #[serde(default)]
    pub rule_providers: HashMap<String, RuleProvider>,
    #[serde(default)]
    pub interception: Vec<FragmentSequenceEntry<InterceptionConfig>>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ModuleLocation {
    File {
        path: String,
    },
    Http {
        url: String,
        path: String,
        interval: u32,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedModuleDocument {
    pub source_path: PathBuf,
    pub document: ModuleDocument,
}

pub async fn read_module_documents(
    config_path: &Path,
    modules: &HashMap<String, ModuleLocation>,
    force_update: bool,
) -> Result<HashMap<String, LoadedModuleDocument>, ConfigError> {
    // A sorted traversal makes load failures deterministic even though module
    // declaration order has no semantic meaning.
    let mut names: Vec<&String> = modules.keys().collect();
    names.sort();

    let mut loaded = HashMap::with_capacity(modules.len());
    for name in names {
        let location = modules
            .get(name)
            .expect("module key came from the same map");
        let (source_path, document) = match location {
            ModuleLocation::File { path } => {
                let io_error = |error| FileError::Io(path.clone(), error);
                let source_path = safe_join_path(config_path, path).map_err(io_error)?;
                let text = fs::read_to_string(&source_path).map_err(io_error)?;
                let document = serde_yaml::from_str(&text)
                    .map_err(|error| FileError::Serde(path.clone(), error))?;
                (source_path, document)
            }
            ModuleLocation::Http { url, path, .. } => {
                let io_error = |error| FileError::Io(path.clone(), error);
                let serde_error = |error| FileError::Serde(url.clone(), error);
                let http_error = |error| FileError::Http(url.clone(), error);
                let source_path = safe_join_path(config_path, path).map_err(io_error)?;

                let document = if !force_update && source_path.exists() {
                    let text = fs::read_to_string(&source_path).map_err(io_error)?;
                    serde_yaml::from_str(&text).map_err(serde_error)?
                } else {
                    let response = reqwest::get(url).await.map_err(http_error)?;
                    let text = response.text().await.map_err(http_error)?;
                    let document = serde_yaml::from_str(&text).map_err(serde_error)?;
                    fs::write(&source_path, text).map_err(io_error)?;
                    document
                };
                (source_path, document)
            }
        };
        loaded.insert(
            name.clone(),
            LoadedModuleDocument {
                source_path,
                document,
            },
        );
    }
    Ok(loaded)
}
