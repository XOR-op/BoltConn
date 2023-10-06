#[allow(clippy::module_inception)]
mod config;
mod inbound;
mod file_path;
mod interception;
mod module;
mod proxy_group;
mod proxy_provider;
mod rule;
mod rule_provider;
mod state;

use crate::platform::get_user_info;
use anyhow::anyhow;
pub use config::*;
pub use inbound::*;
pub(crate) use file_path::*;
pub use interception::*;
pub use module::*;
pub use proxy_group::*;
pub use proxy_provider::*;
pub use rule::*;
pub use rule_provider::*;
use serde::{Deserialize, Serialize};
pub use state::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, io};

pub fn safe_join_path(root: &Path, file_path: &str) -> io::Result<PathBuf> {
    let file_path = if file_path.starts_with('/') {
        PathBuf::from_str(file_path).unwrap()
    } else {
        root.join(file_path)
    };
    // we use parent path in order to ensure fs::canonicalize does not return Err
    let file_folder_path = file_path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?
        .canonicalize()?;
    if file_folder_path.starts_with(root.canonicalize()?) {
        Ok(file_path)
    } else {
        Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
    }
}

pub struct LoadedConfig {
    pub config: RawRootCfg,
    pub state: RawState,
    pub rule_schema: HashMap<String, RuleSchema>,
    pub proxy_schema: HashMap<String, ProxySchema>,
    pub module_schema: Vec<ModuleSchema>,
}

impl LoadedConfig {
    pub fn state_path(app_data_path: &Path) -> PathBuf {
        app_data_path.join("state.yml")
    }

    pub async fn load_config(config_path: &Path, data_path: &Path) -> anyhow::Result<Self> {
        let config_text = fs::read_to_string(config_path.join("config.yml"))
            .map_err(|e| anyhow!("config.yml ({:?}): {}", config_path, e))?;
        let mut raw_config: RawRootCfg =
            serde_yaml::from_str(&config_text).map_err(|e| anyhow!("Read config.yml: {}", e))?;
        let state_text = fs::read_to_string(Self::state_path(data_path))
            .map_err(|e| anyhow!("state.yml ({:?}): {}", data_path, e))?;
        let raw_state: RawState =
            serde_yaml::from_str(&state_text).map_err(|e| anyhow!("Read state.yml: {}", e))?;

        let module_schema =
            tokio::join!(read_module_schema(config_path, &raw_config.module, false)).0?;

        for i in module_schema.iter() {
            for (k, v) in i.rule_provider.iter() {
                raw_config.rule_provider.insert(k.clone(), v.clone());
            }
        }

        let rule_schema = tokio::join!(read_rule_schema(
            config_path,
            &raw_config.rule_provider,
            false
        ))
        .0?;
        let proxy_schema = tokio::join!(read_proxy_schema(
            config_path,
            &raw_config.proxy_provider,
            false
        ))
        .0?;
        let mut ret = Self {
            config: raw_config,
            state: raw_state,
            rule_schema,
            proxy_schema,
            module_schema,
        };
        ret.apply_module();
        Ok(ret)
    }

    pub fn apply_module(&mut self) {
        let mut rule_local = vec![];
        let mut intercept_rule = vec![];
        for i in self.module_schema.drain(..) {
            rule_local.extend(i.rule_local.into_iter());
            intercept_rule.extend(i.interception.into_iter());
        }
        rule_local.append(&mut self.config.rule_local);
        intercept_rule.append(&mut self.config.interception);
        self.config.rule_local = rule_local;
        self.config.interception = intercept_rule;
    }
}

async fn load_remote_config<T>(
    url: String,
    path: String,
    root_path: impl AsRef<Path>,
    force_update: bool,
) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let full_path = safe_join_path(root_path.as_ref(), &path)?;
    let content: T = if !force_update && full_path.as_path().exists() {
        serde_yaml::from_str(fs::read_to_string(full_path.as_path())?.as_str())?
    } else {
        tracing::trace!("Downloading external resource from {}", url);
        let resp = reqwest::get(url).await?;
        let text = resp.text().await?;
        let content: T = serde_yaml::from_str(text.as_str())?;
        // security: `full_path` should be (layers of) subdir of `root_path`,
        //           so arbitrary write should not happen
        fs::write(full_path.as_path(), text)?;
        set_real_ownership(&full_path)?;
        content
    };
    Ok(content)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthData {
    pub username: String,
    pub password: String,
}

pub(super) fn set_real_ownership(path: &Path) -> io::Result<()> {
    if let Some((_, uid, gid)) = get_user_info() {
        nix::unistd::chown(path, Some(uid.into()), Some(gid.into()))?;
    }
    Ok(())
}
