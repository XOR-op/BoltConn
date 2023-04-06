#[allow(clippy::module_inception)]
mod config;
mod module;
mod proxy_group;
mod proxy_provider;
mod rule_provider;
mod state;

use crate::state_path;
pub use config::*;
pub use module::*;
pub use proxy_group::*;
pub use proxy_provider::*;
pub use rule_provider::*;
pub use state::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, io};

fn safe_join_path(root: &Path, file_path: &str) -> io::Result<PathBuf> {
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
    pub async fn load_config(config_path: &Path) -> anyhow::Result<Self> {
        let config_text = fs::read_to_string(config_path.join("config.yml"))?;
        let raw_config: RawRootCfg = serde_yaml::from_str(&config_text)?;
        let state_text = fs::read_to_string(state_path(config_path))?;
        let raw_state: RawState = serde_yaml::from_str(&state_text)?;

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
        let module_schema =
            tokio::join!(read_module_schema(config_path, &raw_config.module, false)).0?;
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
        let mut rewrite = vec![];
        for i in self.module_schema.drain(..) {
            rule_local.extend(i.rule_local.into_iter());
            self.config
                .rule_provider
                .extend(i.rule_provider.into_iter());
            intercept_rule.extend(i.intercept_rule.into_iter());
            rewrite.extend(i.rewrite.into_iter());
        }
        rule_local.append(&mut self.config.rule_local);
        intercept_rule.append(&mut self.config.intercept_rule);
        rewrite.append(&mut self.config.rewrite);
        self.config.rule_local = rule_local;
        self.config.intercept_rule = intercept_rule;
        self.config.rewrite = rewrite;
    }
}
