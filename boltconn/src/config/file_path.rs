use crate::config::set_real_ownership;
use anyhow::Context;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn test_or_create_path(path: &Path) -> anyhow::Result<()> {
    let mut current_path = PathBuf::new();
    for comp in path.components() {
        current_path.push(comp);
        match current_path.try_exists() {
            Ok(true) => {}
            Ok(false) => {
                fs::create_dir(&current_path)
                    .with_context(|| format!("{:?}", current_path.clone()))?;
                set_real_ownership(&current_path)?;
            }
            Err(e) => Err(e)?,
        }
    }
    Ok(())
}

pub fn test_or_create_config(path: &Path) -> anyhow::Result<()> {
    test_or_create_file(path, "config.yml", include_str!("default/config.yml"))
}

pub fn test_or_create_state(path: &Path) -> anyhow::Result<()> {
    test_or_create_file(path, "state.yml", include_str!("default/state.yml"))
}

fn test_or_create_file(path: &Path, file_name: &str, file_content: &str) -> anyhow::Result<()> {
    test_or_create_path(path)?;
    let config_path = path.to_path_buf().join(file_name);
    match config_path.try_exists() {
        Ok(true) => {}
        Ok(false) => {
            fs::write(&config_path, file_content)?;
            set_real_ownership(&config_path)?;
        }
        Err(e) => Err(e)?,
    }
    Ok(())
}

pub(crate) fn parse_paths(
    config: &Option<PathBuf>,
    app_data: &Option<PathBuf>,
    cert: &Option<PathBuf>,
) -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
    let config_path = match config {
        None => {
            let home = PathBuf::from(std::env::var("HOME")?);
            home.join(".config").join("boltconn")
        }
        Some(p) => p.clone(),
    };
    let data_path = match app_data {
        None => {
            let home = PathBuf::from(std::env::var("HOME")?);
            home.join(".local").join("share").join("boltconn")
        }
        Some(p) => p.clone(),
    };
    let cert_path = match cert {
        None => data_path.join("cert"),
        Some(p) => p.clone(),
    };
    Ok((config_path, data_path, cert_path))
}
