use crate::config::set_real_ownership;
use anyhow::Context;
use std::fs;
use std::path::{Path, PathBuf};

fn test_or_create_path(path: &Path) -> anyhow::Result<()> {
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
