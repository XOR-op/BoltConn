use crate::config::{FileError, set_real_ownership};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn test_or_create_path(path: &Path) -> Result<bool, FileError> {
    let mut current_path = PathBuf::new();
    let mut created = false;
    for comp in path.components() {
        current_path.push(comp);
        let io_error = |e| FileError::Io(current_path.to_string_lossy().to_string(), e);
        match current_path.try_exists() {
            Ok(true) => {}
            Ok(false) => {
                created = true;
                fs::create_dir(&current_path).map_err(io_error)?;
                set_real_ownership(&current_path).map_err(io_error)?;
            }
            Err(e) => Err(io_error(e))?,
        }
    }
    Ok(created)
}

pub fn test_or_create_config(path: &Path) -> Result<bool, FileError> {
    test_or_create_file(path, "config.yml", include_str!("default/config.yml"))
}

pub fn test_or_create_state(path: &Path) -> Result<bool, FileError> {
    test_or_create_file(path, "state.yml", include_str!("default/state.yml"))
}

fn test_or_create_file(
    path: &Path,
    file_name: &str,
    file_content: &str,
) -> Result<bool, FileError> {
    let mut created = test_or_create_path(path)?;
    let config_path = path.to_path_buf().join(file_name);
    let io_error = |e| FileError::Io(config_path.to_string_lossy().to_string(), e);
    match config_path.try_exists() {
        Ok(true) => {}
        Ok(false) => {
            created = true;
            fs::write(&config_path, file_content).map_err(io_error)?;
            set_real_ownership(&config_path).map_err(io_error)?;
        }
        Err(e) => Err(io_error(e))?,
    }
    Ok(created)
}

pub(crate) fn parse_paths(
    config: &Option<PathBuf>,
    app_data: &Option<PathBuf>,
    cert: &Option<PathBuf>,
) -> Result<(PathBuf, PathBuf, PathBuf), FileError> {
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
