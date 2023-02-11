#[allow(clippy::module_inception)]
mod config;
mod proxy_provider;
mod rule_provider;
mod state;

pub use config::*;
pub use proxy_provider::*;
pub use rule_provider::*;
pub use state::*;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

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
