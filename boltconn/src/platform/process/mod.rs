#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Tcp,
    Udp,
}

impl std::fmt::Display for NetworkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkType::Tcp => write!(f, "tcp"),
            NetworkType::Udp => write!(f, "udp"),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub path: String,
    pub name: String,
    pub cmdline: String,
    pub parent_name: Option<String>,
}
