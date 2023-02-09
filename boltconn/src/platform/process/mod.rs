#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Tcp,
    Udp,
}

#[derive(Debug, Default, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub path: String,
    pub name: String,
}
