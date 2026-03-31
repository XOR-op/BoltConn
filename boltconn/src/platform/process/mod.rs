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

#[derive(Debug, Clone)]
pub enum ParentProcess {
    Ppid(i32),
    Process(Box<ProcessInfo>),
}

impl Default for ParentProcess {
    fn default() -> Self {
        Self::Ppid(0)
    }
}

#[derive(Debug, Default, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub parent: ParentProcess,
    pub path: String,
    pub name: String,
    pub cmdline: String,
    pub cwd: String,
}

impl ProcessInfo {
    pub fn parent_pid(&self) -> i32 {
        match &self.parent {
            ParentProcess::Ppid(ppid) => *ppid,
            ParentProcess::Process(parent) => parent.pid,
        }
    }

    pub fn parent_info(&self) -> Option<&ProcessInfo> {
        match &self.parent {
            ParentProcess::Ppid(_) => None,
            ParentProcess::Process(parent) => Some(parent.as_ref()),
        }
    }
}
