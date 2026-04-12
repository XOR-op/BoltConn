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

mod token;
#[cfg(target_os = "windows")]
pub use token::setup_token_env;
#[cfg(unix)]
pub use token::setup_token_fd;
pub use token::validate_and_encode_token;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessInfoDepth {
    Limited(u32),
    Unlimited,
}

impl ProcessInfoDepth {
    pub fn next_level(self) -> Option<Self> {
        match self {
            Self::Limited(0) => None,
            Self::Limited(depth) => Some(Self::Limited(depth - 1)),
            Self::Unlimited => Some(Self::Unlimited),
        }
    }
}

impl Serialize for ProcessInfoDepth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Limited(depth) => serializer.serialize_u32(*depth),
            Self::Unlimited => serializer.serialize_str("unlimited"),
        }
    }
}

impl<'de> Deserialize<'de> for ProcessInfoDepth {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProcessInfoDepthVisitor;

        impl Visitor<'_> for ProcessInfoDepthVisitor {
            type Value = ProcessInfoDepth;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a non-negative integer or the string \"unlimited\"")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                u32::try_from(value)
                    .map(ProcessInfoDepth::Limited)
                    .map_err(|_| E::custom("process_info_depth exceeds u32"))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = u32::try_from(value)
                    .map_err(|_| E::custom("process_info_depth must be non-negative"))?;
                Ok(ProcessInfoDepth::Limited(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "unlimited" => Ok(ProcessInfoDepth::Unlimited),
                    _ => Err(E::custom(format!(
                        "invalid process_info_depth {value:?}, expected a non-negative integer or \"unlimited\""
                    ))),
                }
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_any(ProcessInfoDepthVisitor)
    }
}

#[derive(Debug, Clone)]
pub enum ParentProcess {
    None,
    Ppid(i32),
    Process(Box<ProcessInfo>),
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub parent: ParentProcess,
    pub path: String,
    pub name: String,
    pub cmdline: String,
    pub cwd: String,
    /// Bolt token assigned at launch via `boltconn run`, if present.
    pub token: Option<String>,
}

impl ProcessInfo {
    pub fn parent_pid(&self) -> i32 {
        match &self.parent {
            ParentProcess::None => 0,
            ParentProcess::Ppid(ppid) => *ppid,
            ParentProcess::Process(parent) => parent.pid,
        }
    }

    pub fn parent_info(&self) -> Option<&ProcessInfo> {
        match &self.parent {
            ParentProcess::None => None,
            ParentProcess::Ppid(_) => None,
            ParentProcess::Process(parent) => Some(parent.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessInfoDepth;

    #[test]
    fn test_process_info_depth_next_level_for_limited_depth() {
        assert_eq!(
            ProcessInfoDepth::Limited(2).next_level(),
            Some(ProcessInfoDepth::Limited(1))
        );
        assert_eq!(ProcessInfoDepth::Limited(0).next_level(), None);
    }

    #[test]
    fn test_process_info_depth_next_level_for_unlimited_depth() {
        assert_eq!(
            ProcessInfoDepth::Unlimited.next_level(),
            Some(ProcessInfoDepth::Unlimited)
        );
    }
}
