pub mod configure;
pub mod dns;
pub mod egress;
pub mod packet;
pub mod tun_device;
#[cfg(not(target_os = "windows"))]
mod unix_tun;
#[cfg(not(target_os = "windows"))]
use unix_tun::TunInstance;
mod icmp;
#[cfg(target_os = "windows")]
mod windows_tun;
#[cfg(windows)]
mod windows_tun_identity;

#[cfg(target_os = "windows")]
pub(crate) use windows_tun::TunInstance;
