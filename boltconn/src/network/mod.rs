pub mod configure;
pub mod dns;
pub mod egress;
pub mod packet;
pub mod tun_device;
#[cfg(not(target_os = "windows"))]
mod unix_tun;
#[cfg(not(target_os = "windows"))]
use unix_tun::TunInstance;
pub mod dhcp;
#[cfg(target_os = "windows")]
mod windows_tun;

#[cfg(target_os = "windows")]
use windows_tun::TunInstance;
