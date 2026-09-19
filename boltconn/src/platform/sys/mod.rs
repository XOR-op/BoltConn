#[cfg(target_os = "macos")]
pub mod macos_ffi;
#[cfg(target_os = "macos")]
mod macos_sys;

#[cfg(target_os = "macos")]
pub use macos_sys::*;
#[cfg(not(windows))]
use std::io;
#[cfg(not(windows))]
use std::net::IpAddr;

#[cfg(target_os = "macos")]
pub use macos_ffi as ffi;
#[cfg(target_os = "macos")]
pub use macos_sys::MACOS_PLACEHOLDER_DNS;

#[cfg(target_os = "linux")]
pub mod linux_ffi;
#[cfg(target_os = "linux")]
mod linux_sys;

#[cfg(target_os = "linux")]
pub use linux_ffi as ffi;
#[cfg(target_os = "linux")]
pub use linux_sys::*;

#[cfg(not(target_os = "windows"))]
mod unix_sys;

#[cfg(not(target_os = "windows"))]
pub use unix_sys::*;

#[cfg(target_os = "windows")]
mod windows_sys;

#[cfg(target_os = "windows")]
pub use windows_sys::*;

#[cfg(not(windows))]
pub fn get_iface_address(iface_name: &str) -> io::Result<IpAddr> {
    get_iface(iface_name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))
        .and_then(|iface| {
            let mut v6_addr = None;
            for ip in iface.ips {
                match ip.ip() {
                    IpAddr::V4(addr) => return Ok(IpAddr::from(addr)),
                    IpAddr::V6(addr) => v6_addr = Some(IpAddr::from(addr)),
                }
            }
            v6_addr.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no ip address found"))
        })
}

#[cfg(not(windows))]
pub fn get_iface(name: &str) -> Option<pnet_datalink::NetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}

#[cfg(windows)]
mod windows_interface;
#[cfg(windows)]
pub use windows_interface::{bind_to_interface_v4, get_default_v4_route, get_iface_address};

#[cfg(windows)]
pub(crate) use windows_interface::{get_iface_guid, get_iface_index};

#[cfg(windows)]
mod windows_dns;
#[cfg(windows)]
pub use windows_dns::SystemDnsHandle;
