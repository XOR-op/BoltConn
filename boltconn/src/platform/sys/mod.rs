#[cfg(target_os = "macos")]
pub mod macos_ffi;
#[cfg(target_os = "macos")]
mod macos_sys;

#[cfg(target_os = "macos")]
pub use macos_sys::*;
use std::io;
use std::net::IpAddr;

#[cfg(target_os = "macos")]
pub use macos_ffi as ffi;

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

pub fn get_iface(name: &str) -> Option<pnet_datalink::NetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}
