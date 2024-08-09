use std::{io, net::IpAddr};

use ipnet::IpNet;
use libc::c_int;

use crate::common::io_err;

pub unsafe fn open_tun() -> io::Result<(i32, String)> {
    let name = "utun13";
    let Ok(module) = wintun::load() else {
        tracing::error!("Failed to load wintun. Check if wintun.dll exists");
        return Err(io_err("Failed to load wintun.dll"));
    };
    let device = wintun::Adapter::create(&module, name, "utun", None)
        .map_err(io_err("Failed to create wintun adapter"))?;
}

pub fn add_route_entry(subnet: IpNet, name: &str) -> io::Result<()> {
    todo!()
}

pub fn add_route_entry_via_gateway(dst: IpAddr, gw: IpAddr, name: &str) -> io::Result<()> {
    todo!()
}

pub fn delete_route_entry(addr: IpNet) -> io::Result<()> {
    todo!()
}

pub fn get_default_route() -> io::Result<(IpAddr, String)> {
    todo!()
}

pub fn bind_to_device(fd: c_int, dst_iface_name: &str) -> io::Result<()> {
    todo!()
}

pub fn get_default_v4_route() -> io::Result<(IpAddr, String)> {
    todo!()
}

pub struct SystemDnsHandle {}

pub fn get_user_info() -> Option<(String, libc::uid_t, libc::gid_t)> {
    todo!()
}

pub fn set_maximum_opened_files(target_size: u32) -> io::Result<u32> {
    todo!()
}
