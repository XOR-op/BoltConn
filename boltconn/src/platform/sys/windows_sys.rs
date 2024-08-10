use ipnet::{IpNet, Ipv4Net};
use libc::c_int;
use pnet::ipnetwork::IpNetwork;
use std::net::Ipv4Addr;
use std::os::windows::raw::HANDLE;
use std::{io, net::IpAddr};
use windows::Win32::Networking::WinSock::SOCKET_ERROR;

use crate::common::io_err;

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

pub fn bind_to_device(fd: HANDLE, dst_iface_name: &str) -> io::Result<()> {
    Ok(())
}

pub fn get_default_v4_route() -> io::Result<(IpAddr, String)> {
    todo!()
}

pub struct SystemDnsHandle {}

impl SystemDnsHandle {
    pub fn new(dns_addr: Ipv4Addr) -> io::Result<Self> {
        todo!()
    }
}

pub fn get_user_info() -> Option<UserInfo> {
    todo!()
}

pub fn set_maximum_opened_files(target_size: u32) -> io::Result<u32> {
    todo!()
}

pub fn interface_up(_fd: c_int, _name: &str) -> io::Result<()> {
    todo!()
}

pub fn set_address(_fd: c_int, _name: &str, _addr: Ipv4Net) -> io::Result<()> {
    todo!()
}

pub fn get_iface_address(iface_name: &str) -> io::Result<IpAddr> {
    let iface = pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == iface_name)
        .ok_or_else(|| io_err("interface not found"))?;
    // find v4 first, otherwise v6
    if let Some(ip) = iface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V4(ipv4) => Some(ipv4.ip()),
        _ => None,
    }) {
        Ok(ip.into())
    } else if let Some(ip) = iface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V6(ipv6) => Some(ipv6.ip()),
        _ => None,
    }) {
        Ok(ip.into())
    } else {
        Err(io_err("no ip address found"))
    }
}

unsafe fn set_dest(_fd: c_int, _name: &str, _addr: Ipv4Addr) -> io::Result<()> {
    todo!()
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub name: String,
}

impl UserInfo {
    pub fn chown(&self, _path: &std::path::Path) -> io::Result<()> {
        todo!()
    }

    pub fn root() -> UserInfo {
        UserInfo {
            name: "root".to_string(),
        }
    }
}
