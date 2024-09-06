use ipnet::IpNet;
use pnet::ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::{io, net::IpAddr};

use crate::common::io_err;
use crate::platform::{get_command_output, run_command};

pub fn add_route_entry(subnet: IpNet, name: &str) -> io::Result<()> {
    let iface_addr = get_iface_address(name)?;
    run_command(ip_command_by_net(&subnet).args([
        "add",
        &format!("{}", subnet.addr()),
        "mask",
        &format!("{}", subnet.netmask()),
        &format!("{}", iface_addr),
    ]))
}

pub fn delete_route_entry(addr: IpNet) -> io::Result<()> {
    run_command(ip_command_by_net(&addr).args([
        "delete",
        &format!("{}", addr.addr()),
        "mask",
        &format!("{}", addr.netmask()),
    ]))
}

pub fn get_default_v4_route() -> io::Result<(IpAddr, String)> {
    let kv: HashMap<String, String> = get_command_output(
        "powershell",
        [
            "-noprofile",
            "-commmand",
            "Find-NetRoute -RemoteIPAddress 1.1.1.1",
        ],
    )?
    .split('\n')
    .map(|s| s.to_string())
    .filter_map(|l| {
        let vec: Vec<&str> = l.split(": ").collect();
        if vec.len() == 2 {
            Some((vec[0].trim().to_string(), vec[1].to_string()))
        } else {
            None
        }
    })
    .collect();
    if kv.contains_key("IPAddress") && kv.contains_key("InterfaceIndex") {
        let iface_addr: IpAddr = kv
            .get("IPAddress")
            .unwrap()
            .parse()
            .map_err(|_| io_err("Invalid interface address"))?;
        let iface_index = kv.get("InterfaceIndex").unwrap().to_string();
        tracing::debug!("default route: {:?} {:?}", iface_addr, iface_index);
        Ok((iface_addr, iface_index))
    } else {
        Err(io_err("Missing interface"))
    }
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

pub fn set_maximum_opened_files(_target_size: u32) -> io::Result<u32> {
    tracing::debug!("set_maximum_opened_files does nothing on windows");
    Ok(())
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

fn ip_command_by_addr(addr: &IpAddr) -> Command {
    let mut cmd = Command::new("route");
    if matches!(addr, IpAddr::V6(_)) {
        cmd.arg("-6");
    }
    cmd
}

fn ip_command_by_net(addr: &IpNet) -> Command {
    let mut cmd = Command::new("route");
    if matches!(addr, IpNet::V6(_)) {
        cmd.arg("-6");
    }
    cmd
}
