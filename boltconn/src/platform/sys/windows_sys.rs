use ipnet::IpNet;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::process::Command;
use std::{io, net::IpAddr};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};

use crate::common::io_err;
use crate::platform::{get_command_output, run_command};

pub fn add_route_entry(subnet: IpNet, name: &str) -> io::Result<()> {
    let iface_index = match get_iface_index(name) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to get iface index for {}", name);
            return Err(e);
        }
    };
    run_command(ip_command_by_net(&subnet).args([
        "add",
        &format!("{}", subnet.addr()),
        "mask",
        &format!("{}", subnet.netmask()),
        "0.0.0.0",
        "if",
        &format!("{}", iface_index),
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
            "-command",
            "Find-NetRoute -RemoteIPAddress 1.1.1.1",
        ],
    )?
    .split('\n')
    .map(|s| s.to_string())
    .filter_map(|l| {
        let vec: Vec<&str> = l.split(": ").collect();
        if vec.len() == 2 {
            Some((vec[0].trim().to_string(), vec[1].trim().to_string()))
        } else {
            None
        }
    })
    .collect();
    let name_key = "InterfaceAlias";
    // let name_key = "InterfaceIndex";
    if kv.contains_key("IPAddress") && kv.contains_key(name_key) {
        let iface_addr: IpAddr = kv
            .get("IPAddress")
            .unwrap()
            .parse()
            .map_err(|_| io_err("Invalid interface address"))?;
        let iface_index = kv.get(name_key).unwrap().to_string();
        tracing::debug!("default route: {:?} {:?}", iface_addr, iface_index);
        Ok((iface_addr, iface_index))
    } else {
        Err(io_err("Missing interface"))
    }
}

struct DnsRecord {
    iface_name: String,
    iface_index: u32,
    dns_server: Vec<IpAddr>,
}

pub struct SystemDnsHandle {
    old_dns: Vec<DnsRecord>,
}

impl SystemDnsHandle {
    pub fn new(dns_addr: Ipv4Addr, tun_name: &str, outbound_name: &str) -> io::Result<Self> {
        // From https://github.com/dandyvica/resolver/blob/main/src/lib.rs
        let mut list: Vec<DnsRecord> = Vec::new();

        // first call
        let family = AF_UNSPEC.0 as u32;
        let mut buflen = 0u32;
        let mut rc = unsafe {
            GetAdaptersAddresses(family, GAA_FLAG_INCLUDE_PREFIX, None, None, &mut buflen)
        };

        // second with the actual buffer size large enough to hold data
        if rc == ERROR_BUFFER_OVERFLOW.0 {
            let mut addr = vec![0u8; buflen as usize];
            let ptr = addr.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

            rc = unsafe {
                GetAdaptersAddresses(
                    family,
                    GAA_FLAG_INCLUDE_PREFIX,
                    None,
                    Some(ptr),
                    &mut buflen,
                )
            };

            // second with the actual buffer size large enough to hold data
            if rc == ERROR_SUCCESS.0 {
                // loop through adapters and grab DNS addresses and other info
                let mut p = ptr;

                while !p.is_null() {
                    unsafe {
                        // get info an network interface
                        let iface_name = (*p).FriendlyName.display().to_string();
                        let iface_index = (*p).Ipv6IfIndex;

                        // skip non-outbound interfaces
                        if iface_name != outbound_name && iface_name != tun_name {
                            p = (*p).Next;
                            continue;
                        }

                        // now get all DNS ips for this interface
                        let mut ip_list: Vec<IpAddr> = Vec::new();
                        let mut p_dns = (*p).FirstDnsServerAddress;

                        // loop through DNS addresses for this adapter
                        while !p_dns.is_null() {
                            let sockaddr = (*p_dns).Address.lpSockaddr;
                            let dns_addr = from_sockaddr(sockaddr)?;
                            ip_list.push(dns_addr);

                            p_dns = (*p_dns).Next;
                        }

                        // save resolver into the list
                        let res = DnsRecord {
                            iface_name,
                            iface_index,
                            dns_server: ip_list,
                        };

                        list.push(res);

                        p = (*p).Next;
                    }
                }
            } else {
                return Err(ErrorKind::UnexpectedEof.into());
            }
        } else {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        // set new dns
        let dns_string = dns_addr.to_string();
        for record in list.iter() {
            run_command(Command::new("netsh").args([
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                &format!("name={}", record.iface_name),
                "source=static",
                &format!("address={}", dns_string),
                "register=primary",
                "validate=no",
            ]))?;
        }
        Ok(Self { old_dns: list })
    }
}

impl Drop for SystemDnsHandle {
    fn drop(&mut self) {
        for record in self.old_dns.iter() {
            if let Some(dns) = record.dns_server.first() {
                let _ = run_command(Command::new("netsh").args([
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    &format!("name={}", record.iface_name),
                    "source=static",
                    &format!("address={}", dns),
                    "register=none",
                    "validate=no",
                ]));
            }
        }
    }
}

pub fn get_user_info() -> Option<UserInfo> {
    let name = std::env::var("USERNAME").ok()?;
    Some(UserInfo { name })
}

pub fn set_maximum_opened_files(target_size: u32) -> io::Result<u32> {
    tracing::debug!("set_maximum_opened_files does nothing on windows");
    Ok(target_size)
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub name: String,
}

impl UserInfo {
    pub fn chown(&self, _path: &std::path::Path) -> io::Result<()> {
        tracing::debug!("chown not supported on windows now");
        Ok(())
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

fn from_sockaddr(sockaddr: *const SOCKADDR) -> io::Result<IpAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // this is only valid for INET4 or 6 family
    unsafe {
        match (*sockaddr).sa_family {
            AF_INET => {
                // ip v4 addresses reported by GetAdaptersAddresses() API are like: [0, 0, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0] (for 8.8.8.8)
                let sockaddr_in = sockaddr as *const SOCKADDR_IN;
                let bytes = (*sockaddr_in).sin_addr.S_un.S_un_b;
                let ip = IpAddr::V4(Ipv4Addr::new(
                    bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
                ));
                Ok(ip)
            }
            AF_INET6 => {
                // ip v6 addresses reported by GetAdaptersAddresses() API are like: [0, 0, 0, 0, 0, 0, 254, 192, 0, 0, 0, 0, 255, 255] (for 8.8.8.8)
                let sockaddr_in = sockaddr as *const SOCKADDR_IN6;
                let bytes = (*sockaddr_in).sin6_addr.u.Byte;
                let ip = IpAddr::V6(Ipv6Addr::from(bytes));
                Ok(ip)
            }
            _ => Err(ErrorKind::Unsupported.into()),
        }
    }
}

pub(crate) fn get_iface_index(iface_name: &str) -> io::Result<u32> {
    use network_interface::NetworkInterfaceConfig;
    network_interface::NetworkInterface::show()
        .map(|interfaces| {
            interfaces
                .into_iter()
                .find(|iface| iface.name == iface_name)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))
                .map(|iface| iface.index)
        })
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "failed to get list",
            ))
        })
}
