use super::macos_ffi::*;
use crate::common::io_err;
use crate::platform::{errno_err, get_command_output, run_command};
use ipnet::IpNet;
use libc::{c_char, c_int, c_void, sockaddr, socklen_t, SOCK_DGRAM};
use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr};
use std::{io, mem};

pub unsafe fn open_tun() -> io::Result<(i32, String)> {
    let mut name_buf = [0u8; 32];
    let mut name_len: socklen_t = 32;
    for sc_unit in 0..256 {
        let fd = {
            let fd = libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(errno_err("Failed to pen tun socket"));
            }
            fd
        };

        let mut ctl_info = ctl_info {
            ctl_id: 0,
            ctl_name: {
                let mut r: [c_char; 96] = [0; 96];
                UTUN_CONTROL_NAME
                    .bytes()
                    .zip(r.iter_mut())
                    .for_each(|(c, ptr)| *ptr = c as c_char);
                r
            },
        };

        if ctliocginfo(fd, &mut ctl_info as *mut _) < 0 {
            libc::close(fd);
            return Err(errno_err("Failed to get fd info"));
        }

        let sock_ctl = sockaddr_ctl {
            sc_len: mem::size_of::<sockaddr_ctl>() as _,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: ctl_info.ctl_id,
            sc_unit,
            sc_reserved: [0; 5],
        };

        if libc::connect(
            fd,
            &sock_ctl as *const sockaddr_ctl as *const sockaddr,
            mem::size_of_val(&sock_ctl) as socklen_t,
        ) < 0
        {
            libc::close(fd);
            continue;
        }

        if libc::getsockopt(
            fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            &mut name_buf as *mut u8 as *mut c_void,
            &mut name_len as *mut socklen_t,
        ) < 0
        {
            libc::close(fd);
            return Err(errno_err("Failed to get socket options"));
        }
        return Ok((
            fd,
            CStr::from_ptr(name_buf.as_ptr() as *const c_char)
                .to_string_lossy()
                .into_owned(),
        ));
    }

    Err(errno_err("No available sc_unit"))
}

pub fn add_route_entry(subnet: IpNet, name: &str) -> io::Result<()> {
    // todo: do not use external commands
    run_command(
        "route",
        [
            "-n",
            "add",
            "-net",
            &format!("{}", subnet),
            "-interface",
            name,
        ],
    )
}

pub fn add_route_entry_via_gateway(dst: IpAddr, gw: IpAddr, _name: &str) -> io::Result<()> {
    run_command(
        "route",
        ["-n", "add", &format!("{}", dst), &format!("{}", gw)],
    )
}

pub fn delete_route_entry(addr: IpAddr) -> io::Result<()> {
    // todo: do not use external commands
    run_command("route", ["-n", "delete", &format!("{}", addr)])
}

pub fn bind_to_device(fd: c_int, dst_iface_name: &str) -> io::Result<()> {
    let c_name = std::ffi::CString::new(dst_iface_name).unwrap();
    unsafe {
        let idx = libc::if_nametoindex(c_name.as_ptr());
        if libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            &idx as *const _ as *const _,
            mem::size_of_val(&idx) as socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn get_default_route() -> io::Result<(IpAddr, String)> {
    let lines: Vec<String> = get_command_output("route", ["-n", "get", "1.1.1.1"])?
        .split("\n")
        .map(|s| s.to_string())
        .collect();
    let kv: HashMap<String, String> = lines
        .into_iter()
        .filter_map(|l| {
            let vec: Vec<&str> = l.split(": ").collect();
            if vec.len() == 2 {
                Some((vec[0].trim().to_string(), vec[1].to_string()))
            } else {
                None
            }
        })
        .collect();
    if kv.contains_key("interface") && kv.contains_key("gateway") {
        let gw: IpAddr = kv
            .get("gateway")
            .unwrap()
            .parse()
            .map_err(|_| io_err("Invalid gateway"))?;
        let iface = kv.get("interface").unwrap().to_string();
        Ok((gw, iface))
    } else {
        Err(io_err("Missing interface/gateway"))
    }
}

pub struct SystemDnsHandle {
    old_dns: Vec<Vec<String>>,
}

impl SystemDnsHandle {
    pub fn new(ip: Ipv4Addr) -> io::Result<Self> {
        let services: Vec<String> =
            get_command_output("networksetup", ["-listallnetworkservices"])?
                .split("\n")
                .map(|s| {
                    if s.len() > 0 && !s.contains("*") {
                        Some(s)
                    } else {
                        None
                    }
                })
                .filter_map(|x| x.and_then(|s| Some(s.to_string())))
                .collect();
        let mut old_dns = Vec::new();
        // get old records
        for s in services.iter() {
            let dns_list = get_command_output("networksetup", ["-getdnsservers", s])?;
            let mut v = vec![s.clone()];
            if !dns_list.starts_with("There") {
                v.extend(
                    dns_list
                        .split("\n")
                        .map(|s| if s.len() > 0 { Some(s) } else { None })
                        .filter_map(|x| x.and_then(|s| Some(String::from(s)))),
                );
            } else {
                v.push("empty".parse().unwrap());
            }
            old_dns.push(v);
        }

        // overwrite them
        for s in services.iter() {
            run_command("networksetup", ["-setdnsservers", s, &ip.to_string()])?
        }
        Ok(Self { old_dns })
    }
}

impl Drop for SystemDnsHandle {
    fn drop(&mut self) {
        for args in self.old_dns.iter() {
            let mut v = vec![String::from("-setdnsservers")];
            v.extend_from_slice(args);
            run_command("networksetup", v).unwrap_or(());
        }
    }
}
