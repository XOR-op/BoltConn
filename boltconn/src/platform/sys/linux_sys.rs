use super::linux_ffi::*;
use crate::common::io_err;
use crate::platform::sys::unix_sys::create_req;
use crate::platform::{
    get_command_output, linux_ffi, run_command, run_command_with_args, UserInfo,
};
use ipnet::IpNet;
use libc::{c_int, socklen_t, O_RDWR};
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::{cmp, io, mem};

use super::super::errno_err;

pub unsafe fn open_tun() -> io::Result<(i32, String)> {
    let mut req: ifreq = mem::zeroed();
    req.ifru.flags = IFF_TUN | IFF_NO_PI;
    let fd = {
        let fd = libc::open(c"/dev/net/tun".as_ptr() as *const _, O_RDWR);
        if fd < 0 {
            return Err(errno_err("Failed to open /dev/net/tun"));
        }
        fd
    };
    if tunsetiff(fd, &mut req as *mut _ as *mut _) < 0 {
        libc::close(fd);
        return Err(errno_err("Failed to tunsetiff"));
    }
    Ok((
        fd,
        CStr::from_ptr(req.ifrn.name.as_ptr())
            .to_string_lossy()
            .into_owned(),
    ))
}

fn ip_command_by_addr(addr: &IpAddr) -> Command {
    let mut cmd = Command::new("ip");
    if matches!(addr, IpAddr::V6(_)) {
        cmd.arg("-6");
    }
    cmd
}

fn ip_command_by_net(addr: &IpNet) -> Command {
    let mut cmd = Command::new("ip");
    if matches!(addr, IpNet::V6(_)) {
        cmd.arg("-6");
    }
    cmd
}

pub fn add_route_entry(subnet: IpNet, name: &str) -> io::Result<()> {
    run_command(ip_command_by_net(&subnet).args([
        "route",
        "add",
        &format!("{}", subnet),
        "dev",
        name,
    ]))
}

pub fn add_route_entry_via_gateway(dst: IpAddr, gw: IpAddr, name: &str) -> io::Result<()> {
    run_command(ip_command_by_addr(&dst).args([
        "route",
        "add",
        &format!("{}", dst),
        "dev",
        name,
        "via",
        &format!("{}", gw),
    ]))
}

pub fn delete_route_entry(addr: IpNet) -> io::Result<()> {
    run_command(ip_command_by_net(&addr).args(["route", "delete", &format!("{}", addr)]))
}

pub fn get_default_v4_route() -> io::Result<(IpAddr, String)> {
    let words: Vec<String> = get_command_output("ip", ["-s", "route", "get", "1.1.1.1"])?
        .split(' ')
        .map(|s| s.to_string())
        .collect();
    // example: 1.1.1.1 via 192.168.0.1 dev en0 src 192.168.0.100 uid 1000
    if words.len() >= 5 && words[1] == "via" && words[3] == "dev" && words[0] == "1.1.1.1" {
        let gw = words[2]
            .parse()
            .map_err(|e| io_err(format!("Invalid gateway:{:?}", e).as_str()))?;
        Ok((gw, words[4].clone()))
    } else {
        Err(io_err("Invalid parse"))
    }
}

pub fn bind_to_device(fd: c_int, dst_iface_name: &str) -> io::Result<()> {
    unsafe {
        let req = create_req(dst_iface_name);
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            &req as *const linux_ffi::ifreq as *const libc::c_void,
            mem::size_of_val(&req) as socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub struct SystemDnsHandle {}

impl SystemDnsHandle {
    const PATH: &'static str = "/tmp/fake_resolv.conf";
    const RESOLV: &'static str = "/etc/resolv.conf";
    pub fn new(ip: Ipv4Addr, _tun_name: &str, _outbound_name: &str) -> io::Result<Self> {
        let mut output = File::create(Self::PATH).unwrap_or(
            OpenOptions::new()
                .read(true)
                .write(true)
                .truncate(true)
                .open(Self::PATH)?,
        );
        output.write_all(format!("nameserver {}\n", ip).as_bytes())?;
        run_command_with_args("mount", ["--bind", Self::PATH, Self::RESOLV])?;
        Ok(Self {})
    }
}

impl Drop for SystemDnsHandle {
    fn drop(&mut self) {
        let _ = run_command_with_args("umount", [Self::RESOLV]);
    }
}

pub fn get_user_info() -> Option<UserInfo> {
    let (name, user_info) = if let Ok(n) = std::env::var("SUDO_USER") {
        let user_info = unsafe { libc::getpwnam(CString::new(n.clone()).ok()?.as_ptr()) };
        (n, user_info)
    } else {
        let user_name = unsafe { libc::getlogin() };
        if user_name.is_null() {
            return None;
        }
        let name = unsafe { CStr::from_ptr(user_name) }
            .to_string_lossy()
            .into_owned();
        let user_info = unsafe { libc::getpwnam(user_name) };
        (name, user_info)
    };
    if user_info.is_null() {
        return None;
    }
    let uid = unsafe { (*user_info).pw_uid };
    let gid = unsafe { (*user_info).pw_gid };
    Some(UserInfo { name, uid, gid })
}

pub fn set_maximum_opened_files(target_size: u32) -> io::Result<u32> {
    unsafe {
        // Fetch the current resource limits
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) != 0 {
            return Err(io::Error::last_os_error());
        }

        // Set soft limit to hard imit
        rlim.rlim_cur = cmp::min(rlim.rlim_max, target_size as libc::rlim_t);

        // Set our newly-increased resource limit
        if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(rlim.rlim_cur as u32)
    }
}

pub(crate) unsafe fn set_dest(_fd: c_int, _name: &str, _addr: Ipv4Addr) -> io::Result<()> {
    // nop
    Ok(())
}
