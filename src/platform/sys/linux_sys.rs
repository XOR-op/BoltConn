use super::linux_ffi::*;
use crate::common::async_raw_fd;
use crate::platform::run_command;
use crate::platform::{create_req, linux_ffi};
use ipnet::IpNet;
use libc::{bind, c_int, sockaddr, sockaddr_in, socklen_t, O_RDWR};
use std::ffi::CStr;
use std::os::unix::io::RawFd;
use std::{io, mem};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, IpAddr};

use super::super::errno_err;

pub unsafe fn open_tun() -> io::Result<(i32, String)> {
    let mut req: ifreq = mem::zeroed();
    req.ifru.flags = IFF_TUN | IFF_NO_PI;
    let fd = {
        let fd = libc::open(b"/dev/net/tun\0".as_ptr() as *const _, O_RDWR);
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

pub fn add_route_entry(subnet: IpNet, name: &str) -> io::Result<()> {
    // todo: do not use external commands
    run_command("ip", ["route", "add", &format!("{}", subnet), "dev", name])
}

pub fn delete_route_entry(addr: IpAddr) -> io::Result<()> {
    // todo: do not use external commands
    run_command(
        "ip",
        [
            "route",
            "delete",
            &format!("{}", addr),
        ],
    )
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
    const PATH: &str = "/tmp/fake_resolv.conf";
    const RESOLV: &str = "/etc/resolv.conf";
    pub fn new(ip: Ipv4Addr) -> io::Result<Self> {
        let mut output = File::create(Self::PATH).unwrap_or(
            OpenOptions::new().read(true).write(true).truncate(true).open(Self::PATH)?
        );
        output.write_all(format!("nameserver {}\n", ip).as_bytes())?;
        run_command("mount", ["--bind", Self::PATH, Self::RESOLV])?;
        Ok(Self {})
    }
}

impl Drop for SystemDnsHandle {
    fn drop(&mut self) {
        let _ = run_command("umount", [Self::RESOLV]);
    }
}