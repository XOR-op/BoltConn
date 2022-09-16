use c_ffi::*;
use ipnet::IpNet;
use libc::{c_char, c_int, c_void, sockaddr, socklen_t, O_RDWR, SOCK_DGRAM};
use std::ffi::CStr;
use std::net::IpAddr;
use std::{io, mem};

pub mod c_ffi;

use super::errno_err;

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

pub unsafe fn add_route_entry(subnet: IpNet, name: &str) -> io::Result<()> {
    // todo: do not use external commands
    super::run_command("ip", ["route", "add", &format!("{}", subnet), "dev", name])
}
