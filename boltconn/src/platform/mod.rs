use ipnet::Ipv4Net;
use libc::{c_char, c_int};
use std::ffi::OsStr;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Stdio};
use std::{io, mem, ptr};

pub mod route;

pub mod process;
mod sys;
use sys::ffi;
pub use sys::*;

pub use crate::common::async_raw_fd::AsyncRawFd;

pub fn errno_err(msg: &str) -> io::Error {
    io::Error::new(io::Error::last_os_error().kind(), msg)
}

pub fn run_command<I, S>(cmd: &str, args: I) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut handle = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let status = handle.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            ErrorKind::Other,
            format!("Subcommand exit status: {}", status),
        ))
    }
}

fn get_command_output<I, S>(cmd: &str, args: I) -> io::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if output.status.success() {
        String::from_utf8(output.stdout).map_err(|e| io::Error::new(ErrorKind::Other, e))
    } else {
        Err(io::Error::new(
            ErrorKind::Other,
            format!("Subcommand exit status: {}", output.status),
        ))
    }
}

unsafe fn create_req(name: &str) -> ffi::ifreq {
    let mut req: ffi::ifreq = mem::zeroed();
    ptr::copy_nonoverlapping(
        name.as_ptr() as *const c_char,
        req.ifrn.name.as_mut_ptr(),
        name.len(),
    );
    req
}

pub fn interface_up(fd: c_int, name: &str) -> io::Result<()> {
    unsafe {
        let mut req = create_req(name);
        if ffi::siocgifflags(fd, &mut req) < 0 {
            return Err(errno_err("Failed to read ifflags"));
        }
        req.ifru.flags |= ffi::IFF_UP | ffi::IFF_RUNNING;
        if ffi::siocsifflags(fd, &req) < 0 {
            return Err(errno_err("Failed to up tun"));
        }
        Ok(())
    }
}

pub(crate) unsafe fn get_sockaddr(v4: Ipv4Addr) -> libc::sockaddr_in {
    let mut addr = mem::zeroed::<libc::sockaddr_in>();
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(v4.octets()),
    };
    addr
}

#[cfg(target_os = "macos")]
unsafe fn set_dest(fd: c_int, name: &str, addr: Ipv4Addr) -> io::Result<()> {
    let mut addr_req = create_req(name);
    addr_req.ifru.dstaddr = mem::transmute(get_sockaddr(addr));
    if ffi::siocsifdstaddr(fd, &addr_req) < 0 {
        return Err(errno_err("Failed to set tun dst addr"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn set_dest(_fd: c_int, _name: &str, _addr: Ipv4Addr) -> io::Result<()> {
    // nop
    Ok(())
}

pub unsafe fn create_v4_raw_socket() -> io::Result<c_int> {
    let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub fn set_address(fd: c_int, name: &str, addr: Ipv4Net) -> io::Result<()> {
    unsafe {
        let mut addr_req = create_req(name);
        addr_req.ifru.addr = mem::transmute(get_sockaddr(addr.addr()));
        if ffi::siocsifaddr(fd, &addr_req) < 0 {
            return Err(errno_err("Failed to set tun addr"));
        }
        // only useful for macos; for linux, this is a nop
        set_dest(fd, name, addr.addr())?;

        // set subnet mask
        let mut mask_req = create_req(name);
        mask_req.ifru.addr = mem::transmute(get_sockaddr(addr.netmask()));
        if ffi::siocsifnetmask(fd, &mask_req) < 0 {
            return Err(errno_err("Failed to set tun mask"));
        }
        Ok(())
    }
}

pub fn get_iface_address(iface_name: &str) -> io::Result<IpAddr> {
    let ctl_fd = {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(errno_err("Unable to open control fd").into());
        }
        fd
    };
    let mut req = unsafe { create_req(iface_name) };
    req.ifru.addr.sa_family = libc::AF_INET as libc::sa_family_t;
    if unsafe { ffi::siocgifaddr(ctl_fd, &mut req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let addr = unsafe { req.ifru.addr };
    match addr.sa_family as c_int {
        libc::AF_INET => {
            let addr: libc::sockaddr_in = unsafe { mem::transmute(addr) };
            Ok(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                addr.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                format!("Ipv6 address is not acceptable for iface {}", iface_name),
            ))
            // let addr: libc::sockaddr_in6 = unsafe { mem::transmute(addr) };
            // Ok(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)))
        }
        _ => Err(io::Error::new(
            ErrorKind::AddrNotAvailable,
            format!("No address found for iface {}", iface_name),
        )),
    }
}
