use std::process::Command;
use std::{fmt, io, mem, ptr};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use libc::{c_char, c_int};
use thiserror::Error;

pub mod tun_device;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
use linux as platform;

use platform::c_ffi;

#[derive(Debug, Error)]
pub enum SysError {
    IoError(#[from] io::Error),
    ExitStatus(std::process::ExitStatus),
}

pub fn errno_err(msg: &str) -> io::Error {
    io::Error::new(io::Error::last_os_error().kind(), msg)
}

impl fmt::Display for SysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            SysError::IoError(ref err) => write!(f, "IO Error: {}", err),
            SysError::ExitStatus(ref err) => write!(f, "Exit Status: {:?}", err),
        }
    }
}

fn run_command(cmd: &str, args: &[&str]) -> Result<(), SysError> {
    let mut handle = Command::new(cmd).args(args).spawn()?;
    let status = handle.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(SysError::ExitStatus(status))
    }
}

fn run_privileged_command(cmd: &str, args: &[&str]) -> Result<(), SysError> {
    let mut handle = Command::new("sudo").arg(cmd).args(args).spawn()?;
    let status = handle.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(SysError::ExitStatus(status))
    }
}

unsafe fn create_req(name: &str) -> c_ffi::ifreq {
    let mut req: c_ffi::ifreq = mem::zeroed();
    ptr::copy_nonoverlapping(
        name.as_ptr() as *const c_char,
        req.ifrn.name.as_mut_ptr(),
        name.len(),
    );
    req
}

pub unsafe fn interface_up(fd: c_int, name: &str) -> io::Result<()> {
    let mut req = create_req(name);
    if c_ffi::siocgifflags(fd, &mut req) < 0 {
        return Err(errno_err("Failed to read ifflags"));
    }
    req.ifru.flags |= c_ffi::IFF_UP | c_ffi::IFF_RUNNING;
    if c_ffi::siocsifflags(fd, &req) < 0 {
        return Err(errno_err("Failed to up tun"));
    }
    Ok(())
}

unsafe fn get_sockaddr(v4: Ipv4Addr) -> libc::sockaddr_in {
    let mut addr = mem::zeroed::<libc::sockaddr_in>();
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(v4.octets())
    };
    addr
}

pub unsafe fn set_address(fd: c_int, name: &str, addr: Ipv4Addr, subnet: u8) -> io::Result<()> {
    let mut addr_req = create_req(name);
    addr_req.ifru.addr = mem::transmute(get_sockaddr(addr));
    // addr_req.ifru.dstaddr = addr_req.ifru.addr;
    if c_ffi::siocsifaddr(fd, &addr_req) < 0 {
        return Err(errno_err("Failed to set tun src_addr"));
    }
    let mask_addr = {
        assert!(subnet <= 32);
        let v = (u32::MAX) ^ (1u32.checked_shl((32-subnet) as u32).unwrap_or(0) - 1);
        Ipv4Addr::from(v.to_be_bytes())
    };
    let mut mask_req = create_req(name);
    mask_req.ifru.addr = mem::transmute(get_sockaddr(mask_addr));
    if c_ffi::siocsifnetmask(fd, &mask_req) < 0 {
        return Err(errno_err("Failed to set tun mask"));
    }
    Ok(())
}

