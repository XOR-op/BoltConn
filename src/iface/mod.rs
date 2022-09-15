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

#[derive(Debug, Error)]
pub enum SysError {
    IoError(#[from] io::Error),
    ExitStatus(std::process::ExitStatus),
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

unsafe fn create_req(name: &str) -> platform::ifreq {
    let mut req: platform::ifreq = mem::zeroed();
    ptr::copy_nonoverlapping(
        name.as_ptr() as *const c_char,
        req.ifrn.name.as_mut_ptr(),
        name.len(),
    );
    req
}

pub unsafe fn interface_up(fd: c_int, name: &str) -> io::Result<()> {
    let mut req = create_req(name);
    if platform::siocgifflags(fd, &mut req) < 0 {
        return Err(io::Error::last_os_error().into());
    }
    req.ifru.flags |= platform::IFF_UP | platform::IFF_RUNNING;
    if platform::siocsifflags(fd, &req) < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

unsafe fn get_sockaddr(addr: IpAddr) -> io::Result<libc::sockaddr> {
    match addr {
        IpAddr::V4(v4) => {
            let mut addr = mem::zeroed::<libc::sockaddr_in>();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = 0;
            addr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.octets())
            };
            Ok(mem::transmute(addr))
        }
        IpAddr::V6(v6) => {
            Err(io::Error::new(ErrorKind::AddrNotAvailable, "No support for IPv6 yet"))
        }
    }
}

pub unsafe fn set_address(fd: c_int, name: &str, addr: IpAddr, subnet: u8) -> io::Result<()> {
    let mut addr_req = create_req(name);
    addr_req.ifru.addr = get_sockaddr(addr)?;
    addr_req.ifru.dstaddr = addr_req.ifru.addr;
    if platform::siocsifaddr(fd, &addr_req) < 0 {
        return Err(io::Error::last_os_error());
    }
    let mask_addr = match addr {
        IpAddr::V4(_) => {
            assert!(subnet <= 31);
            let v = (u32::MAX) ^ (1u32.checked_shl(subnet as u32).unwrap_or(0) - 1);
            IpAddr::V4(Ipv4Addr::from(v.to_ne_bytes()))
        }
        IpAddr::V6(_) => {
            assert!(subnet <= 127);
            let v = (u128::MAX) ^ (1u128.checked_shl(subnet as u32).unwrap_or(0) - 1);
            IpAddr::V6(Ipv6Addr::from(v.to_ne_bytes()))
        }
    };
    addr_req.ifru.addr = get_sockaddr(mask_addr)?;
    if platform::siocsifnetmask(fd, &addr_req) < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

