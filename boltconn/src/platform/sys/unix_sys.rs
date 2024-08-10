use crate::platform::errno_err;
use crate::platform::sys::ffi;
use ipnet::Ipv4Net;
use libc::{c_char, c_int};
use socket2::{Domain, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::{io, mem, ptr};

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub name: String,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

impl UserInfo {
    #[cfg(not(target_os = "windows"))]
    pub fn chown(&self, path: &Path) -> io::Result<()> {
        std::os::unix::fs::chown(path, Some(self.uid), Some(self.gid))?;
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn root() -> UserInfo {
        UserInfo {
            name: "root".to_string(),
            uid: 0,
            gid: 0,
        }
    }
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

pub(super) unsafe fn create_req(name: &str) -> ffi::ifreq {
    let mut req: ffi::ifreq = mem::zeroed();
    ptr::copy_nonoverlapping(
        name.as_ptr() as *const c_char,
        req.ifrn.name.as_mut_ptr(),
        name.len(),
    );
    req
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

pub fn get_iface_address(iface_name: &str) -> io::Result<IpAddr> {
    let ctl_socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
    let mut req = unsafe { create_req(iface_name) };
    req.ifru.addr.sa_family = libc::AF_INET as libc::sa_family_t;
    if unsafe { ffi::siocgifaddr(ctl_socket.as_raw_fd(), &mut req) } < 0 {
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

pub fn set_address(fd: c_int, name: &str, addr: Ipv4Net) -> io::Result<()> {
    unsafe {
        let mut addr_req = create_req(name);
        addr_req.ifru.addr =
            mem::transmute::<libc::sockaddr_in, libc::sockaddr>(get_sockaddr(addr.addr()));
        if ffi::siocsifaddr(fd, &addr_req) < 0 {
            return Err(errno_err("Failed to set tun addr"));
        }
        // only useful for macos; for linux, this is a nop
        crate::platform::set_dest(fd, name, addr.addr())?;

        // set subnet mask
        let mut mask_req = create_req(name);
        mask_req.ifru.addr =
            mem::transmute::<libc::sockaddr_in, libc::sockaddr>(get_sockaddr(addr.netmask()));
        if ffi::siocsifnetmask(fd, &mask_req) < 0 {
            return Err(errno_err("Failed to set tun mask"));
        }
        Ok(())
    }
}
