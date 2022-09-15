use c_ffi::*;
use libc::{c_char, c_int, c_void, sockaddr, socklen_t, O_RDWR, SOCK_DGRAM};
use std::ffi::CStr;
use std::{io, mem};
use std::net::IpAddr;

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

// unsafe fn create_req(name: &str) -> ifreq {
//     let mut req: ifreq = mem::zeroed();
//     ptr::copy_nonoverlapping(
//         name.as_ptr() as *const c_char,
//         req.ifrn.name.as_mut_ptr(),
//         name.len(),
//     );
//     req
// }
//
// pub unsafe fn interface_up(fd: c_int, name: &str) -> io::Result<()> {
//     let mut req = create_req(name);
//     if siocgifflags(fd, &mut req) < 0 {
//         return Err(io::Error::last_os_error().into());
//     }
//     req.ifru.flags |= IFF_UP | IFF_RUNNING;
//     if siocsifflags(fd, &req) < 0 {
//         return Err(io::Error::last_os_error().into());
//     }
//     Ok(())
// }
//
// unsafe fn get_sockaddr(addr: IpAddr) -> io::Result<sockaddr> {
//     mem::transmute(match addr {
//         IpAddr::V4(v4) => {
//             let mut addr = mem::zeroed::<sockaddr_in>();
//             addr.sin_family = AF_INET as sa_family_t;
//             addr.sin_port = 0;
//             addr.sin_addr = in_addr {
//                 s_addr: u32::from_ne_bytes(v4.octets())
//             };
//             addr
//         }
//         IpAddr::V6(v6) => {
//             return Err(io::Error::new(ErrorKind::AddrNotAvailable, "No support for IPv6 yet"));
//         }
//     })
// }
//
// pub unsafe fn set_address(fd: c_int, name: &str, addr: IpAddr, subnet: u8) -> io::Result<()> {
//     let mut addr_req = create_req(name);
//     addr_req.ifru.addr = get_sockaddr(addr)?;
//     if siocsifaddr(fd, &addr_req) < 0 {
//         return Err(io::Error::last_os_error());
//     }
//     let mask_addr = IpAddr(match addr {
//         IpAddr::V4(_) => {
//             assert!(subnet <= 31);
//             let v = (-1) ^ (1u32.checked_shl(subnet as u32).unwrap_or(0) - 1);
//             IpAddr::V4(Ipv4Addr::from(v.to_ne_bytes()))
//         }
//         IpAddr::V6(_) => {
//             assert!(subnet <= 127);
//             let v = (-1) ^ (1u128.checked_shl(subnet as u32).unwrap_or(0) - 1);
//             IpAddr::V6(Ipv6Addr::from(v.to_ne_bytes()))
//         }
//     });
//     addr_req.ifru.addr = get_sockaddr(mask_addr)?;
//     if siocsifnetmask(fd, &addr_req) < 0 {
//         return Err(io::Error::last_os_error());
//     }
//     Ok(())
// }
