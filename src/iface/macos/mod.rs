use super::errno_err;
use crate::iface::create_req;
use crate::iface::macos::c_ffi::*;
use ipnet::IpNet;
use libc::{c_char, c_int, c_void, sockaddr, socklen_t, SOCK_DGRAM, sockaddr_in};
use std::ffi::CStr;
use std::os::unix::io::RawFd;
use std::{io, mem};

pub mod c_ffi;

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

pub unsafe fn add_route_entry(subnet: IpNet, name: &str) -> io::Result<()> {
    // todo: do not use external commands
    super::run_command(
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

pub unsafe fn create_v4_raw_socket(dst_iface_name: &str) -> io::Result<(c_int, sockaddr_in)> {
    let fd = {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        fd
    };
    let c_name = std::ffi::CString::new(dst_iface_name).unwrap();
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
    let mut req = create_req(dst_iface_name);
    req.ifru.addr.sa_family = libc::AF_INET as libc::sa_family_t;
    if siocgifaddr(fd, &mut req) < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fd, mem::transmute(req.ifru.addr)))
}
