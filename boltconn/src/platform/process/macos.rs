use crate::platform::process::{NetworkType, ProcessInfo};
use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::io::{ErrorKind, Result};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{io, mem};

const TCP_SYSCTL_NAME: &str = "net.inet.tcp.pcblist_n";
const UDP_SYSCTL_NAME: &str = "net.inet.udp.pcblist_n";

pub fn get_pid(addr: SocketAddr, net_type: NetworkType) -> Result<i32> {
    // http://newosxbook.com/bonus/vol1ch16.html search for 'net.inet.tcp.pcblist_n'
    /*
    from bsd/netinet/in_pcblist.c:

    size_t item_size = ROUNDUP64(sizeof (struct xinpcb_n)) +
        ROUNDUP64(sizeof (struct xsocket_n)) +
        2 * ROUNDUP64(sizeof (struct xsockbuf_n)) +
        ROUNDUP64(sizeof (struct xsockstat_n));

    if (proto == IPPROTO_TCP)
        item_size += ROUNDUP64(sizeof (struct xtcpcb_n));
     */
    let (sys_ctl_name, item_size) = match net_type {
        NetworkType::TCP => (TCP_SYSCTL_NAME, 592),
        NetworkType::UDP => (UDP_SYSCTL_NAME, 384),
    };
    let sys_ctl_name = CString::new(sys_ctl_name).unwrap();
    let mut buf = Vec::<u8>::new();
    unsafe {
        let mut len: usize = 0;
        // in order to get length
        if libc::sysctlbyname(
            sys_ctl_name.as_ptr(),
            std::ptr::null_mut() as *mut _,
            &mut len as *mut _,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        buf.resize(len, 0);
        // real read
        if libc::sysctlbyname(
            sys_ctl_name.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            &mut len as *mut _,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    for chunk in buf.as_slice().chunks(item_size) {
        let inpcb_offset = 24;
        let socket_offset = 128;
        let pcb = &chunk[inpcb_offset..socket_offset];
        if addr.port() != u16::from_be_bytes(*arrayref::array_ref![pcb, 18, 2]) {
            continue;
        }
        // inp_ip_p
        let ip_version = pcb[44];
        let ipv4_equal = addr.is_ipv4()
            && ip_version & 0x1 != 0
            && Ipv4Addr::from(*arrayref::array_ref![pcb, 76, 4]) == addr.ip();
        let ipv6_equal = addr.is_ipv6()
            && ip_version & 0x2 != 0
            && Ipv6Addr::from(*arrayref::array_ref![pcb, 64, 16]) == addr.ip();
        let udp_any = net_type == NetworkType::UDP
            && addr.is_ipv4()
            && addr.ip() == Ipv4Addr::new(0, 0, 0, 0);
        if ipv4_equal || ipv6_equal || udp_any {
            // hit
            let socket = &chunk[socket_offset..];
            return Ok(i32::from_ne_bytes(*arrayref::array_ref![socket, 68, 4]));
        } else {
            continue;
        }
    }
    Err(io::Error::new(
        ErrorKind::NotFound,
        "Cannot find such a process",
    ))
}

pub fn get_process_info(pid: i32) -> Option<ProcessInfo> {
    let mut bsd_info: libc::proc_bsdinfo =
        unsafe { MaybeUninit::<libc::proc_bsdinfo>::zeroed().assume_init() };
    if unsafe {
        libc::proc_pidinfo(
            pid as c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut bsd_info as *mut _ as *mut _,
            mem::size_of_val(&bsd_info) as c_int,
        )
    } != mem::size_of_val(&bsd_info) as c_int
    {
        // partial read
        return None;
    }
    let mut vpath_info: libc::proc_vnodepathinfo =
        unsafe { MaybeUninit::<libc::proc_vnodepathinfo>::zeroed().assume_init() };
    if unsafe {
        libc::proc_pidinfo(
            pid as c_int,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            &mut vpath_info as *mut _ as *mut _,
            mem::size_of_val(&vpath_info) as c_int,
        )
    } != mem::size_of_val(&vpath_info) as c_int
    {
        return None;
    }
    Some(ProcessInfo {
        pid,
        path: unsafe { CStr::from_ptr(&vpath_info.pvi_cdir.vip_path as *const _ as *const c_char) }
            .to_string_lossy()
            .into_owned(),
        name: unsafe { CStr::from_ptr(&bsd_info.pbi_name as *const c_char) }
            .to_string_lossy()
            .into_owned(),
    })
}
