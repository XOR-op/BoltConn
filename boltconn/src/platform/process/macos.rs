use crate::platform::process::{NetworkType, ProcessInfo};
use libc::c_int;
use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::proc_pid::pidinfo;
use std::ffi::{CString, OsStr, c_void};
use std::io;
use std::io::{ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

const TCP_SYSCTL_NAME: &str = "net.inet.tcp.pcblist_n";
const UDP_SYSCTL_NAME: &str = "net.inet.udp.pcblist_n";

fn get_os_basic_len() -> Result<usize> {
    let os_version_str = CString::new("kern.osrelease").unwrap();
    let mut buf = [0u8; 64];
    let mut len: usize = 64;
    unsafe {
        if libc::sysctlbyname(
            os_version_str.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            &mut len as *mut _,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let original_str = String::from_utf8_lossy(&buf[..len]);
    let ver_str: Vec<_> = original_str.split('.').collect();
    if ver_str.len() == 3 {
        #[allow(clippy::get_first)]
        if let Ok(major) = ver_str.get(0).unwrap().parse::<u8>() {
            return if major >= 22 { Ok(408) } else { Ok(384) };
        }
    }
    Err(io::Error::from(io::ErrorKind::InvalidData))
}

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
    let basic_len = get_os_basic_len()?;
    let (sys_ctl_name, item_size) = match net_type {
        NetworkType::Tcp => (TCP_SYSCTL_NAME, basic_len + 208),
        NetworkType::Udp => (UDP_SYSCTL_NAME, basic_len),
    };
    let sys_ctl_name = CString::new(sys_ctl_name).unwrap();
    let mut len: usize = 0;
    unsafe {
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
    }
    let mut buf = vec![0; len];
    unsafe {
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
        if chunk.len() == item_size {
            let inpcb_offset = 24;
            let socket_offset = inpcb_offset + 104;
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
            let udp_any = net_type == NetworkType::Udp
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
    }
    Err(io::Error::new(
        ErrorKind::NotFound,
        "Cannot find such a process",
    ))
}

// from dalance/procs
// maybe the source is https://gist.github.com/nonowarn/770696
pub fn get_process_info(pid: i32) -> Option<ProcessInfo> {
    let (ppid, path, name, cmdline) = get_process_info_inner(pid)?;
    let p_name = get_process_info_inner(ppid).map(|(_, _, p_name, _)| p_name);
    Some(ProcessInfo {
        pid,
        ppid,
        path,
        name,
        cmdline,
        parent_name: p_name,
    })
}

fn get_process_info_inner(pid: i32) -> Option<(i32, String, String, String)> {
    let mut size = get_arg_max()?;
    let mut proc_args = Vec::with_capacity(size);
    let ptr: *mut u8 = proc_args.as_mut_slice().as_mut_ptr();

    let mut mib: [c_int; 3] = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as c_int];

    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            ptr as *mut c_void,
            &mut size,
            ::std::ptr::null_mut(),
            0,
        ) == -1
        {
            return None;
        }
        let mut n_args: c_int = 0;
        libc::memcpy(
            (&mut n_args) as *mut c_int as *mut c_void,
            ptr as *const c_void,
            ::std::mem::size_of::<c_int>(),
        );
        let mut cp = ptr.add(::std::mem::size_of::<c_int>());
        let mut start = cp;
        if cp < ptr.add(size) {
            // get process name
            while cp < ptr.add(size) && *cp != 0 {
                cp = cp.offset(1);
            }
            let path = get_unchecked_str(cp, start);
            let exe = std::path::Path::new(path.as_str()).to_path_buf();
            let name = exe
                .file_name()
                .unwrap_or_else(|| OsStr::new(""))
                .to_str()
                .unwrap_or("")
                .to_owned();

            // skip trailing zeros
            while cp < ptr.add(size) && *cp == 0 {
                cp = cp.offset(1);
            }

            start = cp;
            let mut c = 0;
            let mut cmd = Vec::new();
            while c < n_args && cp < ptr.add(size) {
                if *cp == 0 {
                    c += 1;
                    cmd.push(get_unchecked_str(cp, start));
                    start = cp.offset(1);
                }
                cp = cp.offset(1);
            }

            let bsd_info: BSDInfo = pidinfo(pid, 0).ok()?;

            Some((bsd_info.pbi_ppid as i32, path, name, cmd.join(" ")))
        } else {
            None
        }
    }
}

fn get_arg_max() -> Option<usize> {
    let mut mib: [c_int; 2] = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut arg_max = 0i32;
    let mut size = ::std::mem::size_of::<c_int>();

    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut arg_max) as *mut i32 as *mut c_void,
            &mut size,
            ::std::ptr::null_mut(),
            0,
        ) == -1
    } {
        return None;
    }

    Some(arg_max as usize)
}

unsafe fn get_unchecked_str(cp: *mut u8, start: *mut u8) -> String {
    let len = cp as usize - start as usize;
    let part = unsafe { Vec::from_raw_parts(start, len, len) };
    let tmp = unsafe { String::from_utf8_unchecked(part.clone()) };
    ::std::mem::forget(part);
    tmp
}
