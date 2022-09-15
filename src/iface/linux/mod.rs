use std::{io, mem};
use std::ffi::CStr;
use libc::{c_char, c_void, O_RDWR, SOCK_DGRAM, sockaddr, socklen_t};
use c_ffi::*;

mod c_ffi;

pub unsafe fn open_tun() -> io::Result<(i32, String)> {
    let mut req: ifreq = mem::zeroed();
    req.ifru.flags = IFF_TUN | IFF_NO_PI;
    let fd = {
        let fd = libc::open(b"/dev/net/tun\0".as_ptr() as *const _, O_RDWR);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        fd
    };
    if tunsetiff(fd, &mut req as *mut _ as *mut _) < 0 {
        libc::close(fd);
        return Err(io::Error::last_os_error());
    }
    Ok((fd, CStr::from_ptr(req.ifrn.name.as_ptr()).to_string_lossy().into_owned()))
}