use std::borrow::Borrow;
use crate::packet::buf_pool::PktBufHandle;
use crate::packet::state::Shared;
use crate::iface::SysError;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::os::unix::io::RawFd;
use tokio::io::unix::AsyncFd;
use tokio::net::

pub struct TunDevice {
    fd: AsyncFd<RawFd>,
    name: String,
    state: Shared,
}

extern "C" {
    fn ffi_open_tun(name: *mut u8) -> i32;
}

impl TunDevice {
    pub fn open(shared: Shared) -> Result<Self, SysError> {
        let mut name_buffer: Vec<c_char> = Vec::new();
        name_buffer.resize(36, 0);
        let name_ptr = name_buffer.as_ptr() as *mut u8;

        let result = unsafe { ffi_open_tun(name_ptr) };
        if result >= 0 {
            let name = unsafe { CStr::from_ptr(name_ptr as *const c_char) }
                .to_string_lossy()
                .into_owned();
            Ok(TunDevice { fd: AsyncFd::new(RawFd(fd)).unwrap(), name, state: shared })
        } else {
            Err(SysError::Tun(errno::errno()))
        }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub async fn receive(&mut self) -> PktBufHandle {
        let handle = self.state.pool.obtain().await;
        loop {}
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        // todo: unset route table
    }
}
