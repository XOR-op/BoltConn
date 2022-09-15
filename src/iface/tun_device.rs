use crate::iface::SysError;
use crate::packet::ip::IPPkt;
use crate::resource::buf_slab::{PktBufHandle, MAX_PKT_SIZE};
use crate::resource::state::Shared;
use byteorder::{ByteOrder, NetworkEndian};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::os::unix::io::RawFd;
use std::{io, slice};
use tokio::io::AsyncReadExt;

pub type AsyncRawFd = tokio_fd::AsyncFd;

pub struct TunDevice {
    fd: AsyncRawFd,
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
            Ok(TunDevice {
                fd: AsyncRawFd::try_from(RawFd::from(result))?,
                name,
                state: shared,
            })
        } else {
            Err(SysError::Tun(errno::errno()))
        }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Read a full ip packet from tun device.
    pub async fn recv_ip(&mut self) -> io::Result<IPPkt> {
        // https://stackoverflow.com/questions/17138626/read-on-a-non-blocking-tun-tap-file-descriptor-gets-eagain-error
        // We must read full packet in one syscall, otherwise the remaining part will be discarded.
        // And we are guaranteed to read a full packet when fd is ready.
        // todo: macOS 4 bytes AF_INET/AF_INET6 prefix even if IFF_NO_PI set
        let mut handle = self.state.pool.obtain().await;
        let buffer =
            unsafe { slice::from_raw_parts_mut(handle.data.as_ptr() as *mut u8, MAX_PKT_SIZE) };
        tracing::trace!("Got buffer, ready for recv");
        self.fd.read(buffer).await?;
        match buffer[0] >> 4 {
            4 => {
                handle.len = <NetworkEndian as ByteOrder>::read_u16(&buffer[2..4]) as usize;
                Ok(IPPkt::from_v4(handle.clone()))
            }
            6 => {
                handle.len = <NetworkEndian as ByteOrder>::read_u16(&buffer[4..6]) as usize + 40;
                Ok(IPPkt::from_v6(handle.clone()))
            }
            _ => panic!("Packet is not IPv4 or IPv6"),
        }
    }

    // Read raw data from tun device. No parsing is done.
    pub async fn recv_raw(&mut self) -> io::Result<PktBufHandle> {
        let mut handle = self.state.pool.obtain().await;
        let buffer =
            unsafe { slice::from_raw_parts_mut(handle.data.as_ptr() as *mut u8, MAX_PKT_SIZE) };
        handle.len = self.fd.read(&mut buffer[..]).await?;
        Ok(handle.clone())
    }
}
