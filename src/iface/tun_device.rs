use crate::iface::SysError;
use crate::resource::buf_slab::PktBufHandle;
use crate::resource::state::Shared;
use std::borrow::{Borrow, BorrowMut};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::os::unix::io::RawFd;
use std::{io, process};
use byteorder::{ByteOrder, NetworkEndian};
use tokio::io::unix::AsyncFd;
use tokio::io::AsyncReadExt;
use crate::packet::ip::{IPPkt, IPv4Pkt, IPv6Pkt};

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

    pub async fn recv_ip(&mut self) -> io::Result<IPPkt> {
        // todo: macOS 4 bytes AF_INET/AF_INET6 prefix even if IFF_NO_PI set
        let mut handle = self.state.pool.obtain().await;
        let mut buffer = handle.data.write().unwrap();
        tracing::trace!("Got buffer, ready for recv");
        self.fd.read_exact(&mut buffer[..4]).await?;
        match buffer[0] >> 4 {
            4 => {
                handle.len = <NetworkEndian as ByteOrder>::read_u16(&buffer[2..4]) as usize;
                tracing::trace!("Read header");
                self.fd.read_exact(&mut buffer[4..handle.len]).await?;
                tracing::trace!("Read body");
                Ok(IPPkt::V4(IPv4Pkt::new(handle.clone())))
            }
            6 => {
                handle.len = <NetworkEndian as ByteOrder>::read_u16(&buffer[4..6]) as usize + 40;
                self.fd.read_exact(&mut buffer[40..handle.len]).await?;
                Ok(IPPkt::V6(IPv6Pkt::new(handle.clone())))
            }
            _ => panic!("Packet is not IPv4 or IPv6"),
        }
    }

    pub async fn recv_raw(&mut self) -> io::Result<PktBufHandle> {
        let mut handle = self.state.pool.obtain().await;
        let mut buffer = handle.data.write().unwrap();
        handle.len = self.fd.read(&mut buffer[..]).await?;
        Ok(handle.clone())
    }
}
