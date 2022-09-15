use crate::iface::{platform, SysError};
use crate::packet::ip::IPPkt;
use crate::resource::buf_slab::{PktBufHandle, MAX_PKT_SIZE};
use crate::resource::state::Shared;
use byteorder::{ByteOrder, NetworkEndian};
use std::ffi::CStr;
use std::net::IpAddr;
use std::os::raw::c_char;
use std::os::unix::io::{AsRawFd, RawFd};
use std::{io, slice};
use std::io::ErrorKind;
use tokio::io::AsyncReadExt;

pub type AsyncRawFd = tokio_fd::AsyncFd;

pub struct TunDevice {
    fd: AsyncRawFd,
    name: String,
    // (addr, mask)
    addr: Option<(IpAddr, u8)>,
    state: Shared,
}

impl TunDevice {
    pub fn open(shared: Shared) -> Result<Self, SysError> {
        let mut name_buffer: Vec<c_char> = Vec::new();
        name_buffer.resize(36, 0);
        let name_ptr = name_buffer.as_ptr() as *mut u8;

        let (fd, name) = unsafe { platform::open_tun()? };
        Ok(TunDevice {
            fd: AsyncRawFd::try_from(RawFd::from(fd))?,
            name,
            addr: None,
            state: shared,
        })
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Read a full ip packet from tun device.
    pub async fn recv_ip(&mut self) -> io::Result<IPPkt> {
        // https://stackoverflow.com/questions/17138626/read-on-a-non-blocking-tun-tap-file-descriptor-gets-eagain-error
        // We must read full packet in one syscall, otherwise the remaining part will be discarded.
        // And we are guaranteed to read a full packet when fd is ready.
        let mut handle = self.state.pool.obtain().await;
        let raw_buffer =
            unsafe { slice::from_raw_parts_mut(handle.data.as_ptr() as *mut u8, MAX_PKT_SIZE) };
        tracing::trace!("Got buffer, ready for recv");
        self.fd.read(raw_buffer).await?;
        // macOS 4 bytes AF_INET/AF_INET6 prefix because of no IFF_NO_PI flag
        #[cfg(target_os = "macos")]
            let start_offset = 4;
        #[cfg(target_os = "linux")]
            let start_offset = 0;
        let buffer = &raw_buffer[start_offset..];
        match buffer[0] >> 4 {
            4 => {
                handle.len = <NetworkEndian as ByteOrder>::read_u16(&buffer[2..4]) as usize;
                Ok(IPPkt::from_v4(handle.clone(), start_offset))
            }
            6 => {
                handle.len = <NetworkEndian as ByteOrder>::read_u16(&buffer[4..6]) as usize + 40;
                Ok(IPPkt::from_v6(handle.clone(), start_offset))
            }
            _ => panic!("Packet is not IPv4 or IPv6"),
        }
    }

    /// Read raw data from tun device. No parsing is done.
    pub async fn recv_raw(&mut self) -> io::Result<PktBufHandle> {
        let mut handle = self.state.pool.obtain().await;
        let buffer =
            unsafe { slice::from_raw_parts_mut(handle.data.as_ptr() as *mut u8, MAX_PKT_SIZE) };
        handle.len = self.fd.read(&mut buffer[..]).await?;
        Ok(handle.clone())
    }

    pub fn set_network_address(&mut self, addr: IpAddr, subnet: u8) -> io::Result<()> {
        self.addr = Some((addr, subnet));
        unsafe { platform::set_address(self.fd.as_raw_fd(), self.get_name(), addr, subnet) }
    }

    pub fn up(&self) -> io::Result<()> {
        if self.addr.is_none() {
            return Err(io::Error::new(ErrorKind::AddrNotAvailable, "No available address to up iface"));
        }
        unsafe { platform::interface_up(self.fd.as_raw_fd(), self.get_name()) }
    }
}
