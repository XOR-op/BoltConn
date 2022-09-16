use crate::iface::route::setup_ipv4_routing_table;
use crate::iface::{errno_err, interface_up, platform, set_address};
use crate::packet::ip::IPPkt;
use crate::resource::buf_slab::{PktBufHandle, MAX_PKT_SIZE};
use crate::resource::state::Shared;
use byteorder::{ByteOrder, NetworkEndian};
use ipnet::Ipv4Net;
use std::io::ErrorKind;
use std::os::raw::c_char;
use std::os::unix::io::RawFd;
use std::{io, slice};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub type AsyncRawFd = tokio_fd::AsyncFd;

pub struct TunDevice {
    fd: AsyncRawFd,
    ctl_fd: RawFd,
    name: String,
    // (addr, mask)
    addr: Option<Ipv4Net>,
    state: Shared,
}

impl TunDevice {
    pub fn open(shared: Shared) -> io::Result<TunDevice> {
        let mut name_buffer: Vec<c_char> = Vec::new();
        name_buffer.resize(36, 0);

        let (fd, name) = unsafe { platform::open_tun()? };
        let ctl_fd = {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if fd < 0 {
                return Err(errno_err("Unable to open control fd").into());
            }
            fd
        };
        Ok(TunDevice {
            fd: AsyncRawFd::try_from(RawFd::from(fd))?,
            ctl_fd,
            name,
            addr: None,
            state: shared,
        })
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Read a full ip packet from tun device.
    pub async fn read_ip(&mut self) -> io::Result<IPPkt> {
        // https://stackoverflow.com/questions/17138626/read-on-a-non-blocking-tun-tap-file-descriptor-gets-eagain-error
        // We must read full packet in one syscall, otherwise the remaining part will be discarded.
        // And we are guaranteed to read a full packet when fd is ready.
        let mut handle = self.state.pool.obtain().await;
        let raw_buffer =
            unsafe { slice::from_raw_parts_mut(handle.data.as_ptr() as *mut u8, MAX_PKT_SIZE) };
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
    pub async fn read_raw(&mut self) -> io::Result<PktBufHandle> {
        let mut handle = self.state.pool.obtain().await;
        let buffer =
            unsafe { slice::from_raw_parts_mut(handle.data.as_ptr() as *mut u8, MAX_PKT_SIZE) };
        handle.len = self.fd.read(&mut buffer[..]).await?;
        Ok(handle.clone())
    }

    pub async fn write_ip(&mut self, ip_pkt: IPPkt) -> io::Result<()> {
        if self.fd.write(ip_pkt.raw_data()).await? != ip_pkt.raw_data().len() {
            Err(io::Error::new(ErrorKind::Other, "Write partial packet"))
        } else {
            Ok(())
        }
    }

    /// Due to API compatibility of OS, we can only set AF_INET addresses.
    /// See https://man7.org/linux/man-pages/man7/netdevice.7.html
    pub fn set_network_address(&mut self, addr: Ipv4Net) -> io::Result<()> {
        self.addr = Some(addr);
        unsafe { set_address(self.ctl_fd, self.get_name(), addr) }
    }

    pub fn up(&self) -> io::Result<()> {
        if self.addr.is_none() {
            return Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                "No available address to up iface",
            ));
        }
        unsafe { interface_up(self.ctl_fd, self.get_name())? };
        setup_ipv4_routing_table(self.get_name())
    }
}
