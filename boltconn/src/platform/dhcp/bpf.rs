//! macOS DHCP datalink channel. Keep pnet's BPF setup, but avoid its fixed-size fd_set.

use pnet_datalink::{Channel, Config, DataLinkReceiver, DataLinkSender, NetworkInterface};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::time::Duration;

const ETHERNET_HEADER_SIZE: usize = 14;
const NULL_HEADER_SIZE: usize = 4;

// Darwin's BPF header has an 8-byte timeval32, two u32 lengths, and a u16
// header length. Its on-device prefix is 18 bytes; sizeof(bpf_hdr) includes
// trailing C padding and must not be used as the minimum bh_hdrlen.
const BPF_HEADER_SIZE: usize = 18;

pub(super) fn channel(interface: &NetworkInterface, config: Config) -> io::Result<Channel> {
    let name = CString::new(interface.name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
    let mut iface: libc::ifreq = unsafe { std::mem::zeroed() };
    if name.as_bytes_with_nul().len() > iface.ifr_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    for (dst, src) in iface.ifr_name.iter_mut().zip(name.as_bytes_with_nul()) {
        *dst = *src as libc::c_char;
    }

    let mut device = Err(io::Error::new(io::ErrorKind::NotFound, "no BPF device"));
    for index in 0..config.bpf_fd_attempts {
        device = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(format!("/dev/bpf{index}"));
        if device.is_ok() {
            break;
        }
    }
    // File owns the descriptor so every setup failure closes it.
    let device = Arc::new(device?);
    let fd = device.as_raw_fd();
    let mut buflen = libc::c_uint::try_from(config.read_buffer_size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "BPF buffer too large"))?;
    // BPF requires the buffer size to be set before binding the interface.
    ioctl(fd, libc::BIOCSBLEN, &mut buflen)?;
    ioctl(fd, libc::BIOCSETIF, &mut iface)?;
    ioctl(fd, libc::BIOCIMMEDIATE, &mut 1u32)?;
    let mut dlt = 0u32;
    ioctl(fd, libc::BIOCGDLT, &mut dlt)?;
    let loopback = dlt == 0; // DLT_NULL
    if !loopback {
        // Preserve the source MAC supplied by create_dhcp_discover.
        ioctl(fd, libc::BIOCSHDRCMPLT, &mut 1u32)?;
    }

    Ok(Channel::Ethernet(
        Box::new(Sender {
            device: device.clone(),
            write_buffer: vec![0; config.write_buffer_size],
            loopback,
        }),
        Box::new(Receiver {
            device,
            read_buffer: vec![0; buflen as usize],
            filled: 0,
            cursor: 0,
            timeout: config.read_timeout,
            loopback,
            loopback_packet: Vec::new(),
        }),
    ))
}

fn ioctl<T>(fd: RawFd, request: libc::c_ulong, value: &mut T) -> io::Result<()> {
    // Each caller supplies the type required by the corresponding BPF request.
    if unsafe { libc::ioctl(fd, request, value as *mut T) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wait_readable(fd: RawFd, timeout: Option<Duration>) -> io::Result<()> {
    // Round up so sub-millisecond durations do not turn into immediate timeouts.
    let timeout_ms = timeout.map_or(-1, |value| {
        value.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32
    });
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // poll indexes an array of descriptors, never a bitmap indexed by the fd value.
    match unsafe { libc::poll(&mut descriptor, 1, timeout_ms) } {
        -1 => Err(io::Error::last_os_error()),
        0 => Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")),
        _ if descriptor.revents & libc::POLLNVAL != 0 => {
            Err(io::Error::from_raw_os_error(libc::EBADF))
        }
        _ if descriptor.revents & libc::POLLERR != 0 => Err(io::Error::other("BPF poll error")),
        _ if descriptor.revents & libc::POLLIN != 0 => Ok(()),
        _ => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "BPF closed")),
    }
}

struct Sender {
    device: Arc<File>,
    write_buffer: Vec<u8>,
    loopback: bool,
}

fn send_packet(mut device: &File, packet: &[u8], loopback: bool) -> io::Result<()> {
    let packet = if loopback {
        packet
            .get(ETHERNET_HEADER_SIZE..)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "short Ethernet packet"))?
    } else {
        packet
    };
    // Darwin's BPF select(FWRITE) always returns ready. poll(POLLOUT) instead
    // fails because bpfkqfilter only supports EVFILT_READ. Write directly, as
    // pnet does after select; no write timeout or readiness wait is needed.
    // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.c
    let written = device.write(packet)?;
    if written != packet.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "short BPF write"));
    }
    Ok(())
}

impl DataLinkSender for Sender {
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        let len = num_packets.checked_mul(packet_size)?;
        if len >= self.write_buffer.len() || packet_size == 0 {
            return None;
        }
        for packet in self.write_buffer[..len].chunks_mut(packet_size) {
            func(packet);
            if let Err(err) = send_packet(&self.device, packet, self.loopback) {
                return Some(Err(err));
            }
        }
        Some(Ok(()))
    }

    fn send_to(&mut self, packet: &[u8], _dst: Option<NetworkInterface>) -> Option<io::Result<()>> {
        Some(send_packet(&self.device, packet, self.loopback))
    }
}

struct Receiver {
    device: Arc<File>,
    read_buffer: Vec<u8>,
    filled: usize,
    cursor: usize,
    timeout: Option<Duration>,
    loopback: bool,
    loopback_packet: Vec<u8>,
}

// BPF reads contain multiple records, each rounded up to a 4-byte boundary.
// Return the packet bounds and the start of the following record.
fn packet_bounds(buffer: &[u8], cursor: usize) -> io::Result<(usize, usize, usize)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid BPF record");
    let record = buffer.get(cursor..).ok_or_else(invalid)?;
    if record.len() < BPF_HEADER_SIZE {
        return Err(invalid());
    }
    // Read native-endian fields without requiring alignment or C struct padding.
    let caplen = u32::from_ne_bytes(record[8..12].try_into().unwrap()) as usize;
    let hdrlen = u16::from_ne_bytes(record[16..18].try_into().unwrap()) as usize;
    if hdrlen < BPF_HEADER_SIZE || hdrlen > record.len() || caplen > record.len() - hdrlen {
        return Err(invalid());
    }
    let start = cursor + hdrlen;
    let end = start + caplen;
    Ok((start, end, end.next_multiple_of(4)))
}

impl DataLinkReceiver for Receiver {
    fn next(&mut self) -> io::Result<&[u8]> {
        if self.cursor >= self.filled {
            wait_readable(self.device.as_raw_fd(), self.timeout)?;
            self.filled = (&*self.device).read(&mut self.read_buffer)?;
            self.cursor = 0;
            if self.filled == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "BPF closed"));
            }
        }
        let (start, end, next) = packet_bounds(&self.read_buffer[..self.filled], self.cursor)?;
        self.cursor = next;
        let packet = &self.read_buffer[start..end];
        if self.loopback {
            let payload = packet.get(NULL_HEADER_SIZE..).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "short BPF loopback packet")
            })?;
            self.loopback_packet.clear();
            self.loopback_packet.resize(ETHERNET_HEADER_SIZE, 0);
            self.loopback_packet.extend_from_slice(payload);
            Ok(&self.loopback_packet)
        } else {
            Ok(packet)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn receives_with_fd_above_fd_setsize() {
        // Some macOS shells start with a soft limit below FD_SETSIZE. Raise
        // only this test process's soft limit so the regression can run there.
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) },
            0
        );
        let mut limit = unsafe { limit.assume_init() };
        if limit.rlim_cur < 1345 {
            limit.rlim_cur = 1345;
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        }
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let fd = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 1344) };
        assert!(fd >= 1344, "{}", io::Error::last_os_error());
        let device = Arc::new(unsafe { File::from_raw_fd(fd) });
        assert_eq!(
            wait_readable(fd, Some(Duration::from_millis(1)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        let mut bytes = record(b"first frame");
        bytes.extend(record(b"second frame"));
        writer.write_all(&bytes).unwrap();
        let mut receiver = Receiver {
            device: device.clone(),
            read_buffer: vec![0; 4096],
            filled: 0,
            cursor: 0,
            timeout: Some(Duration::from_millis(300)),
            loopback: false,
            loopback_packet: Vec::new(),
        };
        assert_eq!(receiver.next().unwrap(), b"first frame");
        assert_eq!(receiver.next().unwrap(), b"second frame");
        let mut sender = Sender {
            device,
            write_buffer: vec![0; 4096],
            loopback: false,
        };
        sender.send_to(b"discover", None).unwrap().unwrap();
        let mut packet = [0; 8];
        writer.read_exact(&mut packet).unwrap();
        assert_eq!(&packet, b"discover");
    }

    fn record(packet: &[u8]) -> Vec<u8> {
        // Real macOS Ethernet captures use bh_hdrlen=18, without C tail padding.
        let mut bytes = vec![0; 18];
        bytes[8..12].copy_from_slice(&(packet.len() as u32).to_ne_bytes());
        bytes[12..16].copy_from_slice(&(packet.len() as u32).to_ne_bytes());
        bytes[16..18].copy_from_slice(&18u16.to_ne_bytes());
        bytes.extend_from_slice(packet);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes
    }

    #[test]
    fn rejects_truncated_or_invalid_records() {
        assert!(packet_bounds(&[0; 17], 0).is_err());
        let mut bytes = record(b"frame");
        assert!(packet_bounds(&bytes[..22], 0).is_err());
        bytes[16..18].copy_from_slice(&1u16.to_ne_bytes());
        assert!(packet_bounds(&bytes, 0).is_err());
        bytes[16..18].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert!(packet_bounds(&bytes, 0).is_err());
    }

    #[test]
    fn accepts_header_without_c_tail_padding() {
        let bytes = record(b"frame");
        // Last record need not include alignment padding in the read result.
        assert_eq!(packet_bounds(&bytes[..23], 0).unwrap(), (18, 23, 24));
        assert_eq!(packet_bounds(&record(b"")[..18], 0).unwrap(), (18, 18, 20));
        let mut padded = vec![0; 22];
        padded[16..18].copy_from_slice(&22u16.to_ne_bytes());
        assert_eq!(packet_bounds(&padded, 0).unwrap(), (22, 22, 24));
    }

    #[test]
    fn reports_invalid_descriptor() {
        assert_eq!(
            wait_readable(i32::MAX, Some(Duration::ZERO))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
    }
}
