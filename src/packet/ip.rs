use crate::resource::buf_slab::{PktBufHandle, PktBuffer};
use byteorder::{ByteOrder, NetworkEndian};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::RwLockReadGuard;
use std::{mem, slice};

#[derive(Debug, Clone, Copy)]
pub enum PayloadProtocol {
    TCP,
    UDP,
    ICMP,
    UNKNOWN,
}

pub struct IPPkt {
    handle: PktBufHandle,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub payload_offset: usize,
    pub proto: PayloadProtocol,
}

impl Display for IPPkt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[version={}, src={}, dst={}, len={}, proto={:?}",
            {
                if let IpAddr::V4(_) = self.src_addr {
                    4
                } else {
                    6
                }
            },
            self.src_addr,
            self.dst_addr,
            self.handle.len,
            self.proto,
        )
    }
}

impl IPPkt {
    pub fn from_v4(handle: PktBufHandle) -> Self {
        let data = handle.data.read().unwrap();
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let ihl = data[0] & 0xf;
        let payload_offset = (ihl * 4) as usize;
        let proto = match data[9] {
            0x06 => PayloadProtocol::TCP,
            0x11 => PayloadProtocol::UDP,
            0x01 => PayloadProtocol::ICMP,
            _ => PayloadProtocol::UNKNOWN,
        };
        drop(data);
        Self {
            handle,
            src_addr: IpAddr::V4(src),
            dst_addr: IpAddr::V4(dst),
            payload_offset,
            proto,
        }
    }

    pub fn from_v6(handle: PktBufHandle) -> Self {
        let data = handle.data.read().unwrap();
        let src_addr = unsafe { slice::from_raw_parts(data[8..16].as_ptr() as *const u16, 8) };
        let src = Ipv6Addr::from(rename(src_addr));
        let dst_addr = unsafe { slice::from_raw_parts(data[16..24].as_ptr() as *const u16, 8) };
        let dst = Ipv6Addr::from(rename(dst_addr));
        let payload_offset = 40;
        let proto = match data[6] {
            0x06 => PayloadProtocol::TCP,
            0x11 => PayloadProtocol::UDP,
            0x01 => PayloadProtocol::ICMP,
            _ => PayloadProtocol::UNKNOWN,
        };
        drop(data);
        Self {
            handle,
            src_addr: IpAddr::V6(src),
            dst_addr: IpAddr::V6(dst),
            payload_offset,
            proto,
        }
    }
}

fn rename(d: &[u16]) -> [u16; 8] {
    d.try_into().unwrap()
}
