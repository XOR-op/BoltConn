use crate::resource::buf_slab::PktBufHandle;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice;

#[derive(Debug, Clone, Copy)]
pub enum PayloadProtocol {
    TCP,
    UDP,
    ICMP,
    ICMPv6,
    UNKNOWN,
}

pub struct IPPkt {
    handle: PktBufHandle,
    // 0 on linux and 4 on macOS: utun in macOS does not support IFF_NO_PI
    pkt_start_offset: usize,
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
    pub fn from_v4(handle: PktBufHandle, start_offset: usize) -> Self {
        let data = &handle.data[start_offset..];
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let ihl = data[0] & 0xf;
        let payload_offset = (ihl * 4) as usize;
        let proto = match data[9] {
            0x06 => PayloadProtocol::TCP,
            0x11 => PayloadProtocol::UDP,
            0x01 => PayloadProtocol::ICMP,
            0x3a => PayloadProtocol::ICMPv6,
            _ => PayloadProtocol::UNKNOWN,
        };
        Self {
            handle,
            pkt_start_offset: start_offset,
            src_addr: IpAddr::V4(src),
            dst_addr: IpAddr::V4(dst),
            payload_offset,
            proto,
        }
    }

    pub fn from_v6(handle: PktBufHandle, start_offset: usize) -> Self {
        let data = &handle.data[start_offset..];
        let src = Ipv6Addr::from(*rename(&data[8..24]));
        let dst = Ipv6Addr::from(*rename(&data[24..40]));
        let payload_offset = 40;
        let proto = match data[6] {
            0x06 => PayloadProtocol::TCP,
            0x11 => PayloadProtocol::UDP,
            0x01 => PayloadProtocol::ICMP,
            0x3a => PayloadProtocol::ICMPv6,
            _ => PayloadProtocol::UNKNOWN,
        };
        Self {
            handle,
            pkt_start_offset: start_offset,
            src_addr: IpAddr::V6(src),
            dst_addr: IpAddr::V6(dst),
            payload_offset,
            proto,
        }
    }
}

fn rename(d: &[u8]) -> &[u8; 16] {
   d.try_into().expect("slice with incorrect len")
}
