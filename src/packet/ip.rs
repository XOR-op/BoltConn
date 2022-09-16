use crate::resource::buf_slab::PktBufHandle;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{IpRepr, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct IPPkt {
    handle: PktBufHandle,
    // 0 on linux and 4 on macOS: utun in macOS does not support IFF_NO_PI
    pkt_start_offset: usize,
    pub repr: IpRepr,
}

impl Display for IPPkt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (version, src, dst, len, proto) = match self.repr {
            IpRepr::Ipv4(expr) => (
                4,
                IpAddr::V4(expr.src_addr.into()),
                IpAddr::V4(expr.dst_addr.into()),
                expr.payload_len,
                expr.protocol,
            ),
            IpRepr::Ipv6(expr) => (
                6,
                IpAddr::V6(expr.src_addr.into()),
                IpAddr::V6(expr.dst_addr.into()),
                expr.payload_len,
                expr.next_header,
            ),
            _ => unreachable!(),
        };
        write!(
            f,
            "[version={}, src={}, dst={}, len={}, proto={:?}]",
            version, src, dst, len, proto
        )
    }
}

impl IPPkt {
    pub fn from_v4(handle: PktBufHandle, start_offset: usize) -> Self {
        let data = &handle.data[start_offset..];
        let pkt = Ipv4Packet::new_unchecked(data);
        let expr = Ipv4Repr::parse(&pkt, &ChecksumCapabilities::default()).unwrap();
        Self {
            handle,
            pkt_start_offset: start_offset,
            repr: IpRepr::Ipv4(expr),
        }
    }

    pub fn from_v6(handle: PktBufHandle, start_offset: usize) -> Self {
        let data = &handle.data[start_offset..];
        let pkt = Ipv6Packet::new_unchecked(data);
        let expr = Ipv6Repr::parse(&pkt).unwrap();
        Self {
            handle,
            pkt_start_offset: start_offset,
            repr: IpRepr::Ipv6(expr),
        }
    }

    pub fn raw_data(&self) -> &[u8] {
        &self.handle.data[..self.handle.len]
    }

    pub fn packet_data(&self) -> &[u8] {
        &self.handle.data[self.pkt_start_offset..self.handle.len]
    }

    pub fn packet_payload(&self) -> &[u8] {
        &self.handle.data[self.handle.len - self.repr.payload_len()..self.handle.len]
    }
}

fn rename(d: &[u8]) -> &[u8; 16] {
    d.try_into().expect("slice with incorrect len")
}
