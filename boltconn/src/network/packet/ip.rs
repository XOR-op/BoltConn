use crate::common::buf_pool::PktBufHandle;
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

pub struct IPPktContent {
    pub handle: PktBufHandle,
    // 0 on linux and 4 on macOS: utun in macOS does not support IFF_NO_PI
    pub pkt_start_offset: usize,
}

pub enum IPPkt {
    V4(IPPktContent),
    V6(IPPktContent),
}

impl Display for IPPkt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (version, src, dst, len, proto) = match self {
            Self::V4(_) => {
                let d = Ipv4Packet::new_unchecked(self.packet_data());
                (
                    4,
                    IpAddr::V4(d.src_addr().into()),
                    IpAddr::V4(d.dst_addr().into()),
                    d.payload().len(),
                    d.next_header(),
                )
            }
            Self::V6(_) => {
                let d = Ipv6Packet::new_unchecked(self.packet_data());
                (
                    6,
                    IpAddr::V6(d.src_addr().into()),
                    IpAddr::V6(d.dst_addr().into()),
                    d.payload().len(),
                    d.next_header(),
                )
            }
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
        Self::V4(IPPktContent {
            handle,
            pkt_start_offset: start_offset,
        })
    }

    pub fn from_v6(handle: PktBufHandle, start_offset: usize) -> Self {
        Self::V6(IPPktContent {
            handle,
            pkt_start_offset: start_offset,
        })
    }

    pub(crate) fn set_len(&mut self, len: u16) {
        match self {
            IPPkt::V4(_) => {
                let mut pkt = Ipv4Packet::new_unchecked(self.packet_data_mut());
                pkt.set_total_len(len);
            }
            IPPkt::V6(_) => {
                let mut pkt = Ipv6Packet::new_unchecked(self.packet_data_mut());
                pkt.set_payload_len(len - pkt.header_len() as u16);
            }
        }
    }

    pub fn src_addr(&self) -> IpAddr {
        match self {
            IPPkt::V4(_) => IpAddr::V4(
                Ipv4Packet::new_unchecked(self.packet_data())
                    .src_addr()
                    .into(),
            ),
            IPPkt::V6(_) => IpAddr::V6(
                Ipv6Packet::new_unchecked(self.packet_data())
                    .src_addr()
                    .into(),
            ),
        }
    }

    pub fn dst_addr(&self) -> IpAddr {
        match self {
            IPPkt::V4(_) => IpAddr::V4(
                Ipv4Packet::new_unchecked(self.packet_data())
                    .dst_addr()
                    .into(),
            ),
            IPPkt::V6(_) => IpAddr::V6(
                Ipv6Packet::new_unchecked(self.packet_data())
                    .dst_addr()
                    .into(),
            ),
        }
    }

    pub fn protocol(&self) -> IpProtocol {
        match self {
            IPPkt::V4(_) => Ipv4Packet::new_unchecked(self.packet_data()).next_header(),
            IPPkt::V6(_) => Ipv6Packet::new_unchecked(self.packet_data()).next_header(),
        }
    }

    pub fn pkt_total_len(&self) -> usize {
        match self {
            IPPkt::V4(_) => Ipv4Packet::new_unchecked(self.packet_data()).total_len() as usize,
            IPPkt::V6(_) => Ipv6Packet::new_unchecked(self.packet_data()).total_len(),
        }
    }

    pub fn raw_start_offset(&self) -> usize {
        match self {
            IPPkt::V4(inner) => inner.pkt_start_offset,
            IPPkt::V6(inner) => inner.pkt_start_offset,
        }
    }

    pub fn raw_data(&self) -> &[u8] {
        match self {
            IPPkt::V4(inner) => &inner.handle.data[..inner.handle.len],
            IPPkt::V6(inner) => &inner.handle.data[..inner.handle.len],
        }
    }

    pub fn packet_data(&self) -> &[u8] {
        match self {
            IPPkt::V4(inner) => &inner.handle.data[inner.pkt_start_offset..inner.handle.len],
            IPPkt::V6(inner) => &inner.handle.data[inner.pkt_start_offset..inner.handle.len],
        }
    }
    pub fn packet_data_mut(&mut self) -> &mut [u8] {
        match self {
            IPPkt::V4(inner) => &mut inner.handle.data[inner.pkt_start_offset..inner.handle.len],
            IPPkt::V6(inner) => &mut inner.handle.data[inner.pkt_start_offset..inner.handle.len],
        }
    }

    pub fn packet_payload(&self) -> &[u8] {
        match self {
            IPPkt::V4(inner) => {
                let payload_len = Ipv4Packet::new_unchecked(self.packet_data())
                    .payload()
                    .len();
                &inner.handle.data[inner.handle.len - payload_len..inner.handle.len]
            }
            IPPkt::V6(inner) => {
                let payload_len = Ipv6Packet::new_unchecked(self.packet_data())
                    .payload()
                    .len();
                &inner.handle.data[inner.handle.len - payload_len..inner.handle.len]
            }
        }
    }

    pub fn packet_payload_mut(&mut self) -> &mut [u8] {
        match self {
            IPPkt::V4(_) => {
                let payload_len = Ipv4Packet::new_unchecked(self.packet_data())
                    .payload()
                    .len();
                let data_len = self.packet_data().len();
                &mut self.packet_data_mut()[data_len - payload_len..data_len]
            }
            IPPkt::V6(_) => {
                let payload_len = Ipv4Packet::new_unchecked(self.packet_data())
                    .payload()
                    .len();
                let data_len = self.packet_data().len();
                &mut self.packet_data_mut()[data_len - payload_len..data_len]
            }
        }
    }

    pub fn into_handle(self) -> PktBufHandle {
        match self {
            IPPkt::V4(inner) => inner.handle,
            IPPkt::V6(inner) => inner.handle,
        }
    }
}

#[macro_export]
macro_rules! ip_packet_data {
    ($pkt:expr) => {
        &$pkt.handle.data[$pkt.pkt_start_offset..$pkt.handle.len]
    };
}

#[macro_export]
macro_rules! ip_packet_data_mut {
    ($pkt:expr) => {
        &mut $pkt.handle.data[$pkt.pkt_start_offset..$pkt.handle.len]
    };
}

#[macro_export]
macro_rules! ip_packet_payload {
    ($pkt:expr) => {
        &$pkt.handle.data[$pkt.handle.len - $pkt.repr.payload_len()..$pkt.handle.len]
    };
}

#[macro_export]
macro_rules! ip_packet_payload_mut {
    ($pkt:expr) => {
        &mut $pkt.handle.data[$pkt.handle.len - $pkt.repr.payload_len()..$pkt.handle.len]
    };
}

fn rename(d: &[u8]) -> &[u8; 16] {
    d.try_into().expect("slice with incorrect len")
}
