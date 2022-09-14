use std::net::Ipv4Addr;
use std::sync::RwLockReadGuard;
use crate::packet::PayloadProtocol;
use crate::resource::buf_slab::{PktBuffer, PktBufHandle};

pub struct IPv4Pkt {
    handle: PktBufHandle,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub payload_offset: usize,
    pub proto: PayloadProtocol,
}


impl IPv4Pkt {
    pub fn new(handle: PktBufHandle) -> Self {
        let data = handle.data.read().unwrap();
        let src_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_addr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
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
            src_addr,
            dst_addr,
            payload_offset,
            proto,
        }
    }
}