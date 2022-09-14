use std::{mem, slice};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::RwLockReadGuard;
use byteorder::{ByteOrder, NetworkEndian};
use crate::resource::buf_slab::{PktBuffer, PktBufHandle};

#[derive(Debug, Clone, Copy)]
pub enum PayloadProtocol {
    TCP,
    UDP,
    ICMP,
    UNKNOWN,
}

pub enum IPPkt {
    V4(IPv4Pkt),
    V6(IPv6Pkt),
}

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


pub struct IPv6Pkt {
    handle: PktBufHandle,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    payload_offset: usize,
    proto: PayloadProtocol,
}

fn rename(d: &[u16]) -> [u16; 8] {
    d.try_into().unwrap()
}

impl IPv6Pkt {
    pub fn new(handle: PktBufHandle) -> Self {
        let data = handle.data.read().unwrap();
        let src_addr = unsafe { slice::from_raw_parts(data[8..16].as_ptr() as *const u16, 8) };
        let src_addr = Ipv6Addr::from(rename(src_addr));
        let dst_addr = unsafe { slice::from_raw_parts(data[16..24].as_ptr() as *const u16, 8) };
        let dst_addr = Ipv6Addr::from(rename(dst_addr));
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
            src_addr,
            dst_addr,
            payload_offset,
            proto,
        }
    }
}