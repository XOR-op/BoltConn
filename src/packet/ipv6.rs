use std::net::Ipv6Addr;
use std::sync::RwLockReadGuard;
use crate::packet::PayloadProtocol;
use crate::resource::buf_slab::{PktBuffer, PktBufHandle};

pub struct IPv6Pkt {
    handle: PktBufHandle,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    payload_offset: usize,
    proto: PayloadProtocol,
}

impl IPv6Pkt {
    pub fn new(handle: PktBufHandle) -> Self {
        unimplemented!()
    }
}