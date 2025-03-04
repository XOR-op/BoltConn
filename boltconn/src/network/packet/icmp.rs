use crate::network::packet::ip::IPPkt;
use bytes::BytesMut;
use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, IpProtocol, Ipv4Packet};
use std::net::Ipv4Addr;

pub struct Icmpv4Pkt {
    ip_pkt: IPPkt,
}

impl Icmpv4Pkt {
    pub fn into_bytes_mut(self) -> BytesMut {
        self.ip_pkt.into_bytes_mut()
    }

    pub fn ip_pkt(&self) -> &IPPkt {
        &self.ip_pkt
    }

    pub fn rewrite_addr(&mut self, src_addr: Ipv4Addr, dst_addr: Ipv4Addr) {
        let mut pkt = Icmpv4Packet::new_unchecked(self.ip_pkt.packet_payload_mut());
        pkt.fill_checksum();
        // rewrite ip header
        let mut pkt = Ipv4Packet::new_unchecked(self.ip_pkt.packet_data_mut());
        pkt.set_src_addr(src_addr);
        pkt.set_dst_addr(dst_addr);
        pkt.fill_checksum();
    }

    pub fn is_echo_request(&self) -> bool {
        let pkt = Icmpv4Packet::new_unchecked(self.ip_pkt.packet_payload());
        pkt.msg_type() == Icmpv4Message::EchoRequest
    }

    pub fn set_as_reply(&mut self) {
        let mut pkt = Icmpv4Packet::new_unchecked(self.ip_pkt.packet_payload_mut());
        pkt.set_msg_type(Icmpv4Message::EchoReply);
        pkt.set_msg_code(0);
        pkt.fill_checksum();
    }

    pub fn new(ip_pkt: IPPkt) -> Self {
        assert_eq!(ip_pkt.protocol(), IpProtocol::Icmp);
        Self { ip_pkt }
    }
}
