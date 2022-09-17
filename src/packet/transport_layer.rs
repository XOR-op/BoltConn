use crate::packet::ip::IPPkt;
use crate::resource::buf_slab::PktBufHandle;
use smoltcp::wire::{IpProtocol, TcpPacket, TcpRepr, UdpPacket};
use std::fmt::{Display, Formatter};

pub trait TransLayerPkt {
    fn src_port(&self) -> u16;
    fn dst_port(&self) -> u16;
    fn packet_payload(&self) -> &[u8];
    fn into_handle(self) -> PktBufHandle;
    fn ip_pkt(&self) -> &IPPkt;
}

pub struct TcpPkt {
    ip_pkt: IPPkt,
}

impl TransLayerPkt for TcpPkt {
    fn src_port(&self) -> u16 {
        TcpPacket::new_unchecked(self.ip_pkt.packet_payload()).src_port()
    }

    fn dst_port(&self) -> u16 {
        TcpPacket::new_unchecked(self.ip_pkt.packet_payload()).dst_port()
    }

    fn packet_payload(&self) -> &[u8] {
        let pkt = self.ip_pkt.packet_payload();
        &pkt[(TcpPacket::new_unchecked(pkt).header_len() as usize)..]
    }

    fn into_handle(self) -> PktBufHandle {
        self.ip_pkt.into_handle()
    }

    fn ip_pkt(&self) -> &IPPkt {
        &self.ip_pkt
    }
}

impl Display for TcpPkt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: [src_port:{}, dst_port:{}",
            self.ip_pkt,
            self.src_port(),
            self.dst_port()
        )
    }
}

impl TcpPkt {
    pub fn new(ip_pkt: IPPkt) -> Self {
        assert_eq!(ip_pkt.repr.protocol(), IpProtocol::Tcp);
        Self { ip_pkt }
    }
}

pub struct UdpPkt {
    ip_pkt: IPPkt,
}

impl TransLayerPkt for UdpPkt {
    fn src_port(&self) -> u16 {
        UdpPacket::new_unchecked(self.ip_pkt.packet_payload()).src_port()
    }

    fn dst_port(&self) -> u16 {
        UdpPacket::new_unchecked(self.ip_pkt.packet_payload()).dst_port()
    }

    fn packet_payload(&self) -> &[u8] {
        &self.ip_pkt.packet_payload()[8..]
    }

    fn into_handle(self) -> PktBufHandle {
        self.ip_pkt.into_handle()
    }
    fn ip_pkt(&self) -> &IPPkt {
        &self.ip_pkt
    }
}

impl Display for UdpPkt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: [src_port:{}, dst_port:{}",
            self.ip_pkt,
            self.src_port(),
            self.dst_port()
        )
    }
}

impl UdpPkt {
    pub fn new(ip_pkt: IPPkt) -> Self {
        assert_eq!(ip_pkt.repr.protocol(), IpProtocol::Udp);
        Self { ip_pkt }
    }
}
