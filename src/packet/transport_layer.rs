use crate::packet::ip::IPPkt;
use crate::resource::buf_slab::PktBufHandle;
use crate::{ip_packet_data_mut, ip_packet_payload, ip_packet_payload_mut};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, IpRepr, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket,
    TcpRepr, UdpPacket,
};
use std::fmt::{Display, Formatter};
use std::io;
use std::io::ErrorKind;
use std::net::{SocketAddrV4, SocketAddrV6, SocketAddr};

pub trait TransLayerPkt {
    fn src_port(&self) -> u16;
    fn dst_port(&self) -> u16;
    fn packet_payload(&self) -> &[u8];
    fn into_handle(self) -> PktBufHandle;
    fn ip_pkt(&self) -> &IPPkt;
    fn rewrite_addr(&mut self, src_addr: SocketAddr, dst_addr: SocketAddr);
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

    fn rewrite_addr(
        &mut self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) {
        match (src_addr, dst_addr) {
            (SocketAddr::V4(src_addr), SocketAddr::V4(dst_addr)) => {
                // rewrite tcp
                let mut pkt = TcpPacket::new_unchecked(self.ip_pkt.packet_payload_mut());
                pkt.set_src_port(src_addr.port());
                pkt.set_dst_port(dst_addr.port());
                // use new ip addresses
                pkt.fill_checksum(
                    &IpAddress::Ipv4(Ipv4Address::from(*src_addr.ip())),
                    &IpAddress::Ipv4(Ipv4Address::from(*dst_addr.ip())),
                );
                // rewrite ip header
                let mut pkt = Ipv4Packet::new_unchecked(self.ip_pkt.packet_data_mut());
                pkt.set_src_addr(Ipv4Address::from(*src_addr.ip()));
                pkt.set_dst_addr(Ipv4Address::from(*dst_addr.ip()));
                pkt.fill_checksum();
            }
            (SocketAddr::V6(src_addr), SocketAddr::V6(dst_addr)) => {
                // rewrite tcp
                let mut pkt = TcpPacket::new_unchecked(self.ip_pkt.packet_payload_mut());
                pkt.set_src_port(src_addr.port());
                pkt.set_dst_port(dst_addr.port());
                // use new ip addresses
                pkt.fill_checksum(
                    &IpAddress::Ipv6(Ipv6Address::from(*src_addr.ip())),
                    &IpAddress::Ipv6(Ipv6Address::from(*dst_addr.ip())),
                );
                // rewrite ip header
                let mut pkt = Ipv6Packet::new_unchecked(self.ip_pkt.packet_data_mut());
                pkt.set_src_addr(Ipv6Address::from(*src_addr.ip()));
                pkt.set_dst_addr(Ipv6Address::from(*dst_addr.ip()));
                // ipv6 does not contain checksum
            }
            (_, _) => unreachable!()
        }
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
        assert_eq!(ip_pkt.protocol(), IpProtocol::Tcp);
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

    fn rewrite_addr(&mut self, src_addr: SocketAddr, dst_addr: SocketAddr) {
        match (src_addr, dst_addr) {
            (SocketAddr::V4(src_addr), SocketAddr::V4(dst_addr)) => {
                // rewrite tcp
                let mut pkt = UdpPacket::new_unchecked(self.ip_pkt.packet_payload_mut());
                pkt.set_src_port(src_addr.port());
                pkt.set_dst_port(dst_addr.port());
                // use new ip addresses
                pkt.fill_checksum(
                    &IpAddress::Ipv4(Ipv4Address::from(*src_addr.ip())),
                    &IpAddress::Ipv4(Ipv4Address::from(*dst_addr.ip())),
                );
                // rewrite ip header
                let mut pkt = Ipv4Packet::new_unchecked(self.ip_pkt.packet_data_mut());
                pkt.set_src_addr(Ipv4Address::from(*src_addr.ip()));
                pkt.set_dst_addr(Ipv4Address::from(*dst_addr.ip()));
                pkt.fill_checksum();
            }
            (SocketAddr::V6(src_addr), SocketAddr::V6(dst_addr)) => {
                // rewrite tcp
                let mut pkt = UdpPacket::new_unchecked(self.ip_pkt.packet_payload_mut());
                pkt.set_src_port(src_addr.port());
                pkt.set_dst_port(dst_addr.port());
                // use new ip addresses
                pkt.fill_checksum(
                    &IpAddress::Ipv6(Ipv6Address::from(*src_addr.ip())),
                    &IpAddress::Ipv6(Ipv6Address::from(*dst_addr.ip())),
                );
                // rewrite ip header
                let mut pkt = Ipv6Packet::new_unchecked(self.ip_pkt.packet_data_mut());
                pkt.set_src_addr(Ipv6Address::from(*src_addr.ip()));
                pkt.set_dst_addr(Ipv6Address::from(*dst_addr.ip()));
                // ipv6 does not contain checksum
            }
            (_, _) => unreachable!()
        }
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
        assert_eq!(ip_pkt.protocol(), IpProtocol::Udp);
        Self { ip_pkt }
    }
}
