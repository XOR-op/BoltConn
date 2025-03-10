use crate::network::packet::ip::IPPkt;
use bytes::BytesMut;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket,
    UdpRepr,
};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};

pub trait TransLayerPkt {
    fn src_port(&self) -> u16;
    fn dst_port(&self) -> u16;
    fn packet_payload(&self) -> &[u8];
    fn into_bytes_mut(self) -> BytesMut;
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

    fn into_bytes_mut(self) -> BytesMut {
        self.ip_pkt.into_bytes_mut()
    }

    fn ip_pkt(&self) -> &IPPkt {
        &self.ip_pkt
    }

    fn rewrite_addr(&mut self, src_addr: SocketAddr, dst_addr: SocketAddr) {
        match (src_addr, dst_addr) {
            (SocketAddr::V4(src_addr), SocketAddr::V4(dst_addr)) => {
                // rewrite tcp
                let mut pkt = TcpPacket::new_unchecked(self.ip_pkt.packet_payload_mut());
                pkt.set_src_port(src_addr.port());
                pkt.set_dst_port(dst_addr.port());
                // use new ip addresses
                pkt.fill_checksum(
                    &IpAddress::Ipv4(*src_addr.ip()),
                    &IpAddress::Ipv4(*dst_addr.ip()),
                );
                // rewrite ip header
                let mut pkt = Ipv4Packet::new_unchecked(self.ip_pkt.packet_data_mut());
                pkt.set_src_addr(*src_addr.ip());
                pkt.set_dst_addr(*dst_addr.ip());
                pkt.fill_checksum();
            }
            (SocketAddr::V6(src_addr), SocketAddr::V6(dst_addr)) => {
                // rewrite tcp
                let mut pkt = TcpPacket::new_unchecked(self.ip_pkt.packet_payload_mut());
                pkt.set_src_port(src_addr.port());
                pkt.set_dst_port(dst_addr.port());
                // use new ip addresses
                pkt.fill_checksum(
                    &IpAddress::Ipv6(*src_addr.ip()),
                    &IpAddress::Ipv6(*dst_addr.ip()),
                );
                // rewrite ip header
                let mut pkt = Ipv6Packet::new_unchecked(self.ip_pkt.packet_data_mut());
                pkt.set_src_addr(*src_addr.ip());
                pkt.set_dst_addr(*dst_addr.ip());
                // ipv6 does not contain checksum
            }
            (_, _) => unreachable!(),
        }
    }
}

impl Display for TcpPkt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: [src_port:{}, dst_port:{}]",
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

    pub fn as_tcp_packet(&self) -> TcpPacket<&[u8]> {
        TcpPacket::new_unchecked(self.ip_pkt.packet_payload())
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

    fn into_bytes_mut(self) -> BytesMut {
        self.ip_pkt.into_bytes_mut()
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
                    &IpAddress::Ipv4(*src_addr.ip()),
                    &IpAddress::Ipv4(*dst_addr.ip()),
                );
                // rewrite ip header
                let mut pkt = Ipv4Packet::new_unchecked(self.ip_pkt.packet_data_mut());
                pkt.set_src_addr(*src_addr.ip());
                pkt.set_dst_addr(*dst_addr.ip());
                pkt.fill_checksum();
            }
            (SocketAddr::V6(src_addr), SocketAddr::V6(dst_addr)) => {
                // rewrite tcp
                let mut pkt = UdpPacket::new_unchecked(self.ip_pkt.packet_payload_mut());
                pkt.set_src_port(src_addr.port());
                pkt.set_dst_port(dst_addr.port());
                // use new ip addresses
                pkt.fill_checksum(
                    &IpAddress::Ipv6(*src_addr.ip()),
                    &IpAddress::Ipv6(*dst_addr.ip()),
                );
                // rewrite ip header
                let mut pkt = Ipv6Packet::new_unchecked(self.ip_pkt.packet_data_mut());
                pkt.set_src_addr(*src_addr.ip());
                pkt.set_dst_addr(*dst_addr.ip());
                // ipv6 does not contain checksum
            }
            (_, _) => unreachable!(),
        }
    }
}

impl Display for UdpPkt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: [src_port:{}, dst_port:{}]",
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

    pub fn set_payload(mut self, payload: &[u8]) -> UdpPkt {
        let old_payload_len = self.packet_payload().len();
        let old_ip_total_len = self.ip_pkt.pkt_total_len();
        let delta = payload.len() as i64 - old_payload_len as i64;
        let pkt_start_offset = self.ip_pkt.raw_start_offset();
        let is_v4 = match self.ip_pkt {
            IPPkt::V4(_) => true,
            IPPkt::V6(_) => false,
        };
        self.ip_pkt
            .set_len((old_ip_total_len as i64 + delta) as u16);

        let mut handle = self.ip_pkt.into_bytes_mut();
        // copy data
        handle.resize((handle.len() as i64 + delta) as usize, 0u8);
        let handle_len = handle.len();
        handle[handle_len - payload.len()..].copy_from_slice(payload);

        // set udp fields
        let mut ip_pkt = if is_v4 {
            IPPkt::from_v4(handle, pkt_start_offset)
        } else {
            IPPkt::from_v6(handle, pkt_start_offset)
        };
        let (src_ip, dst_ip) = (ip_pkt.src_addr(), ip_pkt.dst_addr());
        let mut raw_udp = UdpPacket::new_unchecked(ip_pkt.packet_payload_mut());
        raw_udp.set_len((raw_udp.len() as i64 + delta) as u16);
        raw_udp.fill_checksum(&IpAddress::from(src_ip), &IpAddress::from(dst_ip));
        // set ip fields
        if is_v4 {
            let mut raw_ip = Ipv4Packet::new_unchecked(ip_pkt.packet_data_mut());
            raw_ip.fill_checksum();
        }
        UdpPkt { ip_pkt }
    }
}

pub fn create_raw_udp_pkt(data: &[u8], src: SocketAddr, dst: SocketAddr) -> BytesMut {
    let is_v4 = src.is_ipv4();
    let udp_hdr = 8;
    let ip_hdr = if is_v4 { 20 } else { 40 };
    let mut buf = BytesMut::zeroed(ip_hdr + udp_hdr + data.len());
    let mut udp_pkt = UdpPacket::new_unchecked(&mut buf.as_mut()[ip_hdr..]);
    UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    }
    .emit(
        &mut udp_pkt,
        &src.ip().into(),
        &dst.ip().into(),
        data.len(),
        |b| b.copy_from_slice(data),
        &ChecksumCapabilities::default(),
    );
    if is_v4 {
        let mut ip_pkt = Ipv4Packet::new_unchecked(buf.as_mut());
        let (src, dst) = match (src.ip(), dst.ip()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => (src, dst),
            _ => unreachable!(),
        };
        Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Udp,
            payload_len: data.len() + udp_hdr,
            hop_limit: 31,
        }
        .emit(&mut ip_pkt, &ChecksumCapabilities::default());
    } else {
        let mut ip_pkt = Ipv6Packet::new_unchecked(buf.as_mut());
        let (src, dst) = match (src.ip(), dst.ip()) {
            (IpAddr::V6(src), IpAddr::V6(dst)) => (src, dst),
            _ => unreachable!(),
        };
        Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Udp,
            payload_len: data.len() + udp_hdr,
            hop_limit: 31,
        }
        .emit(&mut ip_pkt);
    }
    buf
}
