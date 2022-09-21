use crate::packet::ip::IPPkt;
use crate::resource::buf_slab::PktBufHandle;
use smoltcp::wire::{IpProtocol, IpRepr, Ipv4Packet, Ipv6Packet, TcpPacket, TcpRepr, UdpPacket};
use std::fmt::{Display, Formatter};
use std::io;
use std::net::{SocketAddrV4, SocketAddrV6};
use smoltcp::phy::ChecksumCapabilities;
use tokio::net::unix::SocketAddr;

pub trait TransLayerPkt {
    fn src_port(&self) -> u16;
    fn dst_port(&self) -> u16;
    fn packet_payload(&self) -> &[u8];
    fn into_handle(self) -> PktBufHandle;
    fn ip_pkt(&self) -> &IPPkt;
    fn rewrite_v4_addr(&mut self, src_addr: SocketAddrV4, dst_addr: SocketAddrV4) -> io::Result<()>;
    fn rewrite_v6_addr(&mut self, src_addr: SocketAddrV6, dst_addr: SocketAddrV6) -> io::Result<()>;
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

    fn rewrite_v4_addr(&mut self, src_addr: SocketAddrV4, dst_addr: SocketAddrV4) -> io::Result<()> {
        match self.ip_pkt.repr {
            IpRepr::Ipv4(ref mut repr) => {
                // rewrite tcp
                let mut pkt = TcpPacket::new_unchecked(self.ip_pkt.packet_payload_mut());
                let mut tcp_repr = TcpRepr::parse(&pkt, &self.ip_pkt.repr.src_addr(),
                                                  &self.ip_pkt.repr.dst_addr(), &ChecksumCapabilities::default())?;
                tcp_repr.src_port = src_addr.port();
                tcp_repr.dst_port = dst_addr.port();
                // use new ip addresses
                tcp_repr.emit(&mut pkt, src_addr.ip().into(),
                              dst_addr.ip().into(), &ChecksumCapabilities::default());

                // rewrite ip header
                let mut pkt = Ipv4Packet::new_unchecked(self.ip_pkt.packet_data_mut());
                repr.src_addr = src_addr.ip().into();
                repr.dst_addr = dst_addr.ip().into();
                repr.emit(&mut pkt, &ChecksumCapabilities::default());
            }
            _ => unreachable!(),
        };
        Ok(())
    }

    fn rewrite_v6_addr(&mut self, src_addr: SocketAddrV6, dst_addr: SocketAddrV6) -> io::Result<()> {
        match self.ip_pkt.repr {
            IpRepr::Ipv6(ref mut repr) => {
                // rewrite tcp
                let mut pkt = TcpPacket::new_unchecked(self.ip_pkt.packet_payload_mut());
                let mut tcp_repr = TcpRepr::parse(&pkt, &self.ip_pkt.repr.src_addr(),
                                                  &self.ip_pkt.repr.dst_addr(), &ChecksumCapabilities::default())?;
                tcp_repr.src_port = src_addr.port();
                tcp_repr.dst_port = dst_addr.port();
                // use new ip addresses
                tcp_repr.emit(&mut pkt, src_addr.ip().into(),
                              dst_addr.ip().into(), &ChecksumCapabilities::default());

                // rewrite ip header
                let mut pkt = Ipv6Packet::new_unchecked(self.ip_pkt.packet_data_mut());
                repr.src_addr = src_addr.ip().into();
                repr.dst_addr = dst_addr.ip().into();
                repr.emit(&mut pkt);
            }
            _ => unreachable!(),
        };
        Ok(())
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
