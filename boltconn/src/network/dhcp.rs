use crate::network::packet::transport_layer::create_raw_udp_pkt;
use crate::proxy::error::DnsError;
use dhcproto::{
    v4::{self, Message},
    Decodable, Decoder, Encodable, Encoder,
};
use pnet_datalink::{Channel, MacAddr};
use smoltcp::wire::{IpProtocol, Ipv4Packet, UdpPacket};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

fn construct_discover_packet(mac_addr: MacAddr) -> Option<Vec<u8>> {
    // construct a new Message
    let mut msg = v4::Message::default();
    msg.set_flags(v4::Flags::default().set_broadcast()) // set broadcast to true
        .set_chaddr(&mac_addr.octets()) // set chaddr
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover)); // set msg type

    // set some more options
    msg.opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
        ]));
    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(mac_addr.octets().to_vec()));

    // now encode to bytes
    let mut buf = Vec::new();
    let mut e = Encoder::new(&mut buf);
    msg.encode(&mut e).ok()?;
    Some(buf)
}

fn create_dhcp_discover(src_mac: [u8; 6]) -> Option<Vec<u8>> {
    let buf = construct_discover_packet(src_mac.into())?;
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DHCP_CLIENT_PORT);
    let dst = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
        DHCP_SERVER_PORT,
    );
    let ip_pkt = create_raw_udp_pkt(&buf, src, dst);
    let mut ether_pkt_data = Vec::new();
    ether_pkt_data.reserve_exact(14 + ip_pkt.len());
    ether_pkt_data.resize(14, 0);
    ether_pkt_data.extend_from_slice(&ip_pkt);
    let mut ether_pkt = smoltcp::wire::EthernetFrame::new_unchecked(&mut ether_pkt_data[..]);
    let src_mac = smoltcp::wire::EthernetAddress::from_bytes(&src_mac);
    let dst_mac = smoltcp::wire::EthernetAddress::BROADCAST;
    smoltcp::wire::EthernetRepr {
        src_addr: src_mac,
        dst_addr: dst_mac,
        ethertype: smoltcp::wire::EthernetProtocol::Ipv4,
    }
    .emit(&mut ether_pkt);
    Some(ether_pkt_data)
}

pub fn get_dhcp_dns(iface_name: &str) -> Result<IpAddr, DnsError> {
    let interface = pnet_datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == iface_name)
        .ok_or(DnsError::DhcpNameServer("interface not found"))?;
    let (mut tx, mut rx) =
        match pnet_datalink::channel(&interface, pnet_datalink::Config::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(DnsError::DhcpNameServer("failed to open channel")),
        };
    let src_mac = interface
        .mac
        .ok_or(DnsError::DhcpNameServer("missing mac address"))?;
    let discover_pkt = create_dhcp_discover(src_mac.octets()).ok_or(DnsError::DhcpNameServer(
        "failed to create DHCP discover packet",
    ))?;
    tx.send_to(&discover_pkt, None)
        .transpose()
        .ok()
        .flatten()
        .ok_or(DnsError::DhcpNameServer("failed to send packet"))?;
    loop {
        let buf = rx
            .next()
            .ok()
            .ok_or(DnsError::DhcpNameServer("failed to receive packet"))?;
        let Some(msg) = get_dhcp_payload(buf) else {
            continue;
        };
        if msg.chaddr() == src_mac.octets()
            && msg
                .opts()
                .get(v4::OptionCode::MessageType)
                .is_some_and(|v| match v {
                    v4::DhcpOption::MessageType(ty) => *ty == v4::MessageType::Offer,
                    _ => false,
                })
        {
            if let Some(v4::DhcpOption::DomainNameServer(dns)) =
                msg.opts().get(v4::OptionCode::DomainNameServer)
            {
                return dns
                    .first()
                    .map(|&ip| IpAddr::V4(ip))
                    .ok_or(DnsError::DhcpNameServer("no DNS option offered by DHCP"));
            }
        }
    }
}

fn get_dhcp_payload(buf: &[u8]) -> Option<Message> {
    if let Ok(pkt) = smoltcp::wire::EthernetFrame::new_checked(buf) {
        if pkt.ethertype() == smoltcp::wire::EthernetProtocol::Ipv4 {
            if let Ok(pkt) = Ipv4Packet::new_checked(pkt.payload()) {
                if pkt.next_header() == IpProtocol::Udp {
                    if let Ok(pkt) = UdpPacket::new_checked(pkt.payload()) {
                        if pkt.src_port() == DHCP_SERVER_PORT && pkt.dst_port() == DHCP_CLIENT_PORT
                        {
                            let msg = Message::decode(&mut Decoder::new(pkt.payload())).ok()?;
                            return Some(msg);
                        }
                    }
                }
            }
        }
    }
    None
}
