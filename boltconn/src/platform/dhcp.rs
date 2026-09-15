use crate::network::packet::transport_layer::create_raw_udp_pkt;
use crate::proxy::error::DnsError;
use dhcproto::{
    Decodable, Decoder, Encodable, Encoder,
    v4::{self, Message},
};
use pnet_datalink::{Channel, MacAddr};
use smoltcp::wire::{IpProtocol, Ipv4Packet, UdpPacket};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(target_os = "macos")]
mod bpf;
#[cfg(target_os = "macos")]
use bpf::channel;
#[cfg(not(target_os = "macos"))]
use pnet_datalink::channel;

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

#[cfg(not(target_os = "macos"))]
const READ_RETRY: u32 = 1;
#[cfg(not(target_os = "macos"))]
const READ_ONCE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(300);
#[cfg(target_os = "macos")]
const READ_RETRY: u32 = 3;
#[cfg(target_os = "macos")]
const READ_ONCE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn get_dhcp_dns(iface_name: &str) -> Result<IpAddr, DnsError> {
    get_dhcp_dns_impl(iface_name)
}

#[cfg(target_os = "windows")]
pub fn get_dhcp_dns(iface_name: &str) -> Result<IpAddr, DnsError> {
    // spawn a thread calling get_dhcp_dns_impl with a timeout
    let iface_name = iface_name.to_string();
    let handle = std::thread::spawn(move || get_dhcp_dns_impl(&iface_name));
    let start = std::time::Instant::now();
    while start.elapsed() < READ_TIMEOUT {
        if handle.is_finished() {
            return handle
                .join()
                .map_err(|_| DnsError::DhcpNameServer("dhcp thread"))?;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(DnsError::DhcpNameServer(
        "timeout waiting for DHCP response",
    ))
}

fn get_dhcp_dns_impl(iface_name: &str) -> Result<IpAddr, DnsError> {
    let interface = pnet_datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == iface_name)
        .ok_or(DnsError::DhcpNameServer("interface not found"))?;
    let config = pnet_datalink::Config {
        read_timeout: Some(READ_ONCE_TIMEOUT * READ_RETRY),
        ..Default::default()
    };
    // read_timeout only works on linux/BPF/Netmap, which includes macos and linux
    let (mut tx, mut rx) = match channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return Err(DnsError::DhcpNameServer("failed to open channel")),
    };
    let src_mac = interface
        .mac
        .ok_or(DnsError::DhcpNameServer("missing mac address"))?;
    let discover_pkt = create_dhcp_discover(src_mac.octets()).ok_or(DnsError::DhcpNameServer(
        "failed to create DHCP discover packet",
    ))?;
    discover_dns(tx.as_mut(), rx.as_mut(), src_mac, &discover_pkt)
}

fn discover_dns(
    tx: &mut dyn pnet_datalink::DataLinkSender,
    rx: &mut dyn pnet_datalink::DataLinkReceiver,
    src_mac: MacAddr,
    discover_pkt: &[u8],
) -> Result<IpAddr, DnsError> {
    // Keep the channel and transaction ID across retransmissions, so delayed
    // offers remain available. Only macOS retries transient receive failures.
    for _ in 0..READ_RETRY {
        tx.send_to(discover_pkt, None)
            .transpose()
            .ok()
            .flatten()
            .ok_or(DnsError::DhcpNameServer("failed to send packet"))?;
        let start = std::time::Instant::now();
        while start.elapsed() < READ_ONCE_TIMEOUT {
            let buf = match rx.next() {
                Ok(buf) => buf,
                #[cfg(target_os = "macos")]
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
                #[cfg(target_os = "macos")]
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(_) => return Err(DnsError::DhcpNameServer("failed to receive packet")),
            };
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
                && let Some(v4::DhcpOption::DomainNameServer(dns)) =
                    msg.opts().get(v4::OptionCode::DomainNameServer)
            {
                return dns
                    .first()
                    .map(|&ip| IpAddr::V4(ip))
                    .ok_or(DnsError::DhcpNameServer("no DNS option offered by DHCP"));
            }
        }
    }
    Err(DnsError::DhcpNameServer(
        "timeout waiting for DHCP response",
    ))
}

fn get_dhcp_payload(buf: &[u8]) -> Option<Message> {
    if let Ok(pkt) = smoltcp::wire::EthernetFrame::new_checked(buf)
        && pkt.ethertype() == smoltcp::wire::EthernetProtocol::Ipv4
        && let Ok(pkt) = Ipv4Packet::new_checked(pkt.payload())
        && pkt.next_header() == IpProtocol::Udp
        && let Ok(pkt) = UdpPacket::new_checked(pkt.payload())
        && pkt.src_port() == DHCP_SERVER_PORT
        && pkt.dst_port() == DHCP_CLIENT_PORT
    {
        let msg = Message::decode(&mut Decoder::new(pkt.payload())).ok()?;
        return Some(msg);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    const MAC: [u8; 6] = [1, 2, 3, 4, 5, 0];
    const DNS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

    fn offer() -> Vec<u8> {
        let mut message = Message::default();
        message.set_chaddr(&MAC);
        message
            .opts_mut()
            .insert(v4::DhcpOption::MessageType(v4::MessageType::Offer));
        message
            .opts_mut()
            .insert(v4::DhcpOption::DomainNameServer(vec![DNS]));
        let mut payload = Vec::new();
        message.encode(&mut Encoder::new(&mut payload)).unwrap();
        let mut frame = create_dhcp_discover(MAC).unwrap();
        frame.truncate(14);
        frame.extend_from_slice(&create_raw_udp_pkt(
            &payload,
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), DHCP_SERVER_PORT)),
            SocketAddr::from((Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT)),
        ));
        frame
    }

    fn run(events: Vec<io::Result<Vec<u8>>>) -> (Result<IpAddr, DnsError>, Vec<Box<[u8]>>) {
        let mut config = pnet_datalink::dummy::Config::default();
        let inject = config.inject_handle().unwrap();
        let sent = config.read_handle().unwrap();
        for event in events {
            inject.send(event.map(Vec::into_boxed_slice)).unwrap();
        }
        // Fail rather than block if the implementation reads beyond this scenario.
        inject
            .send(Err(io::Error::other("unexpected receive")))
            .unwrap();
        let Channel::Ethernet(mut tx, mut rx) =
            pnet_datalink::dummy::channel(&pnet_datalink::dummy::dummy_interface(0), config)
                .unwrap()
        else {
            panic!("expected Ethernet channel")
        };
        let discover = create_dhcp_discover(MAC).unwrap();
        let result = discover_dns(tx.as_mut(), rx.as_mut(), MAC.into(), &discover);
        (result, sent.try_iter().collect())
    }

    fn timeout() -> io::Result<Vec<u8>> {
        Err(io::ErrorKind::TimedOut.into())
    }

    #[test]
    fn succeeds_without_retransmission() {
        let (result, sent) = run(vec![Ok(offer())]);
        assert_eq!(result.unwrap(), IpAddr::V4(DNS));
        assert_eq!(sent.len(), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn recovers_after_transient_timeouts() {
        for timeouts in 1..=2 {
            let mut events: Vec<_> = (0..timeouts).map(|_| timeout()).collect();
            events.push(Ok(offer()));
            let (result, sent) = run(events);
            assert_eq!(result.unwrap(), IpAddr::V4(DNS));
            assert_eq!(sent.len(), timeouts + 1);
            // Retransmissions preserve the transaction and packet contents.
            assert!(sent.windows(2).all(|pair| pair[0] == pair[1]));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn retries_are_bounded() {
        let (result, sent) = run(vec![timeout(), timeout(), timeout(), Ok(offer())]);
        assert!(matches!(
            result,
            Err(DnsError::DhcpNameServer(
                "timeout waiting for DHCP response"
            ))
        ));
        assert_eq!(sent.len(), 3);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn interrupted_or_would_block_reads_do_not_retransmit() {
        let (result, sent) = run(vec![
            Err(io::ErrorKind::Interrupted.into()),
            Err(io::ErrorKind::WouldBlock.into()),
            Ok(offer()),
        ]);
        assert_eq!(result.unwrap(), IpAddr::V4(DNS));
        assert_eq!(sent.len(), 1);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn other_platforms_keep_one_attempt() {
        let (result, sent) = run(vec![timeout(), Ok(offer())]);
        assert!(matches!(
            result,
            Err(DnsError::DhcpNameServer("failed to receive packet"))
        ));
        assert_eq!(sent.len(), 1);
    }

    #[test]
    fn permanent_receive_error_does_not_retry() {
        let (result, sent) = run(vec![Err(io::ErrorKind::InvalidData.into()), Ok(offer())]);
        assert!(matches!(
            result,
            Err(DnsError::DhcpNameServer("failed to receive packet"))
        ));
        assert_eq!(sent.len(), 1);
    }
}
