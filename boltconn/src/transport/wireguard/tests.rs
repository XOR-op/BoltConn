use super::*;
use crate::network::packet::transport_layer::create_raw_udp_pkt;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpPacket};

fn tcp_packet(ipv6: bool, value: u8) -> BytesMut {
    let ip_len = if ipv6 { 40 } else { 20 };
    let mut packet = BytesMut::zeroed(ip_len + 20 + usize::from(value) + 1);
    let (src, dst) = if ipv6 {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: packet.len() - ip_len,
            hop_limit: 64,
        }
        .emit(&mut Ipv6Packet::new_unchecked(&mut packet[..]));
        (src.into(), dst.into())
    } else {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(192, 0, 2, 2);
        Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: packet.len() - ip_len,
            hop_limit: 64,
        }
        .emit(
            &mut Ipv4Packet::new_unchecked(&mut packet[..]),
            &ChecksumCapabilities::default(),
        );
        (src.into(), dst.into())
    };
    let mut tcp = TcpPacket::new_unchecked(&mut packet[ip_len..]);
    tcp.set_header_len(20);
    tcp.set_src_port(1000);
    tcp.set_dst_port(2000);
    tcp.set_ack(true);
    tcp.set_window_len(65535);
    tcp.payload_mut().fill(value);
    tcp.fill_checksum(&src, &dst);
    packet
}

fn network_packet(result: TunnResult<'_>) -> Vec<u8> {
    match result {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("expected a WireGuard network packet, got {other:?}"),
    }
}

/// Returns a sender and a receiver that completed a handshake with each other.
fn connected_pair() -> (Tunn, Tunn) {
    let sender_key = x25519_dalek::StaticSecret::from([1; 32]);
    let receiver_key = x25519_dalek::StaticSecret::from([2; 32]);
    let sender_public = x25519_dalek::PublicKey::from(&sender_key);
    let receiver_public = x25519_dalek::PublicKey::from(&receiver_key);
    let mut sender = Tunn::new(sender_key, receiver_public, None, None, 1, None);
    let mut receiver = Tunn::new(receiver_key, sender_public, None, None, 2, None);
    let mut wire = [0; MAX_PKT_SIZE];
    let request = network_packet(sender.format_handshake_initiation(&mut wire, true));
    let reply = network_packet(receiver.decapsulate(None, &request, &mut wire));
    let confirmation = network_packet(sender.decapsulate(None, &reply, &mut wire));
    assert!(matches!(
        receiver.decapsulate(None, &confirmation, &mut wire),
        TunnResult::Done
    ));
    (sender, receiver)
}

fn tunnel_config(peer: SocketAddr) -> WireguardConfig {
    let peer_secret = x25519_dalek::StaticSecret::from([2; 32]);
    WireguardConfig {
        name: "wireguard".to_string(),
        ip_addr: Some("10.0.0.2".parse().unwrap()),
        ip_addr6: None,
        private_key: x25519_dalek::StaticSecret::from([1; 32]),
        public_key: x25519_dalek::PublicKey::from(&peer_secret),
        endpoint: NetworkAddr::Socket { address: peer },
        mtu: 1420,
        preshared_key: None,
        keepalive: None,
        dns: ResolverConfig::default(),
        dns_preference: DnsPreference::PreferIpv4,
        reserved: None,
        over_tcp: false,
    }
}

#[tokio::test]
async fn undecryptable_packets_are_dropped_without_closing_the_tunnel() {
    let (mut sender, receiver) = connected_pair();
    let (incoming, incoming_rx) = flume::unbounded();
    let (outgoing, _outgoing_rx) = flume::unbounded();
    let tunnel = WireguardTunnel {
        tunnel: tokio::sync::Mutex::new(receiver),
        inner: WireguardTunnelInner {
            outbound: AdapterOrChannel::Channel(outgoing, incoming_rx),
            endpoint: "127.0.0.1:51820".parse().unwrap(),
            smol_notify: Arc::new(Notify::new()),
            inbound_buf_pool: Arc::new(Pool::new()),
            reserved: None,
        },
    };
    let mut wire = [0; MAX_PKT_SIZE];
    let first = network_packet(sender.encapsulate(&tcp_packet(false, 1), &mut wire));
    let second = tcp_packet(false, 2);
    // A replayed datagram, a malformed one, then live traffic.
    incoming.send(BufferIndex::Raw(first.clone())).unwrap();
    incoming.send(BufferIndex::Raw(first)).unwrap();
    incoming.send(BufferIndex::Raw(vec![0xff; 48])).unwrap();
    incoming
        .send(BufferIndex::Raw(network_packet(
            sender.encapsulate(&second, &mut wire),
        )))
        .unwrap();

    let (mut stack_tx, stack_rx) = flume::unbounded();
    let mut plaintext = [0; MAX_PKT_SIZE];
    tunnel
        .receive_incoming_packets(&mut stack_tx, &mut wire, &mut plaintext)
        .await
        .expect("an undecryptable packet closed the tunnel");
    let delivered: Vec<_> = stack_rx
        .try_iter()
        .flat_map(|batch| match batch {
            IpPacketBatch::Single(packet) => vec![packet],
            IpPacketBatch::Multiple(packets) => packets,
        })
        .collect();
    assert_eq!(delivered, vec![tcp_packet(false, 1), second]);
}

#[tokio::test]
async fn icmp_unreachable_does_not_close_a_socket_tunnel() {
    let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer_addr = closed.local_addr().unwrap();
    drop(closed);
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(peer_addr).await.unwrap();
    let local_addr = socket.local_addr().unwrap();
    let tunnel = WireguardTunnel::new(
        AdapterOrSocket::Socket(socket),
        &tunnel_config(peer_addr),
        peer_addr,
        Arc::new(Notify::new()),
    )
    .await
    .unwrap();

    // Each datagram to the closed port draws an ICMP port unreachable, which a connected
    // socket reports as ECONNREFUSED on its next send or receive.
    for round in 0..5 {
        tunnel
            .inner
            .outbound_send(&mut [4, 0, 0, 0, round])
            .await
            .expect("the tunnel closed after an ICMP error");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The peer comes back on the same port, and traffic flows both ways again.
    let peer = tokio::net::UdpSocket::bind(peer_addr).await.unwrap();
    tunnel
        .inner
        .outbound_send(&mut [4, 0, 0, 0, 9])
        .await
        .expect("the tunnel closed after an ICMP error");
    let mut buf = [0; 64];
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
        .await
        .expect("the tunnel stopped sending")
        .unwrap();
    assert_eq!((&buf[..len], from), (&[4, 0, 0, 0, 9][..], local_addr));
    peer.send_to(&[4, 0, 0, 0, 10], local_addr).await.unwrap();
    let mut received = [0; MAX_PKT_SIZE];
    let len = tokio::time::timeout(
        Duration::from_secs(2),
        tunnel.inner.outbound_recv(&mut received),
    )
    .await
    .expect("the tunnel stopped receiving")
    .unwrap();
    assert_eq!(&received[..len], &[4, 0, 0, 0, 10]);
}

#[test]
fn only_icmp_style_socket_errors_are_transient() {
    for kind in [
        ErrorKind::ConnectionRefused,
        ErrorKind::HostUnreachable,
        ErrorKind::NetworkUnreachable,
    ] {
        assert!(is_transient_socket_error(&io::Error::from(kind)));
    }
    // The local address vanished after a network change, or the interface went down;
    // rebuilding is preferred over waiting for the handshake to expire.
    for kind in [ErrorKind::AddrNotAvailable, ErrorKind::NetworkDown] {
        assert!(!is_transient_socket_error(&io::Error::from(kind)));
    }
}

#[tokio::test]
async fn receive_batches_count_control_packets_and_preserve_mixed_data() {
    let sender_key = x25519_dalek::StaticSecret::from([1; 32]);
    let receiver_key = x25519_dalek::StaticSecret::from([2; 32]);
    let sender_public = x25519_dalek::PublicKey::from(&sender_key);
    let receiver_public = x25519_dalek::PublicKey::from(&receiver_key);
    let mut sender = Tunn::new(sender_key, receiver_public, None, None, 1, None);
    let mut receiver = Tunn::new(receiver_key, sender_public, None, None, 2, None);
    let mut wire = [0; MAX_PKT_SIZE];
    let request = network_packet(sender.format_handshake_initiation(&mut wire, true));
    let reply = network_packet(receiver.decapsulate(None, &request, &mut wire));
    let confirmation = network_packet(sender.decapsulate(None, &reply, &mut wire));
    assert!(matches!(
        receiver.decapsulate(None, &confirmation, &mut wire),
        TunnResult::Done
    ));

    let (incoming, incoming_rx) = flume::unbounded();
    let (outgoing, _outgoing_rx) = flume::unbounded();
    let tunnel = WireguardTunnel {
        tunnel: tokio::sync::Mutex::new(receiver),
        inner: WireguardTunnelInner {
            outbound: AdapterOrChannel::Channel(outgoing, incoming_rx.clone()),
            endpoint: "127.0.0.1:51820".parse().unwrap(),
            smol_notify: Arc::new(Notify::new()),
            inbound_buf_pool: Arc::new(Pool::new()),
            reserved: None,
        },
    };
    for _ in 0..IpPacketBatch::CAPACITY {
        let packet = network_packet(sender.encapsulate(&[], &mut wire));
        incoming.send(BufferIndex::Raw(packet)).unwrap();
    }
    let mut expected: Vec<_> = (0..IpPacketBatch::CAPACITY + 1)
        .map(|index| tcp_packet(index % 2 == 1, index as u8))
        .collect();
    for index in 0..=IpPacketBatch::CAPACITY {
        expected.push(create_raw_udp_pkt(
            &vec![index as u8; index + 1],
            "192.0.2.1:1000".parse().unwrap(),
            "192.0.2.2:2000".parse().unwrap(),
        ));
        expected.push(create_raw_udp_pkt(
            &vec![index as u8; index + 13],
            "[2001:db8::1]:1000".parse().unwrap(),
            "[2001:db8::2]:2000".parse().unwrap(),
        ));
    }
    expected.push(tcp_packet(false, 100));
    expected.push(tcp_packet(true, 101));
    for packet in &expected {
        let encrypted = network_packet(sender.encapsulate(packet, &mut wire));
        incoming.send(BufferIndex::Raw(encrypted)).unwrap();
    }
    let (mut stack_tx, stack_rx) = flume::bounded(4);
    let mut plaintext = [0; MAX_PKT_SIZE];
    assert!(
        !tunnel
            .receive_incoming_packets(&mut stack_tx, &mut wire, &mut plaintext)
            .await
            .unwrap()
    );
    assert_eq!(incoming_rx.len(), expected.len());
    assert!(stack_rx.is_empty());

    let mut actual = Vec::new();
    for expected_batch in expected.chunks(IpPacketBatch::CAPACITY) {
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                tunnel.receive_incoming_packets(&mut stack_tx, &mut wire, &mut plaintext),
            )
            .await
            .expect("a partial batch must not wait for more packets")
            .unwrap()
        );
        let previous_len = actual.len();
        match stack_rx.try_recv().unwrap() {
            IpPacketBatch::Single(packet) => actual.push(packet),
            IpPacketBatch::Multiple(packets) => actual.extend(packets),
        }
        assert_eq!(actual.len() - previous_len, expected_batch.len());
    }
    assert_eq!(actual, expected);
    assert!(incoming_rx.is_empty());
}
