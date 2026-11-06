use super::*;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{Ipv4Packet, Ipv4Repr, TcpPacket};
use std::hint::black_box;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{ReadBuf, split};

const CLIENT: SocketAddrV4 = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 2), 50000);
const REMOTE: SocketAddrV4 = SocketAddrV4::new(std::net::Ipv4Addr::new(203, 0, 113, 7), 443);
const NAT: SocketAddrV4 = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 12345);
const PREFIX_LEN: usize = if cfg!(target_os = "macos") { 4 } else { 0 };

fn tcp_packet(src: SocketAddrV4, dst: SocketAddrV4, size: usize) -> Bytes {
    let mut data = BytesMut::zeroed(PREFIX_LEN + size);
    #[cfg(target_os = "macos")]
    {
        data[..4].copy_from_slice(&[0, 0, 0, libc::AF_INET as u8]);
    }
    let mut ip = Ipv4Packet::new_unchecked(&mut data[PREFIX_LEN..]);
    Ipv4Repr {
        src_addr: *src.ip(),
        dst_addr: *dst.ip(),
        next_header: IpProtocol::Tcp,
        payload_len: size - 20,
        hop_limit: 64,
    }
    .emit(&mut ip, &ChecksumCapabilities::default());
    let mut tcp = TcpPacket::new_unchecked(&mut data[PREFIX_LEN + 20..]);
    tcp.set_header_len(20);
    tcp.set_src_port(src.port());
    tcp.set_dst_port(dst.port());
    tcp.set_ack(true);
    tcp.set_window_len(65535);
    for (i, byte) in tcp.payload_mut().iter_mut().enumerate() {
        *byte = i as u8;
    }
    tcp.fill_checksum(&(*src.ip()).into(), &(*dst.ip()).into());
    data.freeze()
}

fn packet_loop() -> (TunPacketLoop, flume::Sender<Bytes>, flume::Receiver<Bytes>) {
    let (udp_tx, udp_out) = flume::bounded(16);
    let (udp_in, udp_rx) = flume::bounded(16);
    (
        TunPacketLoop {
            session_mgr: Arc::new(MappingSessionManager::new()),
            udp_tx,
            udp_rx,
            icmp_proxy_enabled: false,
            prefix_len: PREFIX_LEN,
        },
        udp_in,
        udp_out,
    )
}

// Packet-oriented I/O: each read supplies a complete packet, including the utun
// prefix on macOS. Unlike a byte stream, packets can never be coalesced.
struct PacketIo {
    packets: Vec<Bytes>,
    reads: usize,
    remaining: usize,
    writes: usize,
    capture: bool,
    output: Vec<Bytes>,
}

impl PacketIo {
    fn new(packets: Vec<Bytes>, count: usize, capture: bool) -> Self {
        Self {
            packets,
            reads: 0,
            remaining: count,
            writes: 0,
            capture,
            output: Vec::new(),
        }
    }
}

impl AsyncRead for PacketIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.remaining > 0 {
            let packet = black_box(&self.packets[self.reads % self.packets.len()]);
            assert!(
                buf.remaining() >= packet.len(),
                "TUN read would truncate a packet"
            );
            buf.put_slice(packet);
            self.reads += 1;
            self.remaining -= 1;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PacketIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        black_box(buf);
        self.writes += 1;
        if self.capture {
            self.output.push(Bytes::copy_from_slice(buf));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(target_os = "linux")]
fn thread_cpu_time() -> std::time::Duration {
    let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime initializes ts on success, checked before reading it.
    let ts = unsafe {
        assert_eq!(
            libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, ts.as_mut_ptr()),
            0
        );
        ts.assume_init()
    };
    std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

// Run the production select/read/NAT/write loop on one runtime thread. Packet
// generation and allocation are outside timing. This isolates userspace CPU
// cost; it does not measure kernel TUN, routing, or outbound proxy throughput.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
// Fail only when invoked; debug test builds must still compile the benchmark.
#[allow(clippy::assertions_on_constants)]
#[ignore = "CPU benchmark; run in release mode with --ignored --nocapture"]
async fn benchmark_tun_tcp_loop() {
    assert!(!cfg!(debug_assertions), "use --release for this benchmark");
    let count = std::env::var("TUN_BENCH_PACKETS")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(500_000);
    assert!(count > 0);
    let (runner, _udp_in, _udp_out) = packet_loop();
    runner
        .session_mgr
        .register_tcp_session(CLIENT.into(), REMOTE.into());
    let (icmp_tx, _icmp_rx) = flume::bounded(16);
    for size in [64, 1500, 9000] {
        let packets = vec![
            tcp_packet(CLIENT, REMOTE, size),
            tcp_packet(NAT, SocketAddrV4::new(*REMOTE.ip(), CLIENT.port()), size),
        ];
        let mut warmup = PacketIo::new(packets.clone(), 10_000, false);
        runner.run(&mut warmup, NAT, icmp_tx.clone()).await;
        for sample in 0..7 {
            let mut io = PacketIo::new(packets.clone(), count, false);
            let cpu_start = thread_cpu_time();
            let start = std::time::Instant::now();
            runner.run(&mut io, NAT, icmp_tx.clone()).await;
            let elapsed = start.elapsed();
            let cpu = thread_cpu_time() - cpu_start;
            assert_eq!(io.reads, count);
            assert_eq!(io.writes, count);
            println!(
                "tun_tcp_loop,size={size},sample={sample},packets={count},cpu_ns_per_packet={:.2},mpps={:.3}",
                cpu.as_nanos() as f64 / count as f64,
                count as f64 / elapsed.as_secs_f64() / 1e6,
            );
        }
    }
}

#[tokio::test]
async fn tcp_nat_preserves_packets_in_both_directions() {
    let (runner, _udp_in, _udp_out) = packet_loop();
    let (icmp_tx, _icmp_rx) = flume::bounded(16);
    let mut packets = Vec::new();
    let mut expected = Vec::new();
    // Alternate short and maximum-size packets to catch stale lengths or an
    // undersized recycled buffer. Each direction exercises a different lookup.
    for size in [40, 65535, 64, 9000, 1500, 40] {
        packets.push(tcp_packet(CLIENT, REMOTE, size));
        expected.push(tcp_packet(
            SocketAddrV4::new(*REMOTE.ip(), CLIENT.port()),
            NAT,
            size,
        ));
        packets.push(tcp_packet(
            NAT,
            SocketAddrV4::new(*REMOTE.ip(), CLIENT.port()),
            size,
        ));
        expected.push(tcp_packet(REMOTE, CLIENT, size));
    }
    let mut io = PacketIo::new(packets, expected.len(), true);
    runner.run(&mut io, NAT, icmp_tx).await;
    // Byte-for-byte comparison covers addresses, ports, payload and both checksums.
    assert_eq!(io.output, expected);
}

// Exercise the production UDP return-packet builder, including allocation,
// payload copying, both headers, checksums, and releasing the result.
#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::assertions_on_constants)]
#[ignore = "CPU benchmark; run in release mode with --ignored --nocapture"]
fn benchmark_udp_return_packet() {
    use crate::network::packet::transport_layer::create_raw_udp_pkt;
    let count = std::env::var("TUN_BENCH_PACKETS")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(500_000);
    assert!(!cfg!(debug_assertions), "use --release for this benchmark");
    assert!(count > 0);
    let src = black_box(SocketAddr::from(REMOTE));
    let dst = black_box(SocketAddr::from(CLIENT));
    for size in [64, 1500, 9000] {
        let payload: Vec<_> = (0..size - 28).map(|i| i as u8).collect();
        for _ in 0..10_000 {
            black_box(create_raw_udp_pkt(black_box(&payload), src, dst));
        }
        for sample in 0..7 {
            let start = thread_cpu_time();
            for _ in 0..count {
                black_box(create_raw_udp_pkt(black_box(&payload), src, dst));
            }
            let elapsed = thread_cpu_time() - start;
            println!(
                "udp_return_packet,size={size},sample={sample},packets={count},cpu_ns_per_packet={:.2}",
                elapsed.as_nanos() as f64 / count as f64,
            );
        }
    }
}

fn with_prefix(packet: &[u8]) -> Bytes {
    let mut result = BytesMut::with_capacity(PREFIX_LEN + packet.len());
    #[cfg(target_os = "macos")]
    {
        result.extend_from_slice(&[0, 0, 0, libc::AF_INET as u8]);
    }
    result.extend_from_slice(packet);
    result.freeze()
}

fn icmp_packet(reply: bool) -> Bytes {
    use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};
    let repr = if reply {
        Icmpv4Repr::EchoReply {
            ident: 123,
            seq_no: 456,
            data: b"test echo",
        }
    } else {
        Icmpv4Repr::EchoRequest {
            ident: 123,
            seq_no: 456,
            data: b"test echo",
        }
    };
    let (src_addr, dst_addr) = if reply {
        (*REMOTE.ip(), *CLIENT.ip())
    } else {
        (*CLIENT.ip(), *REMOTE.ip())
    };
    let mut data = BytesMut::zeroed(20 + repr.buffer_len());
    Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Icmp,
        payload_len: repr.buffer_len(),
        hop_limit: 64,
    }
    .emit(
        &mut Ipv4Packet::new_unchecked(&mut data[..]),
        &ChecksumCapabilities::default(),
    );
    repr.emit(
        &mut Icmpv4Packet::new_unchecked(&mut data[20..]),
        &ChecksumCapabilities::default(),
    );
    with_prefix(&data)
}

#[tokio::test]
async fn queued_packets_keep_ownership_while_tcp_reuses_its_buffer() {
    use crate::network::packet::transport_layer::create_raw_udp_pkt;
    let (mut runner, _udp_in, udp_out) = packet_loop();
    runner.icmp_proxy_enabled = true;
    let (icmp_tx, icmp_rx) = flume::bounded(16);
    let udp1 = create_raw_udp_pkt(b"first UDP packet", CLIENT.into(), REMOTE.into());
    let udp2 = create_raw_udp_pkt(
        b"second UDP packet with a different length",
        CLIENT.into(),
        REMOTE.into(),
    );
    let icmp = icmp_packet(false);
    let tcp = tcp_packet(CLIENT, REMOTE, 1500);
    let packets = vec![
        with_prefix(&udp1),
        tcp.clone(),
        icmp.clone(),
        tcp.clone(),
        with_prefix(&udp2),
        tcp,
    ];
    let mut io = PacketIo::new(packets, 6, true);
    runner.run(&mut io, NAT, icmp_tx).await;
    assert_eq!(io.writes, 3);
    assert_eq!(udp_out.try_recv().unwrap(), udp1);
    assert_eq!(udp_out.try_recv().unwrap(), udp2);
    assert!(udp_out.try_recv().is_err());
    assert_eq!(icmp_rx.try_recv().unwrap().ip_pkt().raw_data(), icmp);
    assert!(icmp_rx.try_recv().is_err());
}

#[tokio::test]
async fn local_icmp_echo_can_reuse_buffer_for_tcp() {
    let (runner, _udp_in, _udp_out) = packet_loop();
    let (icmp_tx, _icmp_rx) = flume::bounded(16);
    let packets = vec![icmp_packet(false), tcp_packet(CLIENT, REMOTE, 1500)];
    let mut io = PacketIo::new(packets, 2, true);
    runner.run(&mut io, NAT, icmp_tx).await;
    assert_eq!(
        io.output,
        vec![
            icmp_packet(true),
            tcp_packet(SocketAddrV4::new(*REMOTE.ip(), CLIENT.port()), NAT, 1500)
        ]
    );
}

#[tokio::test]
async fn cancelled_receive_keeps_its_allocation() {
    let (io, _peer) = tokio::io::duplex(1);
    let (mut reader, _writer) = split(io);
    let mut buffer = BytesMut::with_capacity(MAX_PKT_SIZE);
    let ptr = buffer.as_ptr();
    // This models UDP replies winning select! while the TUN has no input.
    for _ in 0..100 {
        {
            let read = TunPacketLoop::recv_ip(&mut reader, &mut buffer, PREFIX_LEN);
            tokio::pin!(read);
            assert!(futures::poll!(read).is_pending());
        }
        assert_eq!(buffer.as_ptr(), ptr);
        assert!(buffer.is_empty());
        assert!(buffer.capacity() >= MAX_PKT_SIZE);
    }
}

#[tokio::test]
async fn receive_handles_eof_and_invalid_version() {
    let mut invalid = vec![0; PREFIX_LEN + 20];
    invalid[PREFIX_LEN] = 0x70;
    for (packet, kind) in [
        (Bytes::from(invalid), io::ErrorKind::InvalidData),
        (
            Bytes::from(vec![0; PREFIX_LEN]),
            io::ErrorKind::UnexpectedEof,
        ),
    ] {
        let io = PacketIo::new(vec![packet], 1, false);
        let (mut reader, _writer) = split(io);
        let mut buffer = BytesMut::new();
        let result = TunPacketLoop::recv_ip(&mut reader, &mut buffer, PREFIX_LEN).await;
        assert_eq!(result.err().unwrap().kind(), kind);
    }
}

#[tokio::test]
async fn forwarding_returns_the_tcp_allocation() {
    let (runner, _udp_in, _udp_out) = packet_loop();
    let (mut icmp_tx, _icmp_rx) = flume::bounded(16);
    let packet = tcp_packet(CLIENT, REMOTE, 1500);
    let mut buffer = BytesMut::with_capacity(MAX_PKT_SIZE);
    buffer.extend_from_slice(&packet);
    let ptr = buffer.as_ptr();
    let io = PacketIo::new(vec![], 0, false);
    let (_reader, mut writer) = split(io);
    let recycled = runner
        .forwarding_packet(
            IPPkt::from_v4(buffer, PREFIX_LEN),
            &NAT,
            &mut icmp_tx,
            &mut writer,
        )
        .await;
    assert_eq!(recycled.as_ptr(), ptr);
    assert!(recycled.capacity() >= MAX_PKT_SIZE);
}

#[tokio::test]
async fn udp_reply_cancels_idle_read_then_tcp_resumes_on_the_same_io() {
    use crate::network::packet::transport_layer::create_raw_udp_pkt;
    let (runner, udp_in, _udp_out) = packet_loop();
    let (icmp_tx, _icmp_rx) = flume::bounded(16);
    // Exchange one complete packet at a time so the duplex stream supplies the
    // same read boundaries as a TUN. Its capacity holds even the largest packet.
    let (io, mut peer) = tokio::io::duplex(MAX_PKT_SIZE);
    let task = tokio::spawn(async move { runner.run(io, NAT, icmp_tx).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::task::yield_now().await;
        let reply =
            create_raw_udp_pkt(b"UDP reply while TUN is idle", REMOTE.into(), CLIENT.into());
        udp_in.send_async(reply.clone().freeze()).await.unwrap();
        let expected = with_prefix(&reply);
        let mut actual = vec![0; expected.len()];
        peer.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);

        let input = tcp_packet(CLIENT, REMOTE, 1500);
        peer.write_all(&input).await.unwrap();
        let expected = tcp_packet(SocketAddrV4::new(*REMOTE.ip(), CLIENT.port()), NAT, 1500);
        let mut actual = vec![0; expected.len()];
        peer.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        drop(peer);
        task.await.unwrap();
    })
    .await
    .expect("TUN loop stalled when switching between reads and writes");
}

#[cfg(unix)]
#[tokio::test]
async fn tcp_nat_over_real_packet_fd() {
    use crate::common::async_raw_fd::AsyncRawFd;
    use std::os::fd::AsRawFd;

    let (runner, udp_in, _udp_out) = packet_loop();
    let (icmp_tx, _icmp_rx) = flume::bounded(16);
    let (socket, peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let fd = AsyncRawFd::try_from(socket.as_raw_fd()).unwrap();
    peer.set_nonblocking(true).unwrap();
    let peer = tokio::net::UnixDatagram::from_std(peer).unwrap();
    let task = tokio::spawn(async move {
        // AsyncRawFd registers a raw fd without closing it. Keep its owner alive
        // until the packet loop has dropped the readiness registration.
        let _owner = socket;
        runner.run(fd, NAT, icmp_tx).await;
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut response = vec![0; MAX_PKT_SIZE];
        for size in [40, 1500] {
            for (input, expected) in [
                (
                    tcp_packet(CLIENT, REMOTE, size),
                    tcp_packet(SocketAddrV4::new(*REMOTE.ip(), CLIENT.port()), NAT, size),
                ),
                (
                    tcp_packet(NAT, SocketAddrV4::new(*REMOTE.ip(), CLIENT.port()), size),
                    tcp_packet(REMOTE, CLIENT, size),
                ),
            ] {
                assert_eq!(peer.send(&input).await.unwrap(), input.len());
                let len = peer.recv(&mut response).await.unwrap();
                assert_eq!(&response[..len], expected.as_ref());
            }
        }
        drop(udp_in);
        task.await.unwrap();
    })
    .await
    .expect("TUN packet loop stalled on real packet-oriented I/O");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn vnet_tcp_nat_preserves_metadata_and_completes_checksums() {
    let (mut runner, _udp_in, _udp_out) = packet_loop();
    runner.prefix_len = VNET_HEADER_LEN;
    runner
        .session_mgr
        .register_tcp_session(CLIENT.into(), REMOTE.into());
    let (icmp_tx, _icmp_rx) = flume::bounded(16);
    let mut inputs = Vec::new();
    let mut expected = Vec::new();
    for size in [40, 41, 1500, 32768, 65535] {
        for partial in [false, true] {
            for (src, dst, new_src, new_dst) in [
                (
                    CLIENT,
                    REMOTE,
                    SocketAddrV4::new(*REMOTE.ip(), CLIENT.port()),
                    NAT,
                ),
                (
                    NAT,
                    SocketAddrV4::new(*REMOTE.ip(), CLIENT.port()),
                    REMOTE,
                    CLIENT,
                ),
            ] {
                let mut header = [0u8; VNET_HEADER_LEN];
                if partial {
                    header[0] = VNET_NEEDS_CSUM;
                    header[1] = if size > 1500 { 1 } else { 0 }; // TCPv4 GSO
                    header[2..4].copy_from_slice(&40u16.to_ne_bytes());
                    header[4..6].copy_from_slice(&1460u16.to_ne_bytes());
                    header[6..8].copy_from_slice(&20u16.to_ne_bytes());
                    header[8..10].copy_from_slice(&16u16.to_ne_bytes());
                }
                let mut input = BytesMut::from(header.as_slice());
                input.extend_from_slice(&tcp_packet(src, dst, size));
                input[VNET_HEADER_LEN + 36..VNET_HEADER_LEN + 38].fill(0x5a);
                inputs.push(input.freeze());
                expected.push((header, tcp_packet(new_src, new_dst, size)));
            }
        }
    }
    let mut io = PacketIo::new(inputs, expected.len(), true);
    runner.run(&mut io, NAT, icmp_tx).await;
    assert_eq!(io.output.len(), expected.len());
    for (packet, (header, expected)) in io.output.iter().zip(expected) {
        assert_eq!(&packet[..VNET_HEADER_LEN], &header);
        let mut data = packet[VNET_HEADER_LEN..].to_vec();
        if header[0] & VNET_NEEDS_CSUM != 0 {
            let mut sum = 0u32;
            for pair in data[20..].chunks(2) {
                sum += (u32::from(pair[0]) << 8) | u32::from(*pair.get(1).unwrap_or(&0));
                sum = (sum & 0xffff) + (sum >> 16);
            }
            TcpPacket::new_unchecked(&mut data[20..]).set_checksum(!(sum as u16));
        }
        assert_eq!(data, expected);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn vnet_udp_prefix_is_removed_on_receive_and_added_on_reply() {
    use crate::network::packet::transport_layer::create_raw_udp_pkt;
    let (mut runner, udp_in, udp_out) = packet_loop();
    runner.prefix_len = VNET_HEADER_LEN;
    let (icmp_tx, _icmp_rx) = flume::bounded(16);
    let (io, mut peer) = tokio::io::duplex(MAX_PKT_SIZE);
    let task = tokio::spawn(async move { runner.run(io, NAT, icmp_tx).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        // Exercise UDP receive re-arming between TUN reads.
        for size in [1, 1472, 63, 32768] {
            let packet =
                create_raw_udp_pkt(&vec![0x5a; size], CLIENT.into(), REMOTE.into()).freeze();
            let mut wire = vec![0; VNET_HEADER_LEN];
            wire.extend_from_slice(&packet);
            peer.write_all(&wire).await.unwrap();
            assert_eq!(udp_out.recv_async().await.unwrap(), packet);
            udp_in.send_async(packet).await.unwrap();
            let mut actual = vec![0; wire.len()];
            peer.read_exact(&mut actual).await.unwrap();
            assert_eq!(actual, wire);
        }
        drop(peer);
        task.await.unwrap();
    })
    .await
    .expect("offloaded TUN stalled on UDP traffic");
}
