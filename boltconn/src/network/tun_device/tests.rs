use super::*;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{Ipv4Packet, Ipv4Repr, TcpPacket};
use std::hint::black_box;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

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
