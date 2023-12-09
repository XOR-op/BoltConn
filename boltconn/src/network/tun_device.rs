use crate::common::async_raw_fd::AsyncRawFd;
use crate::common::async_socket::AsyncRawSocket;
use crate::common::MAX_PKT_SIZE;
use crate::network;
use crate::network::packet::icmp::Icmpv4Pkt;
use crate::platform;
use crate::platform::{errno_err, interface_up, set_address};
use crate::proxy::SessionManager;
use crate::{TcpPkt, TransLayerPkt, UdpPkt};
use bytes::{BufMut, Bytes, BytesMut};
use ipnet::Ipv4Net;
use network::dns::Dns;
use network::packet::ip::IPPkt;
use smoltcp::wire::IpProtocol;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::IntoRawFd;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

pub struct TunDevice {
    fd: Option<AsyncRawFd>,
    ctl_fd: RawFd,
    dev_name: String,
    gw_name: String,
    // (addr, mask)
    addr: Option<Ipv4Net>,
    session_mgr: Arc<SessionManager>,
    dns_resolver: Arc<Dns>,
    fake_dns_addr: Ipv4Addr,
    udp_tx: flume::Sender<Bytes>,
    udp_rx: flume::Receiver<Bytes>,
}

impl TunDevice {
    pub fn open(
        session_mgr: Arc<SessionManager>,
        outbound_iface: &str,
        dns_resolver: Arc<Dns>,
        fake_dns_addr: Ipv4Addr,
        udp_tx: flume::Sender<Bytes>,
        udp_rx: flume::Receiver<Bytes>,
    ) -> io::Result<TunDevice> {
        let (fd, name) = unsafe { platform::open_tun()? };
        let ctl_fd = {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if fd < 0 {
                return Err(errno_err("Unable to open control fd"));
            }
            fd
        };

        Ok(TunDevice {
            fd: Some(AsyncRawFd::try_from(fd)?),
            ctl_fd,
            dev_name: name,
            gw_name: outbound_iface.parse().unwrap(),
            addr: None,
            session_mgr,
            dns_resolver,
            fake_dns_addr,
            udp_tx,
            udp_rx,
        })
    }

    pub fn get_name(&self) -> &str {
        &self.dev_name
    }

    /// Read a full ip packet from tun device.
    async fn recv_ip(
        receiver: &mut ReadHalf<AsyncRawFd>,
        mut handle: BytesMut,
    ) -> io::Result<IPPkt> {
        // https://stackoverflow.com/questions/17138626/read-on-a-non-blocking-tun-tap-file-descriptor-gets-eagain-error
        // We must read full packet in one syscall, otherwise the remaining part will be discarded.
        // And we are guaranteed to read a full packet when fd is ready.
        let raw_buffer = handle.chunk_mut();
        let len = receiver
            .read(unsafe { core::mem::transmute(raw_buffer.as_uninit_slice_mut()) })
            .await?;
        unsafe { handle.advance_mut(len) };
        // macOS 4 bytes AF_INET/AF_INET6 prefix because of no IFF_NO_PI flag
        #[cfg(target_os = "macos")]
        let start_offset = 4;
        #[cfg(target_os = "linux")]
        let start_offset = 0;
        match handle[start_offset] >> 4 {
            4 => Ok(IPPkt::from_v4(handle, start_offset)),
            6 => Ok(IPPkt::from_v6(handle, start_offset)),
            _ => panic!("Packet is not IPv4 or IPv6"),
        }
    }

    async fn send_ip(sender: &mut WriteHalf<AsyncRawFd>, ip_pkt: &IPPkt) -> io::Result<()> {
        if sender.write(ip_pkt.raw_data()).await? != ip_pkt.raw_data().len() {
            Err(io::Error::new(ErrorKind::Other, "Write partial packet"))
        } else {
            Ok(())
        }
    }

    /// Due to API compatibility of OS, we can only set AF_INET addresses.
    /// See https://man7.org/linux/man-pages/man7/netdevice.7.html
    pub fn set_network_address(&mut self, addr: Ipv4Net) -> io::Result<()> {
        self.addr = Some(addr);
        set_address(self.ctl_fd, self.get_name(), addr)
    }

    pub fn up(&self) -> io::Result<()> {
        if self.addr.is_none() {
            return Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                "No available address to up iface",
            ));
        }
        interface_up(self.ctl_fd, self.get_name())?;
        tracing::event!(
            tracing::Level::INFO,
            "TUN Device {} is up.",
            self.get_name()
        );
        Ok(())
    }

    async fn send_outbound(&mut self, pkt: &IPPkt) -> io::Result<()> {
        match pkt {
            IPPkt::V4(_) => {
                let fd = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
                )?
                .into_raw_fd();
                platform::bind_to_device(fd, self.gw_name.as_str()).map_err(|e| {
                    io::Error::new(ErrorKind::Other, format!("Bind to device failed, {}", e))
                })?;
                let mut outbound = AsyncRawSocket::create(
                    fd,
                    match pkt.dst_addr() {
                        IpAddr::V4(addr) => addr,
                        _ => unreachable!(),
                    },
                )?;
                let _ = outbound.write(pkt.packet_data()).await?;
            }
            _ => {
                tracing::debug!("Drop IPv6 send");
                // Since we did not configure v6 route, we just ignore them (although some are broadcast).
            }
        }
        Ok(())
    }

    pub async fn run(mut self, nat_addr: SocketAddr) -> io::Result<()> {
        let nat_addr = if let SocketAddr::V4(addr) = nat_addr {
            addr
        } else {
            panic!("v6 nat not supported")
        };
        let (mut fd_read, mut fd_write) = split(self.fd.take().unwrap());
        tracing::info!("[TUN] Running...");
        loop {
            // read a ip packet from tun device
            let handle = BytesMut::with_capacity(MAX_PKT_SIZE);
            tokio::select! {
                pkt = Self::recv_ip(&mut fd_read, handle) => {
                    let pkt = pkt?;
                    self.forwarding_packet(pkt, &nat_addr, &mut fd_write).await;
                }
                data = self.udp_rx.recv_async() => {
                    if let Ok(data) = data{
                        Self::backwarding_udp_v4(data, &mut fd_write).await;
                    }
                }
            }
        }
    }

    async fn backwarding_udp_v4(packet: Bytes, fd_write: &mut WriteHalf<AsyncRawFd>) {
        #[cfg(target_os = "linux")]
        let _ = fd_write.write_all(packet.as_ref()).await;
        #[cfg(target_os = "macos")]
        {
            // Warning: cannot use vectored write here
            let mut unified_buf = vec![0, 0, 0, libc::AF_INET as u8];
            unified_buf.extend_from_slice(packet.as_ref());
            let _ = fd_write.write_all(unified_buf.as_ref()).await;
        }
    }

    async fn forwarding_packet(
        &self,
        pkt: IPPkt,
        nat_addr: &SocketAddrV4,
        fd_write: &mut WriteHalf<AsyncRawFd>,
    ) {
        if pkt.src_addr().is_ipv6() {
            // todo: not supported now
            return;
        }
        let (src, dst) = match (pkt.src_addr(), pkt.dst_addr()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => (src, dst),
            (_, _) => unreachable!(),
        };
        // determine where the packet goes
        match pkt.protocol() {
            IpProtocol::Tcp => {
                let mut pkt = TcpPkt::new(pkt);
                if *nat_addr == SocketAddrV4::new(src, pkt.src_port()) {
                    // outbound->inbound
                    if let Ok((conn_src, conn_dst, _)) =
                        self.session_mgr.lookup_tcp_session(pkt.dst_port())
                    {
                        pkt.rewrite_addr(conn_dst, conn_src);
                        if Self::send_ip(fd_write, pkt.ip_pkt()).await.is_err() {
                            tracing::warn!("Send to NAT failed");
                        }
                    } else {
                        tracing::warn!("No record found for {}", pkt.dst_port());
                    }
                } else {
                    // inbound->outbound
                    let inbound_port = self.session_mgr.register_tcp_session(
                        SocketAddr::V4(SocketAddrV4::new(src, pkt.src_port())),
                        SocketAddr::V4(SocketAddrV4::new(dst, pkt.dst_port())),
                    );
                    // (_, session_port, nat_ip, nat_port)
                    pkt.rewrite_addr(
                        SocketAddr::from(SocketAddrV4::new(dst, inbound_port)),
                        SocketAddr::from(*nat_addr),
                    );
                    if Self::send_ip(fd_write, pkt.ip_pkt()).await.is_err() {
                        tracing::warn!("Send to NAT failed");
                    }
                }
            }
            IpProtocol::Udp => {
                let pkt = UdpPkt::new(pkt);
                if pkt.dst_port() == 53 && dst == self.fake_dns_addr {
                    // fake ip
                    if let Ok(answer) = self.dns_resolver.respond_to_query(pkt.packet_payload()) {
                        let mut new_pkt = pkt.set_payload(answer.as_slice());
                        new_pkt.rewrite_addr(
                            SocketAddr::new(IpAddr::from(dst), new_pkt.dst_port()),
                            SocketAddr::new(IpAddr::from(src), new_pkt.src_port()),
                        );
                        let _ = Self::send_ip(fd_write, new_pkt.ip_pkt()).await;
                    }
                } else {
                    let pkt = {
                        #[cfg(target_os = "macos")]
                        let start_offset = 4;
                        #[cfg(target_os = "linux")]
                        let start_offset = 0;
                        pkt.into_bytes_mut().freeze().slice(start_offset..)
                    };
                    let _ = self.udp_tx.send(pkt);
                }
            }
            IpProtocol::Icmp => {
                // just echo now
                let mut pkt = Icmpv4Pkt::new(pkt);
                pkt.rewrite_addr(dst, src);
                let _ = Self::send_ip(fd_write, pkt.ip_pkt()).await;
            }
            _ => {
                tracing::debug!("[TUN] {} packet: {} -> {}", pkt.protocol(), src, dst);
                // discarded
            }
        }
    }
}
