use crate::common::async_raw_fd;
use crate::common::async_raw_fd::AsyncRawFd;
use crate::common::async_socket::AsyncRawSocket;
use crate::common::buf_pool::{PktBufHandle, PktBufPool};
use crate::network;
use crate::platform;
use crate::platform::route::setup_ipv4_routing_table;
use crate::platform::{create_v4_raw_socket, errno_err, interface_up, set_address};
use crate::session::SessionManager;
use crate::{TcpPkt, TransLayerPkt, UdpPkt};
use byteorder::{ByteOrder, NetworkEndian};
use ipnet::Ipv4Net;
use network::dns::Dns;
use network::packet::ip::IPPkt;
use smoltcp::wire::IpProtocol;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::raw::c_char;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

pub struct TunDevice {
    fd: Option<AsyncRawFd>,
    ctl_fd: RawFd,
    dev_name: String,
    gw_name: String,
    // (addr, mask)
    addr: Option<Ipv4Net>,
    pool: PktBufPool,
    session_mgr: Arc<SessionManager>,
    dns_resolver: Arc<Dns>,
}

impl TunDevice {
    pub fn open(
        session_mgr: Arc<SessionManager>,
        pool: PktBufPool,
        outbound_iface: &str,
        dns_resolver: Arc<Dns>,
    ) -> io::Result<TunDevice> {
        let mut name_buffer: Vec<c_char> = Vec::new();
        name_buffer.resize(36, 0);

        let (fd, name) = unsafe { platform::open_tun()? };
        let ctl_fd = {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if fd < 0 {
                return Err(errno_err("Unable to open control fd").into());
            }
            fd
        };

        Ok(TunDevice {
            fd: Some(AsyncRawFd::try_from(RawFd::from(fd))?),
            ctl_fd,
            dev_name: name,
            gw_name: outbound_iface.parse().unwrap(),
            addr: None,
            pool,
            session_mgr,
            dns_resolver,
        })
    }

    pub fn get_name(&self) -> &str {
        &self.dev_name
    }

    /// Read a full ip packet from tun device.
    async fn recv_ip(
        receiver: &mut ReadHalf<AsyncRawFd>,
        mut handle: PktBufHandle,
    ) -> io::Result<IPPkt> {
        // https://stackoverflow.com/questions/17138626/read-on-a-non-blocking-tun-tap-file-descriptor-gets-eagain-error
        // We must read full packet in one syscall, otherwise the remaining part will be discarded.
        // And we are guaranteed to read a full packet when fd is ready.
        let raw_buffer = &mut handle.data;
        receiver.read(raw_buffer.as_mut_slice()).await?;
        // macOS 4 bytes AF_INET/AF_INET6 prefix because of no IFF_NO_PI flag
        #[cfg(target_os = "macos")]
        let start_offset = 4;
        #[cfg(target_os = "linux")]
        let start_offset = 0;
        let buffer = &raw_buffer[start_offset..];
        match buffer[0] >> 4 {
            4 => {
                handle.len =
                    <NetworkEndian as ByteOrder>::read_u16(&buffer[2..4]) as usize + start_offset;
                Ok(IPPkt::from_v4(handle, start_offset))
            }
            6 => {
                handle.len = <NetworkEndian as ByteOrder>::read_u16(&buffer[4..6]) as usize
                    + 40
                    + start_offset;
                Ok(IPPkt::from_v6(handle, start_offset))
            }
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
        setup_ipv4_routing_table(self.get_name())?;
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
                let fd = unsafe { create_v4_raw_socket()? };
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
                // tracing::trace!("IPv4 send done: {}", size);
            }
            _ => {
                tracing::trace!("Drop IPv6 send");
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
            // todo: do we really need a pool here?
            let handle = self.pool.obtain().await;
            let pkt = Self::recv_ip(&mut fd_read, handle).await?;
            if pkt.src_addr().is_ipv6() {
                // not supported now
                // tracing::trace!("[TUN] drop IPv6: {} -> {} ", pkt.src_addr(), pkt.dst_addr());
                continue;
            }
            let (src, dst) = match (pkt.src_addr(), pkt.dst_addr()) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => (src, dst),
                (_, _) => unreachable!(),
            };
            // determine where the packet goes
            match pkt.protocol() {
                IpProtocol::Tcp => {
                    let pkt = TcpPkt::new(pkt);
                    let mut pkt = scopeguard::guard(pkt, |p| self.pool.release(p.into_handle()));
                    // tracing::trace!(
                    //     "[TUN] {}:{} -> {}:{}",
                    //     src,
                    //     pkt.src_port(),
                    //     dst,
                    //     pkt.dst_port()
                    // );
                    if nat_addr == SocketAddrV4::new(src, pkt.src_port()) {
                        // outbound->inbound
                        if let Ok((conn_src, conn_dst, _)) =
                            self.session_mgr.lookup_session(pkt.dst_port())
                        {
                            pkt.rewrite_addr(conn_dst, conn_src);
                            // tracing::trace!(
                            //     "[TUN] inbound rewrite {} -> {}: {} bytes (SYN={},ACK={},seq={})",
                            //     conn_dst,
                            //     conn_src,
                            //     pkt.packet_payload().len(),
                            //     pkt.as_tcp_packet().syn(),
                            //     pkt.as_tcp_packet().ack(),
                            //     pkt.as_tcp_packet().seq_number()
                            // );
                            if let Err(_) = Self::send_ip(&mut fd_write, pkt.ip_pkt()).await {
                                tracing::warn!("Send to NAT failed");
                                continue;
                            }
                        } else {
                            tracing::warn!("No record found for {}", pkt.dst_port());
                            continue;
                        }
                    } else {
                        // inbound->outbound
                        let inbound_port = self.session_mgr.register_session(
                            SocketAddr::V4(SocketAddrV4::new(src, pkt.src_port())),
                            SocketAddr::V4(SocketAddrV4::new(dst, pkt.dst_port())),
                        );
                        // (_, session_port, nat_ip, nat_port)
                        pkt.rewrite_addr(
                            SocketAddr::from(SocketAddrV4::new(dst, inbound_port)),
                            SocketAddr::from(nat_addr),
                        );
                        // tracing::trace!(
                        //     "[TUN] outbound rewrite {} -> {}: {} bytes (SYN={},ACK={},seq={})",
                        //     SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(254,254,254,254), inbound_port)),
                        //     SocketAddr::from(nat_addr),
                        //     pkt.packet_payload().len(),
                        //     pkt.as_tcp_packet().syn(),
                        //     pkt.as_tcp_packet().ack(),
                        //     pkt.as_tcp_packet().seq_number()
                        // );
                        if let Err(_) = Self::send_ip(&mut fd_write, pkt.ip_pkt()).await {
                            tracing::warn!("Send to NAT failed");
                            continue;
                        }
                    }
                }
                IpProtocol::Udp => {
                    let pkt = UdpPkt::new(pkt);
                    // tracing::trace!(
                    //     "[TUN] UDP packet: {}:{} -> {}:{}",
                    //     src,
                    //     pkt.src_port(),
                    //     dst,
                    //     pkt.dst_port()
                    // );
                    if pkt.dst_port() == 53 {
                        // fake ip
                        if let Ok(answer) = self.dns_resolver.respond_to_query(pkt.packet_payload())
                        {
                            let mut new_pkt = pkt.set_payload(answer.as_slice());
                            new_pkt.rewrite_addr(
                                SocketAddr::new(IpAddr::from(dst), new_pkt.dst_port()),
                                SocketAddr::new(IpAddr::from(src), new_pkt.src_port()),
                            );
                            let _ = Self::send_ip(&mut fd_write, new_pkt.ip_pkt()).await;
                            self.pool.release(new_pkt.into_handle());
                        } else {
                            // tracing::warn!("Not valid DNS query");
                            self.pool.release(pkt.into_handle());
                        }
                    } else {
                        let _ = Self::send_ip(&mut fd_write, pkt.ip_pkt()).await;
                        self.pool.release(pkt.into_handle());
                    }
                }
                _ => {
                    tracing::trace!("[TUN] {} packet: {} -> {}", pkt.protocol(), src, dst);
                    // discarded
                }
            }
        }
    }
}
