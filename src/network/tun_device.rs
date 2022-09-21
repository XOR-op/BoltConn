use crate::network::async_socket::AsyncRawSocket;
use crate::network::route::setup_ipv4_routing_table;
use crate::network::{
    create_v4_raw_socket, errno_err, interface_up, platform, set_address, AsyncRawFd,
};
use crate::packet::ip::IPPkt;
use crate::resource::buf_slab::{PktBufHandle, PktBufPool, MAX_PKT_SIZE};
use crate::session::SessionManager;
use crate::{TcpPkt, TransLayerPkt};
use byteorder::{ByteOrder, NetworkEndian};
use ipnet::Ipv4Net;
use smoltcp::wire;
use smoltcp::wire::IpProtocol;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::raw::c_char;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::{io, mem, slice};
use tokio::io::split;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

pub struct TunDevice {
    fd: Option<AsyncRawFd>,
    ctl_fd: RawFd,
    dev_name: String,
    gw_name: String,
    // (addr, mask)
    addr: Option<Ipv4Net>,
    pool: PktBufPool,
    session_mgr: Arc<SessionManager>,
}

impl TunDevice {
    pub fn open(
        session_mgr: Arc<SessionManager>,
        pool: PktBufPool,
        outbound_iface: &str,
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
                handle.len = <NetworkEndian as ByteOrder>::read_u16(&buffer[2..4]) as usize;
                Ok(IPPkt::from_v4(handle, start_offset))
            }
            6 => {
                handle.len = <NetworkEndian as ByteOrder>::read_u16(&buffer[4..6]) as usize + 40;
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
                let size = outbound.write(pkt.packet_data()).await?;
                tracing::trace!("IPv4 send done: {}", size);
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
        loop {
            // read a ip packet from tun device
            let handle = self.pool.obtain().await;
            let pkt = Self::recv_ip(&mut fd_read, handle).await?;
            if pkt.src_addr().is_ipv6() {
                // not supported now
                continue;
            }
            let (src, dst) = match (pkt.src_addr(), pkt.dst_addr()) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => (src, dst),
                (_, _) => unreachable!(),
            };
            // determine where the packet goes
            match pkt.protocol() {
                IpProtocol::Tcp => {
                    let mut pkt = TcpPkt::new(pkt);
                    tracing::trace!(
                        "[TUN] {}:{} -> {}:{}",
                        src,
                        pkt.src_port(),
                        dst,
                        pkt.dst_port()
                    );
                    if nat_addr == SocketAddrV4::new(src, pkt.src_port()) {
                        // outbound->inbound
                        if let Ok((conn_src, conn_dst, _)) =
                            self.session_mgr.query_tcp_by_token(pkt.dst_port())
                        {
                            pkt.rewrite_addr(conn_dst, conn_src);
                            tracing::trace!(
                                "[TUN] inbound rewrite {} -> {}: {} bytes (SYN={},ACK={},seq={})",
                                conn_dst,
                                conn_src,
                                pkt.packet_payload().len(),
                                pkt.as_tcp_packet().syn(),
                                pkt.as_tcp_packet().ack(),
                                pkt.as_tcp_packet().seq_number()
                            );
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
                        let port = self.session_mgr.query_tcp_by_addr(
                            SocketAddr::V4(SocketAddrV4::new(src, pkt.src_port())),
                            SocketAddr::V4(SocketAddrV4::new(dst, pkt.dst_port())),
                        );
                        // (dst_ip, session_port, nat_ip, nat_port)
                        pkt.rewrite_addr(
                            SocketAddr::from(SocketAddrV4::new(dst, port)),
                            SocketAddr::from(nat_addr),
                        );
                        tracing::trace!(
                            "[TUN] outbound rewrite {} -> {}: {} bytes (SYN={},ACK={},seq={})",
                            SocketAddr::from(SocketAddrV4::new(dst, port)),
                            SocketAddr::from(nat_addr),
                            pkt.packet_payload().len(),
                            pkt.as_tcp_packet().syn(),
                            pkt.as_tcp_packet().ack(),
                            pkt.as_tcp_packet().seq_number()
                        );
                        if let Err(_) = Self::send_ip(&mut fd_write, pkt.ip_pkt()).await {
                            tracing::warn!("Send to NAT failed");
                            continue;
                        }
                    }
                }
                IpProtocol::Udp => {}
                _ => {
                    // discarded
                }
            }
        }
    }
}
