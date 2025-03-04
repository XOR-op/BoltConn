use crate::common::MAX_PKT_SIZE;
use crate::network;
use crate::network::packet::icmp::Icmpv4Pkt;
use crate::network::TunInstance;
use crate::proxy::SessionManager;
use crate::{TcpPkt, TransLayerPkt, UdpPkt};
use bytes::{BufMut, Bytes, BytesMut};
use ipnet::Ipv4Net;
use network::packet::ip::IPPkt;
use smoltcp::wire::IpProtocol;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

pub struct TunDevice {
    inner: TunInstance,
    dev_name: String,
    gw_name: String,
    // (addr, mask)
    addr: Option<Ipv4Net>,
    session_mgr: Arc<SessionManager>,
    udp_tx: flume::Sender<Bytes>,
    udp_rx: flume::Receiver<Bytes>,
    ipv6_enabled: bool,
}

impl TunDevice {
    pub fn open(
        session_mgr: Arc<SessionManager>,
        outbound_iface: &str,
        udp_tx: flume::Sender<Bytes>,
        udp_rx: flume::Receiver<Bytes>,
        ipv6_enabled: bool,
    ) -> io::Result<TunDevice> {
        let (inner, name) = TunInstance::new()?;
        Ok(TunDevice {
            inner,
            dev_name: name,
            gw_name: outbound_iface.parse().unwrap(),
            addr: None,
            session_mgr,
            udp_tx,
            udp_rx,
            ipv6_enabled,
        })
    }

    pub fn get_name(&self) -> &str {
        &self.dev_name
    }

    /// Read a full ip packet from tun device.
    async fn recv_ip<T: AsyncRead>(
        receiver: &mut ReadHalf<T>,
        mut handle: BytesMut,
    ) -> io::Result<IPPkt> {
        // https://stackoverflow.com/questions/17138626/read-on-a-non-blocking-tun-tap-file-descriptor-gets-eagain-error
        // We must read full packet in one syscall, otherwise the remaining part will be discarded.
        // And we are guaranteed to read a full packet when fd is ready.
        let raw_buffer = handle.chunk_mut();
        let len = receiver
            .read(unsafe {
                core::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(
                    raw_buffer.as_uninit_slice_mut(),
                )
            })
            .await?;
        unsafe { handle.advance_mut(len) };
        // macOS 4 bytes AF_INET/AF_INET6 prefix because of no IFF_NO_PI flag
        #[cfg(target_os = "macos")]
        let start_offset = 4;
        #[cfg(not(target_os = "macos"))]
        let start_offset = 0;
        match handle[start_offset] >> 4 {
            4 => Ok(IPPkt::from_v4(handle, start_offset)),
            6 => Ok(IPPkt::from_v6(handle, start_offset)),
            _ => panic!("Packet is not IPv4 or IPv6"),
        }
    }

    async fn send_ip<T: AsyncWrite>(sender: &mut WriteHalf<T>, ip_pkt: &IPPkt) -> io::Result<()> {
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
        self.inner.set_address(self.get_name(), addr)
    }

    pub fn up(&self) -> io::Result<()> {
        if self.addr.is_none() {
            return Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                "No available address to up iface",
            ));
        }
        self.inner.interface_up(self.get_name())?;
        tracing::event!(
            tracing::Level::INFO,
            "TUN Device {} is up.",
            self.get_name()
        );
        Ok(())
    }

    // async fn send_outbound(&self, pkt: &IPPkt) -> io::Result<()> {
    //     TunInstance::send_outbound(pkt, self.gw_name.as_str(), self.ipv6_enabled).await
    // }

    pub async fn run(mut self, nat_addr: SocketAddr) -> io::Result<()> {
        let nat_addr = if let SocketAddr::V4(addr) = nat_addr {
            addr
        } else {
            panic!("v6 nat not supported")
        };
        let (mut fd_read, mut fd_write) = split(self.inner.take_fd().unwrap());
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

    async fn backwarding_udp_v4<T: AsyncWrite>(packet: Bytes, fd_write: &mut WriteHalf<T>) {
        #[cfg(not(target_os = "macos"))]
        let _ = fd_write.write_all(packet.as_ref()).await;
        #[cfg(target_os = "macos")]
        {
            // Warning: cannot use vectored write here
            let mut unified_buf = vec![0, 0, 0, libc::AF_INET as u8];
            unified_buf.extend_from_slice(packet.as_ref());
            let _ = fd_write.write_all(unified_buf.as_ref()).await;
        }
    }

    async fn forwarding_packet<T: AsyncWrite>(
        &self,
        pkt: IPPkt,
        nat_addr: &SocketAddrV4,
        fd_write: &mut WriteHalf<T>,
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
                    if let Ok((conn_src, conn_dst, _)) = self
                        .session_mgr
                        .lookup_tcp_session(pkt.ip_pkt().src_addr().is_ipv6(), pkt.dst_port())
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
                if pkt.pkt_total_len() < pkt.ip_header_len() + 8 {
                    // drop invalid UDP packet
                    return;
                }
                let pkt = UdpPkt::new(pkt);
                let pkt = {
                    #[cfg(target_os = "macos")]
                    let start_offset = 4;
                    #[cfg(not(target_os = "macos"))]
                    let start_offset = 0;
                    pkt.into_bytes_mut().freeze().slice(start_offset..)
                };
                let _ = self.udp_tx.send_async(pkt).await;
                // }
            }
            IpProtocol::Icmp => {
                // just echo now
                let mut pkt = Icmpv4Pkt::new(pkt);
                if pkt.is_echo_request() {
                    pkt.rewrite_addr(dst, src);
                    pkt.set_as_reply();
                    let _ = Self::send_ip(fd_write, pkt.ip_pkt()).await;
                }
            }
            _ => {
                // discarded
            }
        }
    }
}
