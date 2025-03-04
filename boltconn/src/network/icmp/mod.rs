use crate::network::packet::icmp::Icmpv4Pkt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use tokio::net::UdpSocket;

pub struct IcmpProxy {
    tun_addr: Ipv4Addr,
    socket: UdpSocket,
    tun_rx: flume::Receiver<Icmpv4Pkt>,
}

impl IcmpProxy {
    pub fn new(
        tun_addr: Ipv4Addr,
        outbound_iface: &str,
        tun_rx: flume::Receiver<Icmpv4Pkt>,
    ) -> io::Result<Self> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            if cfg!(target_os = "linux") {
                socket2::Type::RAW
            } else {
                socket2::Type::DGRAM
            },
            Some(socket2::Protocol::ICMPV4),
        )
        .map_err(|e| {
            tracing::warn!("socket: {e}");
            e
        })?;
        socket.set_nonblocking(true)?;
        #[cfg(not(target_os = "windows"))]
        crate::platform::bind_to_device(socket.as_raw_fd(), outbound_iface)?;
        #[cfg(target_os = "windows")]
        {
            use crate::common::io_err;
            use crate::platform::get_iface_address;
            let IpAddr::V4(local_addr) = get_iface_address(outbound_iface)? else {
                return Err(io_err("not ipv4"));
            };
            socket.bind(&SocketAddr::new(local_addr.into(), 0).into())?;
        }
        let socket = UdpSocket::from_std(socket.into())?;
        Ok(Self {
            tun_addr,
            socket,
            tun_rx,
        })
    }

    pub async fn run(mut self) {
        while let Ok(pkt) = self.tun_rx.recv_async().await {
            self.handle_request(pkt).await;
        }
    }

    // drop the packet if anything goes wrong
    async fn handle_request(&mut self, icmp_pkt: Icmpv4Pkt) {
        if icmp_pkt.is_echo_request() {
            let _ = self
                .socket
                .send_to(
                    icmp_pkt.ip_pkt().packet_payload(),
                    SocketAddr::new(icmp_pkt.ip_pkt().dst_addr(), 0),
                )
                .await;
        }
    }
}
