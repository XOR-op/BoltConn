use crate::dispatch::InboundExtra;
use crate::network::dns::{Dns, DnsHijackController};
use crate::network::packet::transport_layer::create_raw_udp_pkt;
use crate::platform::process;
use crate::platform::process::{NetworkType, ProcessInfo};
use crate::proxy::dispatcher::DispatchError;
use crate::proxy::error::TransportError;
use crate::proxy::{Dispatcher, NetworkAddr, SessionManager};
use bytes::Bytes;
use smoltcp::wire::{Ipv4Packet, Ipv6Packet, UdpPacket};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

struct UdpSession {
    local_addr: SocketAddr,
    proc_info: Option<ProcessInfo>,
    // cache of whether we should allow the connection
    remote_permit: HashMap<NetworkAddr, bool>,
    sender: mpsc::Sender<(Bytes, NetworkAddr)>,
    probe: Arc<AtomicBool>,
}

struct UdpInboundInner {
    dispatcher: Arc<Dispatcher>,
    mapping: HashMap<SocketAddr, UdpSession>,
    session_mgr: Arc<SessionManager>,
    dns: Arc<Dns>,
}

enum UdpReturnChannel {
    Tun(flume::Sender<Bytes>),
    Socks(Arc<UdpSocket>, InboundExtra),
}

impl UdpInboundInner {
    async fn send_payload(
        &mut self,
        src: SocketAddr,
        dst: NetworkAddr,
        payload: Bytes,
        ret_channel: UdpReturnChannel,
    ) -> bool {
        let dst_addr = match dst {
            NetworkAddr::Raw(addr) => match self.dns.fake_ip_to_domain(addr.ip()) {
                None => NetworkAddr::Raw(addr),
                Some(s) => NetworkAddr::DomainName {
                    domain_name: s,
                    port: dst.port(),
                },
            },
            NetworkAddr::DomainName { domain_name, port } => {
                NetworkAddr::DomainName { domain_name, port }
            }
        };

        match self.mapping.entry(src) {
            Entry::Occupied(mut entry) => {
                if !entry.get().probe.load(Ordering::Relaxed) {
                    // connection has been invalid
                    entry.remove();
                    false
                } else {
                    let session = entry.get_mut();
                    if let Some(premit) = session.remote_permit.get(&dst_addr) {
                        if *premit {
                            let _ = session.sender.send((payload, dst_addr)).await;
                        }
                    } else {
                        // not an encountered dest, query dispatcher
                        let permit = self
                            .dispatcher
                            .allow_tun_udp(src, dst_addr.clone(), session.proc_info.clone())
                            .await;
                        session.remote_permit.insert(dst_addr.clone(), permit);
                        if permit {
                            let _ = session.sender.send((payload, dst_addr)).await;
                        }
                    }
                    true
                }
            }
            Entry::Vacant(entry) => {
                let (send_tx, send_rx) = mpsc::channel(20);
                let proc_info =
                    process::get_pid(src, NetworkType::Udp).map_or(None, process::get_process_info);
                let probe = self.session_mgr.get_udp_probe(src);

                // push payload
                let _ = send_tx.send((payload, dst_addr.clone())).await;

                // create record for local port
                let session = UdpSession {
                    local_addr: src,
                    proc_info: proc_info.clone(),
                    remote_permit: Default::default(),
                    sender: send_tx,
                    probe: probe.clone(),
                };
                entry.insert(session);

                let submit_result = match ret_channel {
                    UdpReturnChannel::Tun(tun_tx) => {
                        let (recv_tx, recv_rx) = mpsc::channel(20);
                        tokio::spawn(TunUdpInbound::back_prop(recv_rx, tun_tx, src));

                        self.dispatcher
                            .submit_tun_udp_session(
                                src,
                                dst_addr,
                                proc_info,
                                send_rx,
                                recv_tx,
                                probe.clone(),
                            )
                            .await
                    }
                    UdpReturnChannel::Socks(socks_tx, inbound_extra) => {
                        self.dispatcher
                            .submit_socks_udp_session(
                                inbound_extra,
                                src,
                                dst_addr,
                                proc_info,
                                send_rx,
                                socks_tx,
                                probe.clone(),
                            )
                            .await
                    }
                };

                match submit_result {
                    Ok(_) | Err(DispatchError::BlackHole) => {}
                    Err(_) => probe.store(false, Ordering::Relaxed),
                }
                true
            }
        }
    }
}

pub struct TunUdpInbound {
    inner: UdpInboundInner,
    pkt_chan: flume::Receiver<Bytes>,
    tun_tx: flume::Sender<Bytes>,
    dns_hijack_ctrl: Arc<DnsHijackController>,
}

impl TunUdpInbound {
    pub fn new(
        pkt_chan: flume::Receiver<Bytes>,
        tun_tx: flume::Sender<Bytes>,
        dispatcher: Arc<Dispatcher>,
        session_mgr: Arc<SessionManager>,
        dns: Arc<Dns>,
        hijack_ctrl: Arc<DnsHijackController>,
    ) -> Self {
        Self {
            inner: UdpInboundInner {
                dispatcher,
                mapping: Default::default(),
                session_mgr,
                dns,
            },
            pkt_chan,
            tun_tx,
            dns_hijack_ctrl: hijack_ctrl,
        }
    }

    async fn back_prop(
        mut back_chan: mpsc::Receiver<(Bytes, SocketAddr)>,
        tun_tx: flume::Sender<Bytes>,
        dst: SocketAddr,
    ) -> Result<(), TransportError> {
        while let Some((data, src)) = back_chan.recv().await {
            let raw_data = create_raw_udp_pkt(data.as_ref(), src, dst);
            if !tun_tx.is_full() {
                tun_tx
                    .send(raw_data.freeze())
                    .map_err(|_| TransportError::Internal("TUN UDP back channel full"))?;
            }
        }
        Ok(())
    }

    fn extract_addr(data: &[u8]) -> (SocketAddr, SocketAddr, usize) {
        let version = data[0] >> 4;
        let udp_hdr = 8;
        match version {
            4 => {
                let ip_pkt = Ipv4Packet::new_unchecked(data);
                let header_len = ip_pkt.header_len() as usize + udp_hdr;
                let src = ip_pkt.src_addr();
                let dst = ip_pkt.dst_addr();
                let udp_pkt = UdpPacket::new_unchecked(ip_pkt.payload());
                (
                    SocketAddrV4::new(src, udp_pkt.src_port()).into(),
                    SocketAddrV4::new(dst, udp_pkt.dst_port()).into(),
                    header_len,
                )
            }
            6 => {
                let ip_pkt = Ipv6Packet::new_unchecked(data);
                let header_len = ip_pkt.header_len() + udp_hdr;
                let src = ip_pkt.src_addr();
                let dst = ip_pkt.dst_addr();
                let udp_pkt = UdpPacket::new_unchecked(ip_pkt.payload());
                (
                    SocketAddrV6::new(src, udp_pkt.src_port(), 0, 0).into(),
                    SocketAddrV6::new(dst, udp_pkt.dst_port(), 0, 0).into(),
                    header_len,
                )
            }
            _ => unreachable!(),
        }
    }

    pub async fn run(mut self) {
        while let Ok(data) = self.pkt_chan.recv_async().await {
            let (src, dst, offset) = Self::extract_addr(data.as_ref());
            let payload = data.slice(offset..);
            if self.dns_hijack_ctrl.should_hijack(&dst) {
                // hijack dns
                if let Ok(answer) = self.inner.dns.respond_to_query(payload.as_ref()) {
                    let raw_data = create_raw_udp_pkt(answer.as_ref(), dst, src);
                    if self.tun_tx.send_async(raw_data.freeze()).await.is_err() {
                        tracing::error!("TUN back tx closed");
                    }
                }
            } else {
                // retry once
                if !self
                    .inner
                    .send_payload(
                        src,
                        NetworkAddr::Raw(dst),
                        payload.clone(),
                        UdpReturnChannel::Tun(self.tun_tx.clone()),
                    )
                    .await
                {
                    self.inner
                        .send_payload(
                            src,
                            NetworkAddr::Raw(dst),
                            payload.clone(),
                            UdpReturnChannel::Tun(self.tun_tx.clone()),
                        )
                        .await;
                }
            }
        }
    }
}

pub struct SocksUdpInbound {
    inner: UdpInboundInner,
    src_addr: SocketAddr,
    inbound_extra: InboundExtra,
    socket: Arc<UdpSocket>,
    indicator: Arc<AtomicBool>,
}

impl SocksUdpInbound {
    pub fn new(
        socket: Arc<UdpSocket>,
        src_addr: SocketAddr,
        inbound_extra: InboundExtra,
        dispatcher: Arc<Dispatcher>,
        session_mgr: Arc<SessionManager>,
        dns: Arc<Dns>,
        indicator: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner: UdpInboundInner {
                dispatcher,
                mapping: Default::default(),
                session_mgr,
                dns,
            },
            src_addr,
            inbound_extra,
            socket,
            indicator,
        }
    }

    pub async fn run(mut self) {
        let mut buf = vec![0u8; 65535];
        while self.indicator.load(Ordering::Relaxed) {
            let Ok((len, src_addr)) = self.socket.recv_from(&mut buf).await else {
                break;
            };
            let Ok((frag, dst_addr, payload)) = fast_socks5::parse_udp_request(&buf[..len]).await
            else {
                continue;
            };
            if frag != 0 {
                // cannot handle, drop
                continue;
            }
            let payload = Bytes::copy_from_slice(payload);
            let dst_addr: NetworkAddr = dst_addr.into();

            if !self
                .inner
                .send_payload(
                    src_addr,
                    dst_addr.clone(),
                    payload.clone(),
                    UdpReturnChannel::Socks(self.socket.clone(), self.inbound_extra.clone()),
                )
                .await
            {
                self.inner
                    .send_payload(
                        src_addr,
                        dst_addr,
                        payload.clone(),
                        UdpReturnChannel::Socks(self.socket.clone(), self.inbound_extra.clone()),
                    )
                    .await;
            }
        }
    }
}
