use crate::dispatch::InboundExtra;
use crate::network::dns::{Dns, DnsHijackController};
use crate::network::packet::transport_layer::create_raw_udp_pkt;
use crate::platform::process;
use crate::platform::process::NetworkType;
use crate::proxy::dispatcher::DispatchError;
use crate::proxy::error::TransportError;
use crate::proxy::session_ctl::UdpSessionActivity;
use crate::proxy::{
    ConnTarget, Dispatcher, MappingSessionManager, NetworkAddr, socks_to_network_addr,
};
use boltapi::IdentificationSource;
use bytes::Bytes;
use smoltcp::wire::{Ipv4Packet, Ipv6Packet, UdpPacket};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

struct UdpSession {
    sender: mpsc::Sender<(Bytes, NetworkAddr)>,
    probe: Arc<AtomicBool>,
    activity: UdpSessionActivity,
}

/// Owns one UDP flow once the inbound loop has handed it off.
///
/// Session setup and every per-destination routing decision happen here rather than on
/// the loop shared by all flows: routing can await a genuine DNS lookup for seconds, and
/// that must only delay this flow.
struct UdpSessionTask {
    dispatcher: Arc<Dispatcher>,
    src: SocketAddr,
    first_dst: NetworkAddr,
    probe: Arc<AtomicBool>,
    inbound_rx: mpsc::Receiver<(Bytes, NetworkAddr)>,
}

impl UdpSessionTask {
    async fn run(self, target: ConnTarget, ret_channel: UdpReturnChannel) {
        let Self {
            dispatcher,
            src,
            first_dst,
            probe,
            mut inbound_rx,
        } = self;
        // Walks the whole kernel socket table, so it must stay off the packet loop.
        let proc_info = process::get_pid(src, NetworkType::Udp).map_or(None, |pid| {
            process::get_process_info(pid, dispatcher.process_info_depth)
        });
        let (outbound_tx, outbound_rx) = mpsc::channel(20);

        let submit_result = match ret_channel {
            UdpReturnChannel::Tun(tun_tx) => {
                let (recv_tx, recv_rx) = mpsc::channel(20);
                tokio::spawn(TunUdpInbound::back_prop(recv_rx, tun_tx, src));

                dispatcher
                    .submit_tun_udp_session(
                        src,
                        target,
                        proc_info.clone(),
                        outbound_rx,
                        recv_tx,
                        probe.clone(),
                    )
                    .await
            }
            UdpReturnChannel::Socks(socks_tx, inbound_extra) => {
                dispatcher
                    .submit_socks_udp_session(
                        inbound_extra,
                        src,
                        target,
                        proc_info.clone(),
                        outbound_rx,
                        socks_tx,
                        probe.clone(),
                    )
                    .await
            }
        };

        match submit_result {
            Ok(_) | Err(DispatchError::BlackHole) => {}
            Err(_) => {
                probe.store(false, Ordering::Relaxed);
                return;
            }
        }

        // cache of whether we should allow the connection; submitting the session already
        // routed the first destination.
        let mut remote_permit = HashMap::from([(first_dst, true)]);
        while let Some((payload, dst_addr)) = inbound_rx.recv().await {
            let permit = match remote_permit.get(&dst_addr) {
                Some(permit) => *permit,
                None => {
                    // not an encountered dest, query dispatcher
                    let permit = dispatcher
                        .allow_tun_udp(src, dst_addr.clone(), proc_info.clone())
                        .await;
                    remote_permit.insert(dst_addr.clone(), permit);
                    permit
                }
            };
            if permit && outbound_tx.send((payload, dst_addr)).await.is_err() {
                break;
            }
        }
    }
}

/// Sweep dead sessions out of the mapping once this many have been created. Without it
/// the map is only pruned when another packet happens to arrive from the same port, so a
/// flow that never speaks again would be retained forever.
const SESSION_GC_INTERVAL: usize = 256;

struct UdpInboundInner {
    dispatcher: Arc<Dispatcher>,
    mapping: HashMap<SocketAddr, UdpSession>,
    created_since_gc: usize,
    session_mgr: Arc<MappingSessionManager>,
    dns: Arc<Dns>,
}

enum UdpReturnChannel {
    Tun(flume::Sender<Bytes>),
    Socks(Arc<UdpSocket>, InboundExtra),
}

impl UdpInboundInner {
    /// Hand a packet to the session owning `src`, creating that session if needed.
    ///
    /// Deliberately never awaits: this runs on the loop shared by every UDP flow, so any
    /// wait here delays unrelated traffic, including hijacked DNS answers.
    fn send_payload(
        &mut self,
        src: SocketAddr,
        dst: NetworkAddr,
        payload: Bytes,
        ret_channel: UdpReturnChannel,
    ) -> bool {
        let accepted = dst.clone();
        let (dst_addr, identification) = match dst {
            NetworkAddr::Socket { address: addr } => match self.dns.fake_ip_to_domain(addr.ip()) {
                None => (NetworkAddr::Socket { address: addr }, None),
                Some(name) => (
                    NetworkAddr::Domain {
                        name,
                        port: addr.port(),
                    },
                    Some(IdentificationSource::FakeIpMapping),
                ),
            },
            NetworkAddr::Domain {
                name: domain_name,
                port,
            } => (
                NetworkAddr::Domain {
                    name: domain_name,
                    port,
                },
                None,
            ),
        };
        let handled = match self.mapping.entry(src) {
            Entry::Occupied(entry) => {
                if !entry.get().probe.load(Ordering::Relaxed) {
                    // connection has been invalid
                    entry.remove();
                    false
                } else {
                    // Keep the port off the staleness sweep for as long as it is in use.
                    entry.get().activity.touch();
                    // A session that cannot keep up drops, as UDP allows; blocking here
                    // would stall every other flow behind it.
                    let _ = entry.get().sender.try_send((payload, dst_addr));
                    true
                }
            }
            Entry::Vacant(entry) => {
                let (send_tx, send_rx) = mpsc::channel(20);
                let (probe, activity) = self.session_mgr.register_udp_session(src);

                // push payload
                let _ = send_tx.try_send((payload, dst_addr.clone()));

                // create record for local port
                entry.insert(UdpSession {
                    sender: send_tx,
                    probe: probe.clone(),
                    activity,
                });
                self.created_since_gc += 1;

                let target = match identification {
                    Some(source) => ConnTarget::identified(accepted, dst_addr.clone(), source),
                    None => ConnTarget::from(dst_addr.clone()),
                };
                tokio::spawn(
                    UdpSessionTask {
                        dispatcher: self.dispatcher.clone(),
                        src,
                        first_dst: dst_addr,
                        probe,
                        inbound_rx: send_rx,
                    }
                    .run(target, ret_channel),
                );
                true
            }
        };
        if self.created_since_gc >= SESSION_GC_INTERVAL {
            self.gc();
        }
        handled
    }

    /// Forget sessions whose port has been invalidated or whose task has already exited.
    fn gc(&mut self) {
        self.created_since_gc = 0;
        self.mapping.retain(|_, session| {
            session.probe.load(Ordering::Relaxed) && !session.sender.is_closed()
        });
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
        session_mgr: Arc<MappingSessionManager>,
        dns: Arc<Dns>,
        hijack_ctrl: Arc<DnsHijackController>,
    ) -> Self {
        Self {
            inner: UdpInboundInner {
                dispatcher,
                mapping: Default::default(),
                created_since_gc: 0,
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
            // Must stay non-blocking: flume's `send` parks the whole worker thread when the
            // channel is full, and this channel is only drained by the TUN loop, which may
            // itself be waiting on the forward channel. Drop instead, as UDP allows.
            match tun_tx.try_send(raw_data.freeze()) {
                Ok(()) | Err(flume::TrySendError::Full(_)) => {}
                Err(flume::TrySendError::Disconnected(_)) => {
                    return Err(TransportError::Internal("TUN UDP back channel closed"));
                }
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
                    match self.tun_tx.try_send(raw_data.freeze()) {
                        Ok(()) | Err(flume::TrySendError::Full(_)) => {}
                        Err(flume::TrySendError::Disconnected(_)) => {
                            tracing::error!("TUN back tx closed");
                        }
                    }
                }
            } else {
                // retry once
                if !self.inner.send_payload(
                    src,
                    NetworkAddr::Socket { address: dst },
                    payload.clone(),
                    UdpReturnChannel::Tun(self.tun_tx.clone()),
                ) {
                    self.inner.send_payload(
                        src,
                        NetworkAddr::Socket { address: dst },
                        payload.clone(),
                        UdpReturnChannel::Tun(self.tun_tx.clone()),
                    );
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
        session_mgr: Arc<MappingSessionManager>,
        dns: Arc<Dns>,
        indicator: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner: UdpInboundInner {
                dispatcher,
                mapping: Default::default(),
                created_since_gc: 0,
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
            let dst_addr = socks_to_network_addr(dst_addr);

            if !self.inner.send_payload(
                src_addr,
                dst_addr.clone(),
                payload.clone(),
                UdpReturnChannel::Socks(self.socket.clone(), self.inbound_extra.clone()),
            ) {
                self.inner.send_payload(
                    src_addr,
                    dst_addr,
                    payload.clone(),
                    UdpReturnChannel::Socks(self.socket.clone(), self.inbound_extra.clone()),
                );
            }
        }
    }
}
