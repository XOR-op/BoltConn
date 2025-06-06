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
use tokio::sync::mpsc;

struct UdpSession {
    local_addr: SocketAddr,
    proc_info: Option<ProcessInfo>,
    // cache of whether we should allow the connection
    remote_permit: HashMap<NetworkAddr, bool>,
    sender: mpsc::Sender<(Bytes, NetworkAddr)>,
    probe: Arc<AtomicBool>,
}

pub struct TunUdpInbound {
    pkt_chan: flume::Receiver<Bytes>,
    tun_tx: flume::Sender<Bytes>,
    dispatcher: Arc<Dispatcher>,
    mapping: HashMap<SocketAddr, UdpSession>,
    session_mgr: Arc<SessionManager>,
    dns: Arc<Dns>,
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
            pkt_chan,
            tun_tx,
            dispatcher,
            mapping: Default::default(),
            session_mgr,
            dns,
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
                if let Ok(answer) = self.dns.respond_to_query(payload.as_ref()) {
                    let raw_data = create_raw_udp_pkt(answer.as_ref(), dst, src);
                    if self.tun_tx.send_async(raw_data.freeze()).await.is_err() {
                        tracing::error!("TUN back tx closed");
                    }
                }
            } else {
                // retry once
                if !self.send_payload(src, dst, payload.clone()).await {
                    self.send_payload(src, dst, payload.clone()).await;
                }
            }
        }
    }

    async fn send_payload(&mut self, src: SocketAddr, dst: SocketAddr, payload: Bytes) -> bool {
        let dst_addr = match self.dns.fake_ip_to_domain(dst.ip()) {
            None => NetworkAddr::Raw(dst),
            Some(s) => NetworkAddr::DomainName {
                domain_name: s,
                port: dst.port(),
            },
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
                let (recv_tx, recv_rx) = mpsc::channel(20);
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

                let tun_tx = self.tun_tx.clone();
                tokio::spawn(Self::back_prop(recv_rx, tun_tx, src));

                match self
                    .dispatcher
                    .submit_tun_udp_session(
                        src,
                        dst_addr,
                        proc_info,
                        send_rx,
                        recv_tx,
                        probe.clone(),
                    )
                    .await
                {
                    Ok(_) | Err(DispatchError::BlackHole) => {}
                    Err(_) => probe.store(false, Ordering::Relaxed),
                }
                true
            }
        }
    }
}
