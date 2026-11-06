use crate::common::{MAX_PKT_SIZE, MAX_UDP_PKT_SIZE, io_err, local_async_run};
use crate::config::DnsPreference;
use crate::proxy::NetworkAddr;
use crate::proxy::error::TransportError;
use crate::transport::smol::IpPacketBatch;
use crate::transport::{AdapterOrSocket, UdpSocketAdapter};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use bytes::{Bytes, BytesMut};
use hickory_resolver::config::ResolverConfig;
use sharded_slab::Pool;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::io;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

// We left AllowedIPs since it's boltconn that manages routing.
#[derive(Clone)]
pub struct WireguardConfig {
    pub name: String,
    // local
    pub ip_addr: Option<Ipv4Addr>,
    pub ip_addr6: Option<Ipv6Addr>,
    pub private_key: x25519_dalek::StaticSecret,
    // peer
    pub public_key: x25519_dalek::PublicKey,
    pub endpoint: NetworkAddr,
    pub mtu: usize,
    pub preshared_key: Option<[u8; 32]>,
    pub keepalive: Option<u16>,
    pub dns: ResolverConfig,
    pub dns_preference: DnsPreference,
    // reserved fields
    pub reserved: Option<[u8; 3]>,
    pub over_tcp: bool,
}

impl Debug for WireguardConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("")
            .field(&self.name)
            .field(&self.ip_addr)
            .field(&self.ip_addr6)
            .field(&self.endpoint)
            .field(&self.preshared_key)
            .finish()
    }
}

impl PartialEq for WireguardConfig {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.public_key == other.public_key
            && self.ip_addr == other.ip_addr
            && self.ip_addr6 == other.ip_addr6
            && self.endpoint == other.endpoint
    }
}

impl Eq for WireguardConfig {}

impl Hash for WireguardConfig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.ip_addr.hash(state);
        self.ip_addr6.hash(state);
        self.public_key.hash(state);
        self.endpoint.hash(state);
    }
}

enum AdapterOrChannel {
    Adapter(Arc<dyn UdpSocketAdapter>),
    Channel(flume::Sender<Bytes>, flume::Receiver<BufferIndex<Vec<u8>>>),
}

enum BufferIndex<T> {
    Pool(usize),
    Raw(T),
}

/// Wireguard Tunnel, with only one peer.
pub struct WireguardTunnel {
    tunnel: tokio::sync::Mutex<Tunn>,
    inner: WireguardTunnelInner,
}

struct WireguardTunnelInner {
    outbound: AdapterOrChannel,
    /// remote address on the genuine Internet
    endpoint: SocketAddr,
    smol_notify: Arc<Notify>,
    inbound_buf_pool: Arc<Pool<Vec<u8>>>,
    reserved: Option<[u8; 3]>,
}

impl WireguardTunnel {
    pub async fn new(
        outbound: AdapterOrSocket,
        config: &WireguardConfig,
        endpoint: SocketAddr,
        smol_notify: Arc<Notify>,
    ) -> Result<Self, TransportError> {
        let tunnel = Tunn::new(
            config.private_key.clone(),
            config.public_key,
            config.preshared_key,
            config.keepalive,
            13,
            None,
        );
        let buf_pool = Arc::new(Pool::<Vec<u8>>::new());
        Ok(Self {
            tunnel: tokio::sync::Mutex::new(tunnel),
            inner: WireguardTunnelInner {
                outbound: match outbound {
                    AdapterOrSocket::Adapter(a) => AdapterOrChannel::Adapter(a),
                    AdapterOrSocket::Socket(s) => {
                        const RECEIVE_BUFFER_SIZE: usize = 2 * 1024 * 1024;
                        let socket_ref = socket2::SockRef::from(&s);
                        let resize_result = socket_ref.recv_buffer_size().and_then(|current| {
                            if current < RECEIVE_BUFFER_SIZE {
                                socket_ref.set_recv_buffer_size(RECEIVE_BUFFER_SIZE)
                            } else {
                                Ok(())
                            }
                        });
                        if let Err(e) = resize_result {
                            tracing::warn!(
                                "WireGuard #{} could not increase UDP receive buffer: {}",
                                config.name,
                                e
                            );
                        }
                        let (out_tx, out_rx) = flume::bounded::<Bytes>(4096);
                        let (in_tx, in_rx) = flume::bounded::<BufferIndex<Vec<u8>>>(4096);
                        let socket = Arc::new(s);
                        let socket_clone = socket.clone();
                        let pool = buf_pool.clone();
                        let name = config.name.clone();
                        local_async_run(Some(format!("WG-{}", config.name)), async move {
                            // dedicated to poll UDP from small kernel buffer
                            let mut buf = vec![0; MAX_UDP_PKT_SIZE];
                            while !in_tx.is_disconnected() {
                                let key = match pool.clone().create_owned() {
                                    Some(mut buf) => {
                                        let key = BufferIndex::Pool(buf.key());
                                        buf.resize(MAX_UDP_PKT_SIZE, 0);
                                        let recv_result = tokio::select! {
                                            recv_result = socket.recv(&mut buf) => recv_result,
                                            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                                                pool.clear(buf.key());
                                                continue
                                            },
                                        };
                                        let Ok(len) = recv_result else {
                                            tracing::warn!(
                                                "WireGuard #{} failed to receive from socket",
                                                name,
                                            );
                                            break;
                                        };
                                        buf.resize(len, 0);
                                        key
                                    }
                                    None => {
                                        let recv_result = tokio::select! {
                                            recv_result = socket.recv(&mut buf) => recv_result,
                                            _ = tokio::time::sleep(Duration::from_millis(500)) => continue,
                                        };
                                        let mut used_buf = std::mem::take(&mut buf);
                                        buf.resize(MAX_UDP_PKT_SIZE, 0);
                                        let len = match recv_result {
                                            Ok(len) => len,
                                            Err(e) => {
                                                tracing::warn!(
                                                    "WireGuard #{} failed to receive: {}",
                                                    name,
                                                    e
                                                );
                                                break;
                                            }
                                        };
                                        used_buf.resize(len, 0);
                                        BufferIndex::Raw(used_buf)
                                    }
                                };
                                if let Err(err) = in_tx.try_send(key) {
                                    let is_disconnected =
                                        matches!(err, flume::TrySendError::Disconnected(_));
                                    if let BufferIndex::Pool(key) = err.into_inner() {
                                        pool.clear(key);
                                    }
                                    if is_disconnected {
                                        break;
                                    }
                                    tracing::warn!("channel full, dropping packet");
                                }
                            }
                        });
                        let name = config.name.clone();
                        tokio::spawn(async move {
                            while let Ok(data) = out_rx.recv_async().await {
                                if let Err(e) = socket_clone.send(&data).await {
                                    tracing::warn!(
                                        "WireGuard #{} outbound send failed: {}",
                                        name,
                                        e
                                    );
                                    return Err(e);
                                }
                            }
                            Ok::<(), io::Error>(())
                        });
                        AdapterOrChannel::Channel(out_tx, in_rx)
                    }
                },
                endpoint,
                smol_notify,
                inbound_buf_pool: buf_pool,
                reserved: config.reserved,
            },
        })
    }

    /// Receive and decrypt available packets from the peer.
    pub async fn receive_incoming_packets(
        &self,
        smol_tx: &mut flume::Sender<IpPacketBatch>,
        buf: &mut [u8; MAX_PKT_SIZE],
        wg_buf: &mut [u8; MAX_PKT_SIZE],
    ) -> Result<bool, TransportError> {
        let mut len = self.inner.outbound_recv(buf).await?;
        let mut packets = None;
        // Combine queued packets without waiting to fill a batch.
        for index in 0..IpPacketBatch::CAPACITY {
            let can_batch = self
                .decapsulate_packet(&buf[..len], wg_buf, &mut packets)
                .await?;
            if !can_batch || index + 1 == IpPacketBatch::CAPACITY {
                break;
            }
            match self.inner.try_outbound_recv(buf) {
                Some(next_len) => {
                    tokio::task::coop::consume_budget().await;
                    len = next_len;
                }
                None => break,
            }
        }
        let Some(packets) = packets else {
            return Ok(false);
        };
        smol_tx
            .send_async(packets)
            .await
            .map_err(|_| TransportError::Internal("WireGuard inbound smol tx full"))?;
        self.inner.smol_notify.notify_one();
        Ok(true)
    }

    async fn decapsulate_packet(
        &self,
        packet: &[u8],
        wg_buf: &mut [u8; MAX_PKT_SIZE],
        packets: &mut Option<IpPacketBatch>,
    ) -> Result<bool, TransportError> {
        let result = self.tunnel.lock().await.decapsulate(None, packet, wg_buf);
        let can_batch = match result {
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                let packet = BytesMut::from_iter(data.iter());
                match packets {
                    Some(batch) => batch.push(packet),
                    None => *packets = Some(IpPacketBatch::Single(packet)),
                }
                true
            }
            TunnResult::WriteToNetwork(data) => {
                self.inner.outbound_send(data).await?;
                // Release the tunnel lock before waiting for outbound capacity.
                loop {
                    let result = self.tunnel.lock().await.decapsulate(None, &[], wg_buf);
                    let TunnResult::WriteToNetwork(data) = result else {
                        break;
                    };
                    self.inner.outbound_send(data).await?;
                }
                false
            }
            TunnResult::Err(e) => {
                return Err(TransportError::InternalExtra(format!(
                    "WireGuard receive failed: {:?}",
                    e
                )));
            }
            TunnResult::Done => true,
        };
        Ok(can_batch)
    }

    pub async fn send_outgoing_packet(
        &self,
        smol_rx: &mut flume::Receiver<BytesMut>,
        wg_buf: &mut [u8; MAX_PKT_SIZE],
    ) -> Result<(), TransportError> {
        let data = smol_rx
            .recv_async()
            .await
            .map_err(|_| io::Error::from(ErrorKind::ConnectionAborted))?;
        let result = self.tunnel.lock().await.encapsulate(data.as_ref(), wg_buf);
        match result {
            TunnResult::WriteToNetwork(packet) => {
                if self.inner.outbound_send(packet).await? != packet.len() {
                    // size exceeded
                    Err(io::Error::from(ErrorKind::WouldBlock))?;
                }
            }
            TunnResult::Done => {}
            other => {
                tracing::warn!("Sent failed: {:?}", other);
                Err(io::Error::from(ErrorKind::InvalidData))?
            }
        }
        Ok(())
    }

    /// Used for ticking tunnel, keeping internal state healthy.
    /// Return whether sending any message
    pub async fn tick(&self, buf: &mut [u8; MAX_PKT_SIZE]) -> Result<bool, TransportError> {
        let mut guard = self.tunnel.lock().await;
        match guard.update_timers(buf) {
            TunnResult::Done => {
                // do nothing
                Ok(false)
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                match guard.format_handshake_initiation(buf, false) {
                    TunnResult::Done => {
                        // handshake ongoing, ignore
                        Ok(false)
                    }
                    TunnResult::WriteToNetwork(data) => {
                        drop(guard);
                        if let Err(e) = self.inner.outbound_send(data).await {
                            tracing::warn!("Failed to write to network: {}", e);
                            Err(e)
                        } else {
                            Ok(true)
                        }
                    }
                    other => {
                        tracing::warn!("Unexpected WireGuard timer message: {:?}", other);
                        Ok(false)
                    }
                }
            }
            TunnResult::WriteToNetwork(packet) => {
                drop(guard);
                if let Err(e) = self.inner.outbound_send(packet).await {
                    tracing::warn!("Failed to send timer message: {}", e);
                    Err(e)
                } else {
                    Ok(true)
                }
            }
            other => {
                tracing::warn!("Unexpected WireGuard timer message: {:?}", other);
                Ok(false)
            }
        }
    }

    pub async fn stats(&self) -> (bool, Option<std::time::Duration>) {
        let tun = self.tunnel.lock().await;
        (tun.is_expired(), tun.stats().0)
    }
}

impl WireguardTunnelInner {
    fn copy_received(&self, index: BufferIndex<Vec<u8>>, data: &mut [u8]) -> usize {
        match index {
            BufferIndex::Pool(key) => {
                let buf = self.inbound_buf_pool.get(key).expect("pool key not found");
                let len = buf.len();
                data[..len].copy_from_slice(&buf);
                self.inbound_buf_pool.clear(key);
                len
            }
            BufferIndex::Raw(buf) => {
                let len = buf.len();
                data[..len].copy_from_slice(&buf);
                len
            }
        }
    }

    fn try_outbound_recv(&self, data: &mut [u8]) -> Option<usize> {
        match &self.outbound {
            AdapterOrChannel::Adapter(_) => None,
            AdapterOrChannel::Channel(_, channel) => channel
                .try_recv()
                .ok()
                .map(|index| self.copy_received(index, data)),
        }
    }

    async fn outbound_send(&self, data: &mut [u8]) -> Result<usize, TransportError> {
        if data.len() >= 4
            && let Some(r) = &self.reserved
        {
            data[1] = r[0];
            data[2] = r[1];
            data[3] = r[2];
        }
        match &self.outbound {
            AdapterOrChannel::Adapter(a) => {
                a.send_to(data, NetworkAddr::from(self.endpoint)).await?;
                Ok(data.len())
            }
            AdapterOrChannel::Channel(c, _) => {
                let data = Bytes::copy_from_slice(data);
                let len = data.len();
                c.send_async(data)
                    .await
                    .map_err(|_| io_err("WireGuard outbound channel closed"))?;
                Ok(len)
            }
        }
    }

    async fn outbound_recv(&self, data: &mut [u8]) -> Result<usize, TransportError> {
        match &self.outbound {
            AdapterOrChannel::Adapter(a) => Ok(a.recv_from(data).await?.0),
            AdapterOrChannel::Channel(_, c) => {
                let index = c
                    .recv_async()
                    .await
                    .map_err(|_| io_err("WireGuard outbound channel closed"))?;
                Ok(self.copy_received(index, data))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::packet::transport_layer::create_raw_udp_pkt;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpPacket};

    fn tcp_packet(ipv6: bool, value: u8) -> BytesMut {
        let ip_len = if ipv6 { 40 } else { 20 };
        let mut packet = BytesMut::zeroed(ip_len + 20 + usize::from(value) + 1);
        let (src, dst) = if ipv6 {
            let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
            let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
            Ipv6Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Tcp,
                payload_len: packet.len() - ip_len,
                hop_limit: 64,
            }
            .emit(&mut Ipv6Packet::new_unchecked(&mut packet[..]));
            (src.into(), dst.into())
        } else {
            let src = Ipv4Addr::new(192, 0, 2, 1);
            let dst = Ipv4Addr::new(192, 0, 2, 2);
            Ipv4Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Tcp,
                payload_len: packet.len() - ip_len,
                hop_limit: 64,
            }
            .emit(
                &mut Ipv4Packet::new_unchecked(&mut packet[..]),
                &ChecksumCapabilities::default(),
            );
            (src.into(), dst.into())
        };
        let mut tcp = TcpPacket::new_unchecked(&mut packet[ip_len..]);
        tcp.set_header_len(20);
        tcp.set_src_port(1000);
        tcp.set_dst_port(2000);
        tcp.set_ack(true);
        tcp.set_window_len(65535);
        tcp.payload_mut().fill(value);
        tcp.fill_checksum(&src, &dst);
        packet
    }

    fn network_packet(result: TunnResult<'_>) -> Vec<u8> {
        match result {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a WireGuard network packet, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn receive_batches_count_control_packets_and_preserve_mixed_data() {
        let sender_key = x25519_dalek::StaticSecret::from([1; 32]);
        let receiver_key = x25519_dalek::StaticSecret::from([2; 32]);
        let sender_public = x25519_dalek::PublicKey::from(&sender_key);
        let receiver_public = x25519_dalek::PublicKey::from(&receiver_key);
        let mut sender = Tunn::new(sender_key, receiver_public, None, None, 1, None);
        let mut receiver = Tunn::new(receiver_key, sender_public, None, None, 2, None);
        let mut wire = [0; MAX_PKT_SIZE];
        let request = network_packet(sender.format_handshake_initiation(&mut wire, true));
        let reply = network_packet(receiver.decapsulate(None, &request, &mut wire));
        let confirmation = network_packet(sender.decapsulate(None, &reply, &mut wire));
        assert!(matches!(
            receiver.decapsulate(None, &confirmation, &mut wire),
            TunnResult::Done
        ));

        let (incoming, incoming_rx) = flume::unbounded();
        let (outgoing, _outgoing_rx) = flume::unbounded();
        let tunnel = WireguardTunnel {
            tunnel: tokio::sync::Mutex::new(receiver),
            inner: WireguardTunnelInner {
                outbound: AdapterOrChannel::Channel(outgoing, incoming_rx.clone()),
                endpoint: "127.0.0.1:51820".parse().unwrap(),
                smol_notify: Arc::new(Notify::new()),
                inbound_buf_pool: Arc::new(Pool::new()),
                reserved: None,
            },
        };
        for _ in 0..IpPacketBatch::CAPACITY {
            let packet = network_packet(sender.encapsulate(&[], &mut wire));
            incoming.send(BufferIndex::Raw(packet)).unwrap();
        }
        let mut expected: Vec<_> = (0..IpPacketBatch::CAPACITY + 1)
            .map(|index| tcp_packet(index % 2 == 1, index as u8))
            .collect();
        for index in 0..=IpPacketBatch::CAPACITY {
            expected.push(create_raw_udp_pkt(
                &vec![index as u8; index + 1],
                "192.0.2.1:1000".parse().unwrap(),
                "192.0.2.2:2000".parse().unwrap(),
            ));
            expected.push(create_raw_udp_pkt(
                &vec![index as u8; index + 13],
                "[2001:db8::1]:1000".parse().unwrap(),
                "[2001:db8::2]:2000".parse().unwrap(),
            ));
        }
        expected.push(tcp_packet(false, 100));
        expected.push(tcp_packet(true, 101));
        for packet in &expected {
            let encrypted = network_packet(sender.encapsulate(packet, &mut wire));
            incoming.send(BufferIndex::Raw(encrypted)).unwrap();
        }
        let (mut stack_tx, stack_rx) = flume::bounded(4);
        let mut plaintext = [0; MAX_PKT_SIZE];
        assert!(
            !tunnel
                .receive_incoming_packets(&mut stack_tx, &mut wire, &mut plaintext)
                .await
                .unwrap()
        );
        assert_eq!(incoming_rx.len(), expected.len());
        assert!(stack_rx.is_empty());

        let mut actual = Vec::new();
        for expected_batch in expected.chunks(IpPacketBatch::CAPACITY) {
            assert!(
                tokio::time::timeout(
                    Duration::from_secs(1),
                    tunnel.receive_incoming_packets(&mut stack_tx, &mut wire, &mut plaintext),
                )
                .await
                .expect("a partial batch must not wait for more packets")
                .unwrap()
            );
            let previous_len = actual.len();
            match stack_rx.try_recv().unwrap() {
                IpPacketBatch::Single(packet) => actual.push(packet),
                IpPacketBatch::Multiple(packets) => actual.extend(packets),
            }
            assert_eq!(actual.len() - previous_len, expected_batch.len());
        }
        assert_eq!(actual, expected);
        assert!(incoming_rx.is_empty());
    }
}
