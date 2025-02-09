use crate::common::{io_err, local_async_run, MAX_PKT_SIZE, MAX_UDP_PKT_SIZE};
use crate::config::DnsPreference;
use crate::network::dns::Dns;
use crate::proxy::error::TransportError;
use crate::proxy::NetworkAddr;
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
        dns: Arc<Dns>,
        smol_notify: Arc<Notify>,
    ) -> Result<Self, TransportError> {
        let endpoint = match config.endpoint {
            NetworkAddr::Raw(addr) => addr,
            NetworkAddr::DomainName {
                ref domain_name,
                port,
            } => {
                let resp = dns
                    .genuine_lookup(domain_name)
                    .await?
                    .ok_or_else(|| io_err("dns not found"))?;
                SocketAddr::new(resp, port)
            }
        };
        let tunnel = Tunn::new(
            config.private_key.clone(),
            config.public_key,
            config.preshared_key,
            config.keepalive,
            13,
            None,
        );
        let buf_pool = Arc::new({
            let pool = Pool::<Vec<u8>>::new();
            // allocate memory in advance
            // TODO: profile to determine removal
            const INIT_POOL_SIZE: usize = 128;
            let mut index_arr = [0; INIT_POOL_SIZE];
            for entry in index_arr.iter_mut() {
                *entry = pool
                    .create_with(|x| {
                        x.resize(MAX_PKT_SIZE, 0);
                    })
                    .expect("slab pool initialization failed");
            }
            for entry in index_arr.iter() {
                pool.clear(*entry);
            }
            pool
        });
        Ok(Self {
            tunnel: tokio::sync::Mutex::new(tunnel),
            inner: WireguardTunnelInner {
                outbound: match outbound {
                    AdapterOrSocket::Adapter(a) => AdapterOrChannel::Adapter(a),
                    AdapterOrSocket::Socket(s) => {
                        let (out_tx, out_rx) = flume::bounded::<Bytes>(4096);
                        let (in_tx, in_rx) = flume::bounded::<BufferIndex<Vec<u8>>>(4096);
                        let socket = Arc::new(s);
                        let socket_clone = socket.clone();
                        let pool = buf_pool.clone();
                        let name = config.name.clone();
                        local_async_run(async move {
                            // dedicated to poll UDP from small kernel buffer
                            while !in_tx.is_disconnected() {
                                let key = match pool.clone().create_owned() {
                                    Some(mut buf) => {
                                        let key = BufferIndex::Pool(buf.key());
                                        buf.resize(MAX_UDP_PKT_SIZE, 0);
                                        let recv_result = tokio::select! {
                                            recv_result = socket.recv(&mut buf) => recv_result,
                                            _ = tokio::time::sleep(Duration::from_millis(500)) => continue,
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
                                        let mut buf = vec![0; MAX_UDP_PKT_SIZE];
                                        let recv_result = tokio::select! {
                                            recv_result = socket.recv(&mut buf) => recv_result,
                                            _ = tokio::time::sleep(Duration::from_millis(500)) => continue,
                                        };
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
                                        buf.resize(len, 0);
                                        BufferIndex::Raw(buf)
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

    /// Receive wg packet from Internet
    pub async fn receive_incoming_packet(
        &self,
        smol_tx: &mut flume::Sender<BytesMut>,
        buf: &mut [u8; MAX_PKT_SIZE],
        wg_buf: &mut [u8; MAX_PKT_SIZE],
    ) -> Result<bool, TransportError> {
        let len = self.inner.outbound_recv(buf).await?;
        // Indeed we can achieve zero-copy with the implementation of ring,
        // but there is no hard guarantee for that, so we just manually copy buffer.
        let result = self
            .tunnel
            .lock()
            .await
            .decapsulate(None, &buf[..len], wg_buf);
        Ok(match result {
            TunnResult::WriteToTunnelV4(data, _addr) => {
                let data = BytesMut::from_iter(data.iter());
                smol_tx
                    .send_async(data)
                    .await
                    .map_err(|_| TransportError::Internal("WireGuard inbound smol tx full"))?;
                self.inner.smol_notify.notify_one();
                true
            }
            TunnResult::WriteToTunnelV6(data, _addr) => {
                let data = BytesMut::from_iter(data.iter());
                smol_tx
                    .send_async(data)
                    .await
                    .map_err(|_| TransportError::Internal("WireGuard inbound smol tx full"))?;
                self.inner.smol_notify.notify_one();
                true
            }
            TunnResult::WriteToNetwork(data) => {
                self.inner.outbound_send(data).await?;
                // flush pending queue
                while let TunnResult::WriteToNetwork(data) =
                    self.tunnel.lock().await.decapsulate(None, &[], buf)
                {
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
            TunnResult::Done => false,
        })
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
        match self.tunnel.lock().await.encapsulate(data.as_ref(), wg_buf) {
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
    async fn outbound_send(&self, data: &mut [u8]) -> Result<usize, TransportError> {
        if data.len() >= 4 {
            if let Some(r) = &self.reserved {
                data[1] = r[0];
                data[2] = r[1];
                data[3] = r[2];
            }
        }
        match &self.outbound {
            AdapterOrChannel::Adapter(a) => {
                a.send_to(data, NetworkAddr::Raw(self.endpoint)).await?;
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
                Ok(match index {
                    BufferIndex::Pool(key) => {
                        // panic safety: if key is invalid, there will be an obvious bug in the code, so we need to panic.
                        let buf = self.inbound_buf_pool.get(key).expect("pool key not found");
                        let len = buf.len();
                        (data[..len]).copy_from_slice(&buf);
                        self.inbound_buf_pool.clear(key);
                        len
                    }
                    BufferIndex::Raw(buf) => {
                        let len = buf.len();
                        (data[..len]).copy_from_slice(&buf);
                        len
                    }
                })
            }
        }
    }
}
