use crate::common::{io_err, mut_buf};
use crate::common::{local_async_run, MAX_PKT_SIZE};
use crate::config::DnsPreference;
use crate::network::dns::Dns;
use crate::proxy::error::TransportError;
use crate::proxy::NetworkAddr;
use crate::transport::{AdapterOrSocket, UdpSocketAdapter};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use hickory_resolver::config::ResolverConfig;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::io;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
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
            .field(&self.ip_addr)
            .field(&self.ip_addr6)
            .field(&self.endpoint)
            .field(&self.preshared_key)
            .finish()
    }
}

impl PartialEq for WireguardConfig {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
            && self.ip_addr == other.ip_addr
            && self.ip_addr6 == other.ip_addr6
            && self.endpoint == other.endpoint
    }
}

impl Eq for WireguardConfig {}

impl Hash for WireguardConfig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip_addr.hash(state);
        self.ip_addr6.hash(state);
        self.public_key.hash(state);
        self.endpoint.hash(state);
    }
}

enum AdapterOrChannel {
    Adapter(Arc<dyn UdpSocketAdapter>),
    Channel(flume::Sender<Bytes>, flume::Receiver<Bytes>),
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
                    .await
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
        Ok(Self {
            tunnel: tokio::sync::Mutex::new(tunnel),
            inner: WireguardTunnelInner {
                outbound: match outbound {
                    AdapterOrSocket::Adapter(a) => AdapterOrChannel::Adapter(a),
                    AdapterOrSocket::Socket(s) => {
                        let (out_tx, out_rx) = flume::bounded::<Bytes>(4096);
                        let (in_tx, in_rx) = flume::bounded(4096);
                        let socket = Arc::new(s);
                        let socket_clone = socket.clone();
                        local_async_run(async move {
                            // dedicated to poll UDP from small kernel buffer
                            loop {
                                let mut buf = BytesMut::with_capacity(MAX_PKT_SIZE);
                                let Ok(len) = socket.recv(unsafe { mut_buf(&mut buf) }).await
                                else {
                                    break;
                                };
                                unsafe { buf.advance_mut(len) };
                                if in_tx.try_send(buf.freeze()).is_err() {
                                    tracing::warn!("channel full, dropping packet");
                                }
                            }
                        });
                        tokio::spawn(async move {
                            while let Ok(data) = out_rx.recv_async().await {
                                socket_clone.send(&data).await?;
                            }
                            Ok::<(), io::Error>(())
                        });
                        AdapterOrChannel::Channel(out_tx, in_rx)
                    }
                },
                endpoint,
                smol_notify,
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
            _ => false,
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
                let _ = c.send(data);
                Ok(len)
            }
        }
    }

    async fn outbound_recv(&self, data: &mut [u8]) -> Result<usize, TransportError> {
        match &self.outbound {
            AdapterOrChannel::Adapter(a) => Ok(a.recv_from(data).await?.0),
            AdapterOrChannel::Channel(_, c) => {
                let d = c
                    .recv_async()
                    .await
                    .map_err(|_| io_err("WireGuard outbound channel closed"))?;
                let len = d.len();
                (data[..len]).copy_from_slice(&d);
                Ok(len)
            }
        }
    }
}
