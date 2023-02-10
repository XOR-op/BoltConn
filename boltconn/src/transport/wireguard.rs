use crate::common::buf_pool::MAX_PKT_SIZE;
use crate::common::io_err;
use crate::network::dns::Dns;
use crate::proxy::NetworkAddr;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use bytes::BytesMut;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Notify;

// We left AllowedIPs since it's boltconn that manages routing.
#[derive(Clone)]
pub struct WireguardConfig {
    // local
    pub ip_addr: IpAddr,
    pub private_key: x25519_dalek::StaticSecret,
    // peer
    pub public_key: x25519_dalek::PublicKey,
    pub endpoint: NetworkAddr,
    pub mtu: usize,
    pub preshared_key: Option<[u8; 32]>,
    pub keepalive: Option<u16>,
}

impl Debug for WireguardConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("")
            .field(&self.ip_addr)
            .field(&self.endpoint)
            .field(&self.preshared_key)
            .finish()
    }
}

impl PartialEq for WireguardConfig {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
            && self.ip_addr == other.ip_addr
            && self.endpoint == other.endpoint
    }
}

impl Eq for WireguardConfig {}

impl Hash for WireguardConfig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip_addr.hash(state);
        self.public_key.hash(state);
        self.endpoint.hash(state);
    }
}

/// Wireguard Tunnel, with only one peer.
pub struct WireguardTunnel {
    outbound: UdpSocket,
    tunnel: Box<Tunn>,
    /// remote address on the genuine Internet
    endpoint: SocketAddr,
    smol_notify: Arc<Notify>,
}

impl WireguardTunnel {
    pub async fn new(
        outbound: UdpSocket,
        config: &WireguardConfig,
        dns: Arc<Dns>,
        smol_notify: Arc<Notify>,
    ) -> anyhow::Result<Self> {
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
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        Ok(Self {
            outbound,
            tunnel,
            endpoint,
            smol_notify,
        })
    }

    async fn flush_pending_queue(&self, buf: &mut [u8; MAX_PKT_SIZE]) -> anyhow::Result<()> {
        // flush pending queue
        while let TunnResult::WriteToNetwork(data) = self.tunnel.decapsulate(None, &[], buf) {
            self.outbound.send(data).await?;
        }
        Ok(())
    }

    /// Receive wg packet from Internet
    pub async fn receive_incoming_packet(
        &self,
        smol_tx: &mut flume::Sender<BytesMut>,
        buf: &mut [u8; MAX_PKT_SIZE],
        wg_buf: &mut [u8; MAX_PKT_SIZE],
    ) -> anyhow::Result<()> {
        let len = self.outbound.recv(buf).await?;
        // Indeed we can achieve zero-copy with the implementation of ring,
        // but there is no hard guarantee for that, so we just manually copy buffer.
        match self.tunnel.decapsulate(None, &buf[..len], wg_buf) {
            TunnResult::WriteToTunnelV4(data, _addr) => {
                let data = BytesMut::from_iter(data.iter());
                smol_tx.send_async(data).await?;
                self.smol_notify.notify_one();
            }
            TunnResult::WriteToTunnelV6(data, _addr) => {
                let data = BytesMut::from_iter(data.iter());
                smol_tx.send_async(data).await?;
                self.smol_notify.notify_one();
            }
            TunnResult::WriteToNetwork(data) => {
                self.outbound.send(data).await?;
                self.flush_pending_queue(wg_buf).await?;
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn send_outgoing_packet(
        &self,
        smol_rx: &mut flume::Receiver<BytesMut>,
        wg_buf: &mut [u8; MAX_PKT_SIZE],
    ) -> anyhow::Result<()> {
        let data = smol_rx
            .recv_async()
            .await
            .map_err(|_| io::Error::from(ErrorKind::ConnectionAborted))?;
        match self.tunnel.encapsulate(data.as_ref(), wg_buf) {
            TunnResult::WriteToNetwork(packet) => {
                if self.outbound.send(packet).await? != packet.len() {
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
    pub async fn tick(&self, buf: &mut [u8; MAX_PKT_SIZE]) {
        match self.tunnel.update_timers(buf) {
            TunnResult::Done => {
                // do nothing
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                match self.tunnel.format_handshake_initiation(buf, false) {
                    TunnResult::Done => {
                        // handshake ongoing, ignore
                    }
                    TunnResult::WriteToNetwork(data) => {
                        let _ = self.outbound.send(data).await;
                    }
                    other => {
                        tracing::warn!("Unexpected wireguard timer message: {:?}", other);
                    }
                }
            }
            TunnResult::WriteToNetwork(packet) => {
                if let Err(e) = self.outbound.send(packet).await {
                    tracing::warn!("Failed to send timer message: {}", e);
                }
            }
            other => {
                tracing::warn!("Unexpected wireguard timer message: {:?}", other);
            }
        }
    }
}
