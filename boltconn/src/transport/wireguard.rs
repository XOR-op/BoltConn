use crate::common::buf_pool::MAX_PKT_SIZE;
use crate::common::io_err;
use crate::network::dns::Dns;
use crate::proxy::NetworkAddr;
use anyhow::anyhow;
use boringtun::noise::{Tunn, TunnResult};
use bytes::BytesMut;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

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
}

impl WireguardTunnel {
    pub async fn new(
        outbound: UdpSocket,
        config: &WireguardConfig,
        dns: Arc<Dns>,
    ) -> anyhow::Result<Self> {
        let endpoint = match config.endpoint {
            NetworkAddr::Raw(addr) => addr,
            NetworkAddr::DomainName {
                ref domain_name,
                port,
            } => {
                let resp = dns
                    .genuine_lookup(&domain_name)
                    .await
                    .ok_or(io_err("dns not found"))?;
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
        })
    }

    /// Receive wg packet from Internet
    pub async fn receive_incoming_packet(
        &self,
        smol_tx: &mut mpsc::Sender<BytesMut>,
        buf: &mut [u8; MAX_PKT_SIZE],
        wg_buf: &mut [u8; MAX_PKT_SIZE],
    ) -> anyhow::Result<()> {
        let len = self.outbound.recv(buf).await?;
        // Indeed we can achieve zero-copy with the implementation of ring,
        // but there is no hard guarantee for that, so we just manually copy buffer.
        match self.tunnel.decapsulate(None, &buf[..len], wg_buf) {
            TunnResult::WriteToTunnelV4(data, _addr) => {
                let data = BytesMut::from_iter(data.iter());
                smol_tx.send(data).await?;
            }
            TunnResult::WriteToTunnelV6(data, _addr) => {
                let data = BytesMut::from_iter(data.iter());
                smol_tx.send(data).await?;
            }
            _ => {
                return Err(anyhow!("Unexpected result at endpoint"));
            }
        }
        Ok(())
    }

    pub async fn send_outgoing_packet(
        &self,
        smol_rx: &mut mpsc::Receiver<BytesMut>,
        wg_buf: &mut [u8; MAX_PKT_SIZE],
    ) -> anyhow::Result<()> {
        let data = smol_rx
            .recv()
            .await
            .ok_or(io::Error::from(ErrorKind::ConnectionAborted))?;
        match self.tunnel.encapsulate(data.as_ref(), wg_buf) {
            TunnResult::WriteToNetwork(packet) => {
                if self.outbound.send(packet).await? != packet.len() {
                    // size exceeded
                    Err(io::Error::from(ErrorKind::WouldBlock))?;
                }
            }
            TunnResult::Done => {}
            _ => Err(io::Error::from(ErrorKind::InvalidData))?,
        }
        Ok(())
    }
}
