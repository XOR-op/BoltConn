use crate::common::io_err;
use crate::network::dns::Dns;
use crate::proxy::NetworkAddr;
use anyhow::anyhow;
use boringtun::noise::{Tunn, TunnResult};
use bytes::BytesMut;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const MAX_PKT_SIZE: usize = 65536;

// We left AllowedIPs since it's boltconn that manages routing.
#[derive(Clone, Debug)]
pub struct WireguardPeerConfig {
    public_key: x25519_dalek::PublicKey,
    endpoint: NetworkAddr,
    preshared_key: Option<[u8; 32]>,
    keepalive: Option<u16>,
}

/// Wireguard Tunnel, with only one peer.
pub struct WireguardTunnel {
    outbound: UdpSocket,
    tunnel: Box<Tunn>,
    /// remote address on the genuine Internet
    endpoint: SocketAddr,
    smol_tx: mpsc::Sender<BytesMut>,
    smol_rx: mpsc::Receiver<BytesMut>,

    // Reuse buffer to avoid unnecessary memset
    buf: [u8; MAX_PKT_SIZE],
    wg_buf: [u8; MAX_PKT_SIZE],
}

impl WireguardTunnel {
    pub async fn new(
        outbound: UdpSocket,
        private_key: x25519_dalek::StaticSecret,
        config: &WireguardPeerConfig,
        dns: Arc<Dns>,
        smol_tx: mpsc::Sender<BytesMut>,
        smol_rx: mpsc::Receiver<BytesMut>,
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
            private_key.clone(),
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
            smol_tx,
            smol_rx,

            buf: [0u8; MAX_PKT_SIZE],
            wg_buf: [0u8; MAX_PKT_SIZE],
        })
    }

    /// Receive wg packet from Internet
    pub async fn receive_incoming_packet(&mut self) -> anyhow::Result<()> {
        let len = self.outbound.recv(&mut self.buf).await?;
        // Indeed we can achieve zero-copy with the implementation of ring,
        // but there is no hard guarantee for that, so we just manually copy buffer.
        match self
            .tunnel
            .decapsulate(None, &self.buf[..len], &mut self.wg_buf)
        {
            TunnResult::WriteToTunnelV4(data, _addr) => {
                let data = BytesMut::from_iter(data.iter());
                self.smol_tx.send(data).await?;
            }
            TunnResult::WriteToTunnelV6(data, _addr) => {
                let data = BytesMut::from_iter(data.iter());
                self.smol_tx.send(data).await?;
            }
            _ => {
                return Err(anyhow!("Unexpected result at endpoint"));
            }
        }
        todo!()
    }

    pub async fn send_outgoing_packet(&mut self) -> anyhow::Result<()> {
        let data = self
            .smol_rx
            .recv()
            .await
            .ok_or(io::Error::from(ErrorKind::ConnectionAborted))?;
        match self.tunnel.encapsulate(data.as_ref(), &mut self.wg_buf) {
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
