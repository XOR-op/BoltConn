use crate::adapter::Connector;
use crate::common::io_err;
use crate::network::dns::Dns;
use crate::proxy::NetworkAddr;
use anyhow::anyhow;
use boringtun::noise::{Tunn, TunnResult};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

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
    /// address on the genuine Internet
    endpoint: SocketAddr,
}

impl WireguardTunnel {
    pub async fn new(
        outbound: UdpSocket,
        private_key: x25519_dalek::StaticSecret,
        config: &WireguardPeerConfig,
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
        })
    }

    /// Receive wg packet from Internet
    pub async fn receive_incoming_packet(&self) -> anyhow::Result<()> {
        let mut buf = [0u8; MAX_PKT_SIZE];
        let mut wg_buf = [0u8; MAX_PKT_SIZE];
        let len = self.outbound.recv(&mut buf).await?;
        match self.tunnel.decapsulate(None, &buf[..len], &mut wg_buf) {
            TunnResult::WriteToTunnelV4(data, addr) => {}
            TunnResult::WriteToTunnelV6(data, addr) => {}
            _ => {
                return Err(anyhow!("Unexpected result at endpoint"));
            }
        }
        todo!()
    }
}
