use crate::proxy::NetworkAddr;
use async_trait::async_trait;
use std::sync::Arc;

pub mod smol;
pub mod trojan;
pub mod wireguard;

#[async_trait]
pub trait UdpSocketAdapter: Send + Sync {
    async fn send_to(&self, data: &[u8], addr: NetworkAddr) -> anyhow::Result<()>;

    // @return: <length>, <if addr matches target>
    async fn recv_from(&self, data: &mut [u8]) -> anyhow::Result<(usize, NetworkAddr)>;
}

pub enum AdapterOrSocket {
    Adapter(Arc<dyn UdpSocketAdapter>),
    Socket(tokio::net::UdpSocket),
}
