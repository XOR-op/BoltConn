use crate::proxy::error::TransportError;
use crate::proxy::NetworkAddr;
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub mod smol;
pub mod trojan;
pub mod wireguard;

#[async_trait]
pub trait UdpSocketAdapter: Send + Sync {
    async fn send_to(&self, data: &[u8], addr: NetworkAddr) -> Result<(), TransportError>;

    // @return: <length>, <if addr matches target>
    async fn recv_from(&self, data: &mut [u8]) -> Result<(usize, NetworkAddr), TransportError>;
}

pub enum AdapterOrSocket {
    Adapter(Arc<dyn UdpSocketAdapter>),
    Socket(tokio::net::UdpSocket),
}

#[derive(Copy, Clone, Debug)]
pub enum InterfaceAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    DualStack(Ipv4Addr, Ipv6Addr),
}

impl InterfaceAddress {
    pub fn from_dual(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> Option<Self> {
        Some(match (v4, v6) {
            (Some(v4), None) => Self::Ipv4(v4),
            (None, Some(v6)) => Self::Ipv6(v6),
            (Some(v4), Some(v6)) => Self::DualStack(v4, v6),
            (None, None) => None?,
        })
    }

    pub fn matched_if_addr(&self, addr: IpAddr) -> Option<IpAddr> {
        Some(match (self, addr) {
            (Self::Ipv4(addr), IpAddr::V4(_)) => (*addr).into(),
            (Self::Ipv6(addr), IpAddr::V6(_)) => (*addr).into(),
            (Self::DualStack(addr, _), IpAddr::V4(_)) => (*addr).into(),
            (Self::DualStack(_, addr), IpAddr::V6(_)) => (*addr).into(),
            _ => None?,
        })
    }
}
