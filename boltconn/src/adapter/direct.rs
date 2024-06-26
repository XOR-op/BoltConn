use crate::adapter::{
    established_tcp, established_udp, lookup, AddrConnector, Connector, Outbound, OutboundType,
};
use crate::common::StreamOutboundTrait;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::UdpSocketAdapter;
use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct DirectOutbound {
    iface_name: String,
    dst: NetworkAddr,
    resolved_dst: Option<SocketAddr>,
    dns: Arc<Dns>,
}

impl DirectOutbound {
    pub fn new(
        iface_name: &str,
        dst: NetworkAddr,
        resolved_dst: Option<SocketAddr>,
        dns: Arc<Dns>,
    ) -> Self {
        Self {
            iface_name: iface_name.into(),
            dst,
            resolved_dst,
            dns,
        }
    }

    async fn run_tcp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> io::Result<()> {
        let dst_addr = if let Some(dst) = self.resolved_dst {
            dst
        } else {
            lookup(self.dns.as_ref(), &self.dst).await?
        };
        let outbound = Egress::new(&self.iface_name).tcp_stream(dst_addr).await?;

        established_tcp(inbound, outbound, abort_handle).await;
        Ok(())
    }

    async fn run_udp(
        self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
    ) -> io::Result<()> {
        let outbound = Arc::new(Egress::new(&self.iface_name).udpv4_socket().await?);
        established_udp(
            inbound,
            DirectUdpAdapter(outbound, self.dns.clone()),
            None,
            abort_handle,
        )
        .await;
        Ok(())
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn outbound_type(&self) -> OutboundType {
        OutboundType::Direct
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().run_tcp(inbound, abort_handle))
    }

    async fn spawn_tcp_with_outbound(
        &self,
        _inbound: Connector,
        _tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        _udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        _abort_handle: ConnAbortHandle,
    ) -> io::Result<bool> {
        tracing::error!("spawn_tcp_with_outbound() should not be called with DirectOutbound");
        return Err(io::ErrorKind::InvalidData.into());
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().run_udp(inbound, abort_handle))
    }

    async fn spawn_udp_with_outbound(
        &self,
        _inbound: AddrConnector,
        _tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        _udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        _abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> io::Result<bool> {
        tracing::error!("spawn_udp_with_outbound() should not be called with DirectOutbound");
        return Err(io::ErrorKind::InvalidData.into());
    }
}

#[derive(Clone)]
struct DirectUdpAdapter(Arc<UdpSocket>, Arc<Dns>);

#[async_trait]
impl UdpSocketAdapter for DirectUdpAdapter {
    async fn send_to(&self, data: &[u8], addr: NetworkAddr) -> Result<(), TransportError> {
        let addr = match addr {
            NetworkAddr::Raw(s) => s,
            NetworkAddr::DomainName { domain_name, port } => {
                let Some(ip) = self.1.genuine_lookup(domain_name.as_str()).await else {
                    // drop
                    return Ok(());
                };
                SocketAddr::new(ip, port)
            }
        };
        self.0.send_to(data, addr).await?;
        Ok(())
    }

    async fn recv_from(&self, data: &mut [u8]) -> Result<(usize, NetworkAddr), TransportError> {
        let (len, addr) = self.0.recv_from(data).await?;
        Ok((len, NetworkAddr::Raw(addr)))
    }
}
