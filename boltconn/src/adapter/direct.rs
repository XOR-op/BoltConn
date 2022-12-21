use crate::adapter::{
    established_tcp, established_udp, Connector, TcpOutBound, UdpOutBound, UdpSocketWrapper,
};
use crate::common::duplex_chan::DuplexChan;
use crate::common::io_err;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::NetworkAddr;
use crate::PktBufPool;
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct DirectOutbound {
    iface_name: String,
    dst: NetworkAddr,
    allocator: PktBufPool,
    dns: Arc<Dns>,
}

impl DirectOutbound {
    pub fn new(iface_name: &str, dst: NetworkAddr, allocator: PktBufPool, dns: Arc<Dns>) -> Self {
        Self {
            iface_name: iface_name.into(),
            dst,
            allocator,
            dns,
        }
    }

    async fn get_dst(&self) -> Result<SocketAddr> {
        Ok(match &self.dst {
            NetworkAddr::DomainName { domain_name, port } => {
                // translate fake ip
                SocketAddr::new(
                    self.dns
                        .genuine_lookup(domain_name.as_str())
                        .await
                        .ok_or(io_err("DNS failed"))?,
                    port.clone(),
                )
            }
            NetworkAddr::Raw(s) => s.clone(),
        })
    }

    async fn run_tcp(self, inbound: Connector) -> Result<()> {
        let dst_addr = self.get_dst().await?;
        let outbound = match dst_addr {
            SocketAddr::V4(_) => Egress::new(&self.iface_name).tcpv4_stream(dst_addr).await?,
            SocketAddr::V6(_) => Egress::new(&self.iface_name).tcpv6_stream(dst_addr).await?,
        };
        tracing::trace!(
            "[Direct] Connection {:?} <=> {:?} established",
            outbound.local_addr(),
            outbound.peer_addr()
        );

        established_tcp(inbound, outbound, self.allocator).await;
        Ok(())
    }

    async fn run_udp(self, inbound: Connector) -> Result<()> {
        let dst_addr = self.get_dst().await?;
        let outbound = Arc::new(Egress::new(&self.iface_name).udpv4_socket().await?);
        outbound.connect(dst_addr).await?;
        tracing::trace!(
            "[Direct] UDP Session {:?} <=> {:?} established",
            outbound.local_addr(),
            outbound.peer_addr()
        );
        established_udp(inbound, UdpSocketWrapper::Direct(outbound), self.allocator).await;
        Ok(())
    }
}

impl TcpOutBound for DirectOutbound {
    fn spawn_tcp(&self, inbound: Connector) -> JoinHandle<Result<()>> {
        tokio::spawn(self.clone().run_tcp(inbound))
    }

    fn spawn_tcp_with_chan(&self) -> (DuplexChan, JoinHandle<Result<()>>) {
        let (inner, outer) = Connector::new_pair(10);
        (
            DuplexChan::new(self.allocator.clone(), inner),
            tokio::spawn(self.clone().run_tcp(outer)),
        )
    }
}

impl UdpOutBound for DirectOutbound {
    fn spawn_udp(&self, inbound: Connector) -> JoinHandle<Result<()>> {
        tokio::spawn(self.clone().run_udp(inbound))
    }

    fn spawn_udp_with_chan(&self) -> (DuplexChan, JoinHandle<Result<()>>) {
        let (inner, outer) = Connector::new_pair(10);
        (
            DuplexChan::new(self.allocator.clone(), inner),
            tokio::spawn(self.clone().run_udp(outer)),
        )
    }
}
