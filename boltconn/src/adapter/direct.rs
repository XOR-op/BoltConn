use crate::adapter::{
    established_tcp, established_udp, lookup, Connector, TcpOutBound, UdpOutBound, UdpSocketAdapter,
};
use crate::common::duplex_chan::DuplexChan;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::PktBufPool;
use async_trait::async_trait;
use io::Result;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
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

    async fn run_tcp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        let dst_addr = lookup(self.dns.as_ref(), &self.dst).await?;
        let outbound = Egress::new(&self.iface_name).tcp_stream(dst_addr).await?;

        established_tcp(inbound, outbound, self.allocator, abort_handle).await;
        Ok(())
    }

    async fn run_udp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        let dst_addr = lookup(self.dns.as_ref(), &self.dst).await?;
        let outbound = Arc::new(Egress::new(&self.iface_name).udpv4_socket().await?);
        outbound.connect(dst_addr).await?;
        established_udp(
            inbound,
            DirectUdpAdapter(outbound),
            self.allocator,
            abort_handle,
        )
        .await;
        Ok(())
    }
}

impl TcpOutBound for DirectOutbound {
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().run_tcp(inbound, abort_handle))
    }

    fn spawn_tcp_with_outbound<S>(
        &self,
        inbound: Connector,
        _outbound: S,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<Result<()>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tracing::warn!("spawn_tcp_with_outbound() should not be called with DirectOutbound");
        tokio::spawn(self.clone().run_tcp(inbound, abort_handle))
    }

    fn spawn_tcp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<io::Result<()>>) {
        let (inner, outer) = Connector::new_pair(10);
        (
            DuplexChan::new(self.allocator.clone(), inner),
            tokio::spawn(self.clone().run_tcp(outer, abort_handle)),
        )
    }
}

impl UdpOutBound for DirectOutbound {
    fn spawn_udp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().run_udp(inbound, abort_handle))
    }

    fn spawn_udp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<io::Result<()>>) {
        let (inner, outer) = Connector::new_pair(10);
        (
            DuplexChan::new(self.allocator.clone(), inner),
            self.spawn_tcp(outer, abort_handle),
        )
    }
}

#[derive(Clone, Debug)]
struct DirectUdpAdapter(Arc<UdpSocket>);

#[async_trait]
impl UdpSocketAdapter for DirectUdpAdapter {
    async fn send(&self, data: &[u8]) -> anyhow::Result<()> {
        self.0.send(data).await?;
        Ok(())
    }

    async fn recv(&self, data: &mut [u8]) -> anyhow::Result<(usize, bool)> {
        let (len, _) = self.0.recv_from(data).await?;
        // s is established by connect
        Ok((len, true))
    }
}
