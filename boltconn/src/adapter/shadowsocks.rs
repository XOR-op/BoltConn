use crate::adapter::{
    established_tcp, established_udp, lookup, Connector, TcpOutBound, UdpOutBound, UdpSocketAdapter,
};
use crate::common::buf_pool::PktBufPool;
use crate::common::duplex_chan::DuplexChan;
use crate::common::io_err;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use async_trait::async_trait;
use io::Result;
use shadowsocks::config::ServerType;
use shadowsocks::context::SharedContext;
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
use shadowsocks::relay::Address;
use shadowsocks::{relay, ProxyClientStream, ProxySocket, ServerAddr, ServerConfig};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub struct ShadowSocksConfig {
    pub(crate) server_addr: ServerAddr,
    pub(crate) password: String,
    pub(crate) cipher_kind: shadowsocks::crypto::CipherKind,
    pub(crate) udp: bool,
}

impl From<ShadowSocksConfig> for ServerConfig {
    fn from(value: ShadowSocksConfig) -> Self {
        ServerConfig::new(value.server_addr, value.password, value.cipher_kind)
    }
}

#[derive(Clone)]
pub struct SSOutbound {
    iface_name: String,
    dst: NetworkAddr,
    allocator: PktBufPool,
    dns: Arc<Dns>,
    config: ServerConfig,
}

impl SSOutbound {
    pub fn new(
        iface_name: &str,
        dst: NetworkAddr,
        allocator: PktBufPool,
        dns: Arc<Dns>,
        config: ShadowSocksConfig,
    ) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
            allocator,
            dns,
            config: config.into(),
        }
    }

    async fn create_internal(
        &self,
        server_addr: SocketAddr,
    ) -> Result<(relay::Address, SharedContext, ServerConfig)> {
        let target_addr = match &self.dst {
            NetworkAddr::Raw(s) => shadowsocks::relay::Address::from(*s),
            NetworkAddr::DomainName { domain_name, port } => {
                shadowsocks::relay::Address::from((domain_name.clone(), *port))
            }
        };
        // ss configs
        let context = shadowsocks::context::Context::new_shared(ServerType::Local);
        let resolved_config =
            ServerConfig::new(server_addr, self.config.password(), self.config.method());
        Ok((target_addr, context, resolved_config))
    }

    async fn run_tcp<S>(
        self,
        inbound: Connector,
        outbound: S,
        server_addr: SocketAddr,
        abort_handle: ConnAbortHandle,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (target_addr, context, resolved_config) = self.create_internal(server_addr).await?;
        let ss_stream =
            ProxyClientStream::from_stream(context, outbound, &resolved_config, target_addr);
        established_tcp(inbound, ss_stream, self.allocator, abort_handle).await;
        Ok(())
    }

    async fn run_udp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        let server_addr = match self.config.addr() {
            ServerAddr::SocketAddr(addr) => *addr,
            ServerAddr::DomainName(addr, port) => {
                lookup(
                    self.dns.as_ref(),
                    &NetworkAddr::DomainName {
                        domain_name: addr.clone(),
                        port: *port,
                    },
                )
                    .await?
            }
        };
        let (target_addr, context, resolved_config) = self.create_internal(server_addr).await?;
        let out_sock = {
            let socket = match server_addr {
                SocketAddr::V4(_) => Egress::new(&self.iface_name).udpv4_socket().await?,
                SocketAddr::V6(_) => return Err(io_err("ss ipv6 udp not supported now")),
            };
            socket.connect(server_addr).await?;
            socket
        };
        let proxy_socket = Arc::new(ProxySocket::from_socket(
            UdpSocketType::Client,
            context,
            &resolved_config,
            out_sock,
        ));
        established_udp(
            inbound,
            ShadowsocksUdpAdapter(proxy_socket, target_addr),
            self.allocator,
            abort_handle,
        )
        .await;
        Ok(())
    }
}

impl TcpOutBound for SSOutbound {
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            let server_addr = lookup(self.dns.as_ref(), &self.config.server_addr).await?;
            let tcp_conn = Egress::new(&self.iface_name)
                .tcp_stream(server_addr)
                .await?;
            self.clone()
                .run_tcp(inbound, tcp_conn, server_addr, abort_handle)
        })
    }

    fn spawn_tcp_with_outbound<S>(
        &self,
        inbound: Connector,
        outbound: S,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<Result<()>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            let server_addr = lookup(self.dns.as_ref(), &self.config.server_addr).await?;
            self.clone()
                .run_tcp(inbound, outbound, server_addr, abort_handle)
        })
    }

    fn spawn_tcp_with_chan(
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

impl UdpOutBound for SSOutbound {
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
            tokio::spawn(self.clone().run_udp(outer, abort_handle)),
        )
    }
}

#[derive(Clone)]
struct ShadowsocksUdpAdapter(Arc<ProxySocket>, Address);

#[async_trait]
impl UdpSocketAdapter for ShadowsocksUdpAdapter {
    async fn send(&self, data: &[u8]) -> anyhow::Result<()> {
        self.0.send(&self.1, data).await?;
        Ok(())
    }

    async fn recv(&self, data: &mut [u8]) -> anyhow::Result<(usize, bool)> {
        let (len, addr, _) = self.0.recv(data).await?;
        Ok((len, addr == self.1))
    }
}
