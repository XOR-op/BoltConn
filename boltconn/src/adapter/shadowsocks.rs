use crate::adapter::{
    established_tcp, established_udp, lookup, AddrConnector, Connector, TcpOutBound, UdpOutBound,
    UdpSocketAdapter,
};

use crate::common::{io_err, OutboundTrait};
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
    dns: Arc<Dns>,
    config: ServerConfig,
}

impl SSOutbound {
    pub fn new(
        iface_name: &str,
        dst: NetworkAddr,
        dns: Arc<Dns>,
        config: ShadowSocksConfig,
    ) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
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
        established_tcp(inbound, ss_stream, abort_handle).await;
        Ok(())
    }

    async fn run_udp(self, inbound: AddrConnector, abort_handle: ConnAbortHandle) -> Result<()> {
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
        let self_clone = self.clone();
        tokio::spawn(async move {
            let server_addr = lookup(
                self_clone.dns.as_ref(),
                &match &self_clone.config.addr() {
                    ServerAddr::SocketAddr(s) => NetworkAddr::Raw(*s),
                    ServerAddr::DomainName(domain_name, port) => NetworkAddr::DomainName {
                        domain_name: domain_name.clone(),
                        port: *port,
                    },
                },
            )
            .await?;
            let tcp_conn = Egress::new(&self_clone.iface_name)
                .tcp_stream(server_addr)
                .await?;
            self_clone
                .run_tcp(inbound, tcp_conn, server_addr, abort_handle)
                .await
        })
    }

    fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        outbound: Box<dyn OutboundTrait>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let server_addr = lookup(
                self_clone.dns.as_ref(),
                &match &self_clone.config.addr() {
                    ServerAddr::SocketAddr(s) => NetworkAddr::Raw(*s),
                    ServerAddr::DomainName(domain_name, port) => NetworkAddr::DomainName {
                        domain_name: domain_name.clone(),
                        port: *port,
                    },
                },
            )
            .await?;
            self_clone
                .run_tcp(inbound, outbound, server_addr, abort_handle)
                .await
        })
    }
}

impl UdpOutBound for SSOutbound {
    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().run_udp(inbound, abort_handle))
    }
}

#[derive(Clone)]
struct ShadowsocksUdpAdapter(Arc<ProxySocket>, Address);

#[async_trait]
impl UdpSocketAdapter for ShadowsocksUdpAdapter {
    async fn send_to(&self, data: &[u8], addr: NetworkAddr) -> anyhow::Result<()> {
        self.0.send(&self.1, data).await?;
        Ok(())
    }

    async fn recv_from(&self, data: &mut [u8]) -> anyhow::Result<(usize, NetworkAddr)> {
        let (len, addr, _) = self.0.recv(data).await?;
        Ok((
            len,
            match addr {
                Address::SocketAddress(s) => NetworkAddr::Raw(s),
                Address::DomainNameAddress(domain_name, port) => {
                    NetworkAddr::DomainName { domain_name, port }
                }
            },
        ))
    }
}
