use crate::adapter::{
    established_tcp, established_udp, Connector, TcpOutBound, UdpOutBound, UdpSocketWrapper,
};
use crate::common::buf_pool::PktBufPool;
use crate::common::duplex_chan::DuplexChan;
use crate::common::io_err;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use io::Result;
use shadowsocks::config::ServerType;
use shadowsocks::context::SharedContext;
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
use shadowsocks::{relay, ProxyClientStream, ProxySocket, ServerAddr, ServerConfig};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;

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
        config: ServerConfig,
    ) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
            allocator,
            dns,
            config,
        }
    }

    async fn create_internal(
        &self,
    ) -> Result<(relay::Address, SharedContext, ServerConfig, SocketAddr)> {
        let target_addr = match &self.dst {
            NetworkAddr::Raw(s) => shadowsocks::relay::Address::from(s.clone()),
            NetworkAddr::DomainName { domain_name, port } => {
                shadowsocks::relay::Address::from((domain_name.clone(), port.clone()))
            }
        };
        // ss configs
        let context = shadowsocks::context::Context::new_shared(ServerType::Local);
        let (resolved_config, server_addr) = match self.config.addr().clone() {
            ServerAddr::SocketAddr(p) => (self.config.clone(), p),
            ServerAddr::DomainName(domain_name, port) => {
                let resp = self
                    .dns
                    .genuine_lookup(domain_name.as_str())
                    .await
                    .ok_or(io_err("dns not found"))?;
                let addr = SocketAddr::new(resp, port);
                (
                    ServerConfig::new(addr, self.config.password(), self.config.method()),
                    addr.clone(),
                )
            }
        };
        Ok((target_addr, context, resolved_config.clone(), server_addr))
    }

    async fn run_tcp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        let (target_addr, context, resolved_config, server_addr) = self.create_internal().await?;
        let tcp_conn = match server_addr {
            SocketAddr::V4(_) => {
                Egress::new(&self.iface_name)
                    .tcpv4_stream(server_addr)
                    .await?
            }
            SocketAddr::V6(_) => {
                Egress::new(&self.iface_name)
                    .tcpv6_stream(server_addr)
                    .await?
            }
        };
        let ss_stream =
            ProxyClientStream::from_stream(context, tcp_conn, &resolved_config, target_addr);
        established_tcp(inbound, ss_stream, self.allocator, abort_handle).await;
        Ok(())
    }

    async fn run_udp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        let (target_addr, context, resolved_config, server_addr) = self.create_internal().await?;
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
            UdpSocketWrapper::SS(proxy_socket, target_addr),
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
