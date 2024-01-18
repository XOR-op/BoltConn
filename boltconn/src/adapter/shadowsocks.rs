use crate::adapter::{
    established_tcp, established_udp, lookup, AddrConnector, Connector, Outbound, OutboundType,
};

use crate::common::{io_err, StreamOutboundTrait};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::{AdapterOrSocket, UdpSocketAdapter};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use io::Result;
use shadowsocks::config::ServerType;
use shadowsocks::context::SharedContext;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::udprelay::crypto_io::{decrypt_client_payload, encrypt_client_payload};
use shadowsocks::relay::{udprelay, Address};
use shadowsocks::{relay, ProxyClientStream, ServerAddr, ServerConfig};
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

    async fn get_server_addr(&self) -> Result<SocketAddr> {
        Ok(match self.config.addr() {
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
        })
    }

    async fn create_internal(
        &self,
        server_addr: SocketAddr,
    ) -> (relay::Address, SharedContext, ServerConfig) {
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
        (target_addr, context, resolved_config)
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
        let (target_addr, context, resolved_config) = self.create_internal(server_addr).await;
        let ss_stream =
            ProxyClientStream::from_stream(context, outbound, &resolved_config, target_addr);
        established_tcp(inbound, ss_stream, abort_handle).await;
        Ok(())
    }

    async fn run_udp(
        self,
        adapter_or_socket: AdapterOrSocket,
        inbound: AddrConnector,
        server_addr: SocketAddr,
        abort_handle: ConnAbortHandle,
        tunnel_only: bool,
    ) -> Result<()> {
        let (_, context, resolved_config) = self.create_internal(server_addr).await;
        let proxy_socket = ShadowsocksUdpAdapter::new(context, &resolved_config, adapter_or_socket);
        established_udp(
            inbound,
            proxy_socket,
            if tunnel_only { Some(self.dst) } else { None },
            abort_handle,
        )
        .await;
        Ok(())
    }
}

#[async_trait]
impl Outbound for SSOutbound {
    fn outbound_type(&self) -> OutboundType {
        OutboundType::Shadowsocks
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let server_addr = self_clone.get_server_addr().await?;
            let tcp_conn = Egress::new(&self_clone.iface_name)
                .tcp_stream(server_addr)
                .await?;
            self_clone
                .run_tcp(inbound, tcp_conn, server_addr, abort_handle)
                .await
        })
    }

    async fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> io::Result<bool> {
        if tcp_outbound.is_none() || udp_outbound.is_some() {
            tracing::error!("Invalid Shadowsocks tcp spawn");
            return Err(io::ErrorKind::InvalidData.into());
        }
        let server_addr = self.get_server_addr().await?;
        self.clone()
            .run_tcp(inbound, tcp_outbound.unwrap(), server_addr, abort_handle)
            .await?;
        Ok(true)
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
        tunnel_only: bool,
    ) -> JoinHandle<io::Result<()>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let server_addr = self_clone.get_server_addr().await?;
            let out_sock = {
                let socket = match server_addr {
                    SocketAddr::V4(_) => Egress::new(&self_clone.iface_name).udpv4_socket().await?,
                    SocketAddr::V6(_) => return Err(io_err("ss ipv6 udp not supported now")),
                };
                socket.connect(server_addr).await?;
                socket
            };
            self_clone
                .run_udp(
                    AdapterOrSocket::Socket(out_sock),
                    inbound,
                    server_addr,
                    abort_handle,
                    tunnel_only,
                )
                .await
        })
    }

    async fn spawn_udp_with_outbound(
        &self,
        inbound: AddrConnector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
        tunnel_only: bool,
    ) -> io::Result<bool> {
        if tcp_outbound.is_some() || udp_outbound.is_none() {
            tracing::error!("Invalid Shadowsocks UDP outbound ancestor");
            return Err(io::ErrorKind::InvalidData.into());
        }
        let udp_outbound = udp_outbound.unwrap();
        let server_addr = self.get_server_addr().await?;
        self.clone()
            .run_udp(
                AdapterOrSocket::Adapter(Arc::from(udp_outbound)),
                inbound,
                server_addr,
                abort_handle,
                tunnel_only,
            )
            .await?;
        Ok(true)
    }
}

struct ShadowsocksUdpAdapter {
    method: CipherKind,
    key: Box<[u8]>,
    context: SharedContext,
    identity_keys: Arc<Vec<Bytes>>,
    adapter_or_socket: AdapterOrSocket,
}

impl ShadowsocksUdpAdapter {
    pub fn new(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        adapter_or_socket: AdapterOrSocket,
    ) -> Self {
        let key = svr_cfg.key().to_vec().into_boxed_slice();
        let method = svr_cfg.method();
        Self {
            method,
            key,
            context,
            identity_keys: svr_cfg.clone_identity_keys(),
            adapter_or_socket,
        }
    }
}

#[async_trait]
impl UdpSocketAdapter for ShadowsocksUdpAdapter {
    async fn send_to(&self, data: &[u8], addr: NetworkAddr) -> anyhow::Result<()> {
        let ss_addr = match addr.clone() {
            NetworkAddr::Raw(s) => Address::SocketAddress(s),
            NetworkAddr::DomainName { domain_name, port } => {
                Address::DomainNameAddress(domain_name, port)
            }
        };
        let mut send_buf = BytesMut::new();
        encrypt_client_payload(
            &self.context,
            self.method,
            &self.key,
            &ss_addr,
            &udprelay::options::UdpSocketControlData::default(),
            &self.identity_keys,
            data,
            &mut send_buf,
        );

        match &self.adapter_or_socket {
            AdapterOrSocket::Adapter(a) => a.send_to(send_buf.as_ref(), addr).await?,
            AdapterOrSocket::Socket(s) => {
                s.send(send_buf.as_ref()).await?;
            }
        }
        Ok(())
    }

    async fn recv_from(&self, data: &mut [u8]) -> anyhow::Result<(usize, NetworkAddr)> {
        let len = match &self.adapter_or_socket {
            AdapterOrSocket::Adapter(a) => a.recv_from(data).await?.0,
            AdapterOrSocket::Socket(s) => s.recv(data).await?,
        };
        let (decrypted_size, addr, _) = decrypt_client_payload(
            &self.context,
            self.method,
            &self.key,
            &mut data[..len],
            None,
        )?;
        Ok((
            decrypted_size,
            match addr {
                Address::SocketAddress(s) => NetworkAddr::Raw(s),
                Address::DomainNameAddress(domain_name, port) => {
                    NetworkAddr::DomainName { domain_name, port }
                }
            },
        ))
    }
}
