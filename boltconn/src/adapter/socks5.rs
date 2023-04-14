use crate::adapter::{
    established_tcp, established_udp, lookup, AddrConnector, Connector, OutboundType, TcpOutBound,
    UdpOutBound, UdpSocketAdapter, UdpTransferType,
};

use crate::common::{as_io_err, io_err, OutboundTrait};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use async_trait::async_trait;
use fast_socks5::client::Socks5Stream;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{AuthenticationMethod, Socks5Command};
use std::io;
use std::io::Result;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct Socks5Config {
    pub(crate) server_addr: NetworkAddr,
    pub(crate) auth: Option<(String, String)>,
    pub(crate) udp: bool,
}

impl Socks5Config {
    fn get_auth(&self) -> AuthenticationMethod {
        match &self.auth {
            None => AuthenticationMethod::None,
            Some((username, password)) => AuthenticationMethod::Password {
                username: username.clone(),
                password: password.clone(),
            },
        }
    }
}

#[derive(Clone)]
pub struct Socks5Outbound {
    iface_name: String,
    dst: NetworkAddr,
    dns: Arc<Dns>,
    config: Socks5Config,
}

impl Socks5Outbound {
    pub fn new(iface_name: &str, dst: NetworkAddr, dns: Arc<Dns>, config: Socks5Config) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
            dns,
            config,
        }
    }

    async fn connect_proxy<S>(&self, outbound: S) -> Result<Socks5Stream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut conn_cfg = fast_socks5::client::Config::default();
        conn_cfg.set_connect_timeout(8);
        Socks5Stream::use_stream(outbound, Some(self.config.get_auth()), conn_cfg)
            .await
            .map_err(as_io_err)
    }

    async fn run_tcp<S>(
        self,
        inbound: Connector,
        outbound: S,
        abort_handle: ConnAbortHandle,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut socks_stream = self.connect_proxy(outbound).await?;
        let target = self.dst.into();
        let _bound_addr = socks_stream
            .request(Socks5Command::TCPConnect, target)
            .await
            .map_err(as_io_err)?;
        established_tcp(inbound, socks_stream, abort_handle).await;
        Ok(())
    }

    async fn run_udp<S>(
        self,
        inbound: AddrConnector,
        outbound: S,
        abort_handle: ConnAbortHandle,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let target = match &self.dst {
            NetworkAddr::Raw(addr) => TargetAddr::Ip(*addr),
            NetworkAddr::DomainName { domain_name, port } => {
                TargetAddr::Domain(domain_name.clone(), *port)
            }
        };
        let server_addr = lookup(self.dns.as_ref(), &self.config.server_addr).await?;
        let mut socks_stream = self.connect_proxy(outbound).await?;
        let out_sock = Arc::new(match server_addr {
            SocketAddr::V4(_) => Egress::new(&self.iface_name).udpv4_socket().await?,
            SocketAddr::V6(_) => return Err(io_err("udp v6 not supported")),
        });
        let bound_addr = socks_stream
            .request(Socks5Command::UDPAssociate, target.clone())
            .await
            .map_err(as_io_err)?
            .to_socket_addrs()?
            .next()
            .unwrap();
        out_sock.connect(bound_addr).await?;
        established_udp(inbound, Socks5UdpAdapter(out_sock), abort_handle).await;
        Ok(())
    }
}

impl TcpOutBound for Socks5Outbound {
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let server_addr =
                lookup(self_clone.dns.as_ref(), &self_clone.config.server_addr).await?;
            let socks_conn = Egress::new(&self_clone.iface_name)
                .tcp_stream(server_addr)
                .await?;
            self_clone.run_tcp(inbound, socks_conn, abort_handle).await
        })
    }

    fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        outbound: Box<dyn OutboundTrait>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().run_tcp(inbound, outbound, abort_handle))
    }
}

impl UdpOutBound for Socks5Outbound {
    fn outbound_type(&self) -> OutboundType {
        OutboundType::Socks5
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let server_addr =
                lookup(self_clone.dns.as_ref(), &self_clone.config.server_addr).await?;
            let socks_conn = Egress::new(&self_clone.iface_name)
                .tcp_stream(server_addr)
                .await?;
            self_clone.run_udp(inbound, socks_conn, abort_handle).await
        })
    }

    fn spawn_udp_with_outbound(
        &self,
        inbound: AddrConnector,
        _tcp_outbound: Option<Box<dyn OutboundTrait>>,
        _udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tracing::error!("Socks5 does not support UDP chain");
        self.spawn_udp(inbound, abort_handle)
    }
}

#[derive(Clone, Debug)]
struct Socks5UdpAdapter(Arc<UdpSocket>);

#[async_trait]
impl UdpSocketAdapter for Socks5UdpAdapter {
    async fn send_to(&self, data: &[u8], addr: NetworkAddr) -> anyhow::Result<()> {
        let mut buf = match addr {
            NetworkAddr::Raw(s) => fast_socks5::new_udp_header(s)?,
            NetworkAddr::DomainName { domain_name, port } => {
                fast_socks5::new_udp_header((domain_name.as_str(), port))?
            }
        };
        buf.extend_from_slice(data);
        self.0.send(buf.as_slice()).await?;
        Ok(())
    }

    async fn recv_from(&self, data: &mut [u8]) -> anyhow::Result<(usize, NetworkAddr)> {
        let mut buf = [0u8; 0x10000];
        let (size, _) = self.0.recv_from(&mut buf).await?;
        let (frag, target_addr, raw_data) = fast_socks5::parse_udp_request(&buf[..size]).await?;
        if frag != 0 {
            return Err(anyhow::anyhow!("Unsupported frag value."));
        }
        data[..raw_data.len()].copy_from_slice(raw_data);
        Ok((raw_data.len(), target_addr.into()))
    }
}
