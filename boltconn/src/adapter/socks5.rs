use crate::adapter::{
    established_tcp, established_udp, Connector, TcpOutBound, UdpOutBound, UdpSocketWrapper,
};
use crate::common::buf_pool::PktBufPool;
use crate::common::duplex_chan::DuplexChan;
use crate::common::{as_io_err, io_err};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use fast_socks5::client::Socks5Stream;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{AuthenticationMethod, Socks5Command};
use std::io;
use std::io::Result;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct Socks5Config {
    pub(crate) server_addr: NetworkAddr,
    pub(crate) auth: Option<(String, String)>,
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
    allocator: PktBufPool,
    dns: Arc<Dns>,
    config: Socks5Config,
}

impl Socks5Outbound {
    pub fn new(
        iface_name: &str,
        dst: NetworkAddr,
        allocator: PktBufPool,
        dns: Arc<Dns>,
        config: Socks5Config,
    ) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
            allocator,
            dns,
            config,
        }
    }

    async fn connect_proxy(&self) -> Result<(Socks5Stream<TcpStream>, SocketAddr)> {
        let server_addr = match self.config.server_addr {
            NetworkAddr::Raw(addr) => addr,
            NetworkAddr::DomainName {
                ref domain_name,
                port,
            } => {
                let resp = self
                    .dns
                    .genuine_lookup(domain_name.as_str())
                    .await
                    .ok_or(io_err("dns not found"))?;
                SocketAddr::new(resp, port)
            }
        };
        let socks_conn = match server_addr {
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
        let mut conn_cfg = fast_socks5::client::Config::default();
        conn_cfg.set_connect_timeout(8);
        Ok((
            Socks5Stream::use_stream(socks_conn, Some(self.config.get_auth()), conn_cfg)
                .await
                .map_err(|e| as_io_err(e))?,
            server_addr,
        ))
    }
    async fn run_tcp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        let (mut socks_stream, _) = self.connect_proxy().await?;
        let target = match self.dst {
            NetworkAddr::Raw(addr) => TargetAddr::Ip(addr),
            NetworkAddr::DomainName { domain_name, port } => TargetAddr::Domain(domain_name, port),
        };
        let _bound_addr = socks_stream
            .request(Socks5Command::TCPConnect, target)
            .await
            .map_err(|e| as_io_err(e))?;
        established_tcp(inbound, socks_stream, self.allocator, abort_handle).await;
        Ok(())
    }

    async fn run_udp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        let target = match &self.dst {
            NetworkAddr::Raw(addr) => TargetAddr::Ip(addr.clone()),
            NetworkAddr::DomainName { domain_name, port } => {
                TargetAddr::Domain(domain_name.clone(), port.clone())
            }
        };
        let (mut socks_stream, server_addr) = self.connect_proxy().await?;
        let out_sock = Arc::new(match server_addr {
            SocketAddr::V4(_) => Egress::new(&self.iface_name).udpv4_socket().await?,
            SocketAddr::V6(_) => return Err(io_err("udp v6 not supported")),
        });
        let bound_addr = socks_stream
            .request(Socks5Command::UDPAssociate, target.clone())
            .await
            .map_err(|e| as_io_err(e))?
            .to_socket_addrs()?
            .next()
            .unwrap();
        out_sock.connect(bound_addr).await?;
        established_udp(
            inbound,
            UdpSocketWrapper::Socks5(out_sock, target),
            self.allocator,
            abort_handle,
        )
        .await;
        Ok(())
    }
}

impl TcpOutBound for Socks5Outbound {
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

impl UdpOutBound for Socks5Outbound {
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
