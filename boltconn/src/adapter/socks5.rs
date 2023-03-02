use crate::adapter::{
    established_tcp, established_udp, Connector, TcpOutBound, UdpOutBound, UdpSocketAdapter,
};
use crate::common::buf_pool::PktBufPool;
use crate::common::duplex_chan::DuplexChan;
use crate::common::{as_io_err, io_err};
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
use tokio::net::{TcpStream, UdpSocket};
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
                    .ok_or_else(|| io_err("dns not found"))?;
                SocketAddr::new(resp, port)
            }
        };
        let socks_conn = Egress::new(&self.iface_name)
            .tcp_stream(server_addr)
            .await?;
        let mut conn_cfg = fast_socks5::client::Config::default();
        conn_cfg.set_connect_timeout(8);
        Ok((
            Socks5Stream::use_stream(socks_conn, Some(self.config.get_auth()), conn_cfg)
                .await
                .map_err(as_io_err)?,
            server_addr,
        ))
    }
    async fn run_tcp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        let (mut socks_stream, _) = self.connect_proxy().await?;
        let target = self.dst.into();
        let _bound_addr = socks_stream
            .request(Socks5Command::TCPConnect, target)
            .await
            .map_err(as_io_err)?;
        established_tcp(inbound, socks_stream, self.allocator, abort_handle).await;
        Ok(())
    }

    async fn run_udp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        let target = match &self.dst {
            NetworkAddr::Raw(addr) => TargetAddr::Ip(*addr),
            NetworkAddr::DomainName { domain_name, port } => {
                TargetAddr::Domain(domain_name.clone(), *port)
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
            .map_err(as_io_err)?
            .to_socket_addrs()?
            .next()
            .unwrap();
        out_sock.connect(bound_addr).await?;
        established_udp(
            inbound,
            Socks5UdpAdapter(out_sock, target),
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

#[derive(Clone, Debug)]
struct Socks5UdpAdapter(Arc<UdpSocket>, TargetAddr);

#[async_trait]
impl UdpSocketAdapter for Socks5UdpAdapter {
    async fn send(&self, data: &[u8]) -> anyhow::Result<()> {
        let mut buf = match &self.1 {
            TargetAddr::Ip(s) => fast_socks5::new_udp_header(*s)?,
            TargetAddr::Domain(s, p) => fast_socks5::new_udp_header((s.as_str(), *p))?,
        };
        buf.extend_from_slice(data);
        self.0.send(buf.as_slice()).await?;
        Ok(())
    }

    async fn recv(&self, data: &mut [u8]) -> anyhow::Result<(usize, bool)> {
        let mut buf = [0u8; 0x10000];
        let (size, _) = self.0.recv_from(&mut buf).await?;
        let (frag, target_addr, raw_data) = fast_socks5::parse_udp_request(&buf[..size]).await?;
        if frag != 0 {
            return Err(anyhow::anyhow!("Unsupported frag value."));
        }
        data[..raw_data.len()].copy_from_slice(raw_data);
        Ok((
            raw_data.len(),
            match (&self.1, target_addr) {
                (TargetAddr::Ip(a), TargetAddr::Ip(b)) => *a == b,
                (TargetAddr::Domain(s1, p1), TargetAddr::Domain(s2, p2)) => *p1 == p2 && *s1 == s2,
                _ => false,
            },
        ))
    }
}
