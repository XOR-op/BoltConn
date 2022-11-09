use crate::adapter::{Connector, established_tcp};
use crate::common::buf_pool::PktBufPool;
use crate::common::duplex_chan::DuplexChan;
use crate::network::dns::Dns;
use crate::session::NetworkAddr;
use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use fast_socks5::{AuthenticationMethod, Socks5Command};
use fast_socks5::client::Socks5Stream;
use fast_socks5::util::target_addr::TargetAddr;
use tokio::task::JoinHandle;
use crate::network::egress::Egress;

#[derive(Debug)]
pub struct Socks5Config {
    server_addr: SocketAddr,
    auth: AuthenticationMethod,
}

impl Socks5Config {
    fn get_auth(&self) -> AuthenticationMethod {
        match &self.auth {
            AuthenticationMethod::None => AuthenticationMethod::None
            AuthenticationMethod::Password { username, password } =>
                AuthenticationMethod::Password { username: username.clone(), password: password.clone() }
        }
    }
}

#[derive(Clone)]
pub struct Socks5Outbound {
    iface_name: String,
    dst: NetworkAddr,
    allocator: PktBufPool,
    dns: Arc<Dns>,
    config: Arc<Socks5Config>,
}

impl Socks5Outbound {
    pub fn new(iface_name: &str, dst: NetworkAddr, allocator: PktBufPool, dns: Arc<Dns>, config: Arc<Socks5Config>) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
            allocator,
            dns,
            config,
        }
    }

    pub async fn run(self, inbound: Connector) -> Result<()> {
        let socks_conn = match dst_addr {
            SocketAddr::V4(_) => Egress::new(&self.iface_name).tcpv4_stream(dst_addr).await?,
            SocketAddr::V6(_) => Egress::new(&self.iface_name).tcpv6_stream(dst_addr).await?,
        };
        let mut conn_cfg = fast_socks5::client::Config::default();
        conn_cfg.set_connect_timeout(15);
        let mut socks_stream = Socks5Stream::use_stream(
            socks_conn, Some(self.config.get_auth()), conn_cfg).await?;
        let target = match self.dst {
            NetworkAddr::Raw(addr) => TargetAddr::Ip(addr),
            NetworkAddr::DomainName { domain_name, port } => TargetAddr::Domain(domain_name, port)
        };
        let _bound_addr = socks_stream.request(Socks5Command::TCPConnect, target).await?;
        established_tcp(inbound, outbound, self.allocator).await;
        Ok(())
    }

    pub fn as_async(&self) -> (DuplexChan, JoinHandle<Result<()>>) {
        let (inner, outer) = Connector::new_pair(10);
        (
            DuplexChan::new(self.allocator.clone(), inner),
            tokio::spawn(self.clone().run(outer)),
        )
    }
}
