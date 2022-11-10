use crate::adapter::{established_tcp, Connector};
use crate::common::buf_pool::PktBufPool;
use crate::common::duplex_chan::DuplexChan;
use crate::common::{as_io_err, io_err};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::session::NetworkAddr;
use fast_socks5::client::Socks5Stream;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{AuthenticationMethod, Socks5Command};
use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;

#[derive(Debug)]
pub struct Socks5Config {
    server_addr: SocketAddr,
    auth: AuthenticationMethod,
}

impl Socks5Config {
    fn get_auth(&self) -> AuthenticationMethod {
        match &self.auth {
            AuthenticationMethod::None => AuthenticationMethod::None,
            AuthenticationMethod::Password { username, password } => {
                AuthenticationMethod::Password {
                    username: username.clone(),
                    password: password.clone(),
                }
            }
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
    pub fn new(
        iface_name: &str,
        dst: NetworkAddr,
        allocator: PktBufPool,
        dns: Arc<Dns>,
        config: Arc<Socks5Config>,
    ) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
            allocator,
            dns,
            config,
        }
    }

    pub async fn run(self, inbound: Connector) -> Result<()> {
        let socks_conn = match self.config.server_addr {
            SocketAddr::V4(_) => {
                Egress::new(&self.iface_name)
                    .tcpv4_stream(self.config.server_addr)
                    .await?
            }
            SocketAddr::V6(_) => {
                Egress::new(&self.iface_name)
                    .tcpv6_stream(self.config.server_addr)
                    .await?
            }
        };
        let mut conn_cfg = fast_socks5::client::Config::default();
        conn_cfg.set_connect_timeout(15);
        let mut socks_stream =
            Socks5Stream::use_stream(socks_conn, Some(self.config.get_auth()), conn_cfg)
                .await
                .map_err(|e| as_io_err(e))?;
        let target = match self.dst {
            NetworkAddr::Raw(addr) => TargetAddr::Ip(addr),
            NetworkAddr::DomainName { domain_name, port } => TargetAddr::Domain(domain_name, port),
        };
        let _bound_addr = socks_stream
            .request(Socks5Command::TCPConnect, target)
            .await
            .map_err(|e| as_io_err(e))?;
        established_tcp(inbound, socks_stream, self.allocator).await;
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
