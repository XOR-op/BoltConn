use crate::proxy::error::TransportError;
use crate::proxy::NetworkAddr;
use russh::client::{connect_stream, Handle, Msg};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelStream, SshId};
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU16};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Clone)]
pub enum SshAuthentication {
    Password(String),
    PrivateKey(PrivateKeyWithHashAlg),
}

#[derive(Debug, Clone)]
pub struct SshConfig {
    pub server: NetworkAddr,
    pub user: String,
    pub auth: SshAuthentication,
    // todo: check host pubkey
    // (algo, pubkey)
    pub host_pubkey: Option<Vec<(String, PublicKey)>>,
}

impl PartialEq for SshConfig {
    fn eq(&self, other: &Self) -> bool {
        self.server == other.server && self.user == other.user
    }
}

impl Eq for SshConfig {}
impl Hash for SshConfig {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.server.hash(state);
        self.user.hash(state);
    }
}

struct Client {
    expected_server_key: Option<Vec<PublicKey>>,
}

impl russh::client::Handler for Client {
    type Error = TransportError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        if let Some(ref expected) = self.expected_server_key {
            for k in expected {
                if k == server_public_key {
                    return Ok(true);
                }
            }
            Ok(false)
        } else {
            Ok(true)
        }
    }
}

pub struct SshTunnel {
    client: Handle<Client>,
    port_counter: AtomicU16,
    is_active: Arc<AtomicBool>,
}

impl SshTunnel {
    pub async fn new<S>(config: &SshConfig, outbound: S) -> Result<Self, TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ru_config = Arc::new(russh::client::Config {
            client_id: SshId::Standard("SSH-2.0-OpenSSH_8.2p1".to_string()),
            ..Default::default()
        });
        Ok(Self {
            client: connect_ssh_tunnel(config, ru_config, outbound).await?,
            port_counter: AtomicU16::new(1025),
            is_active: Arc::new(AtomicBool::new(true)),
        })
    }

    pub async fn new_mapped_connection(
        &self,
        dst: NetworkAddr,
    ) -> Result<ChannelStream<Msg>, TransportError> {
        let dst_port = dst.port();
        let channel = match self
            .client
            .channel_open_direct_tcpip(
                match dst {
                    NetworkAddr::Raw(ip) => ip.ip().to_string(),
                    NetworkAddr::DomainName { domain_name, .. } => domain_name,
                },
                dst_port as u32,
                "127.0.0.1",
                self.port_counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u32,
            )
            .await
            .map_err(TransportError::Ssh)
        {
            Ok(c) => c,
            Err(e) => {
                self.is_active
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(e);
            }
        };
        Ok(channel.into_stream())
    }

    pub fn is_active(&self) -> bool {
        self.is_active.load(std::sync::atomic::Ordering::Relaxed)
    }
}

async fn connect_ssh_tunnel<S>(
    config: &SshConfig,
    ru_config: Arc<russh::client::Config>,
    outbound: S,
) -> Result<Handle<Client>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ssh_handler = Client {
        expected_server_key: config
            .host_pubkey
            .as_ref()
            .map(|v| v.iter().map(|(_, k)| k.clone()).collect::<Vec<PublicKey>>()),
    };
    let mut handle = connect_stream(ru_config, outbound, ssh_handler).await?;
    if !(match config.auth {
        SshAuthentication::Password(ref p) => handle.authenticate_password(&config.user, p).await,
        SshAuthentication::PrivateKey(ref k) => {
            handle.authenticate_publickey(&config.user, k.clone()).await
        }
    }
    .map_err(TransportError::Ssh)?
    .success())
    {
        return Err(TransportError::Ssh(russh::Error::NotAuthenticated));
    }
    Ok(handle)
}
