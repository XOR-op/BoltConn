use crate::proxy::error::TransportError;
use crate::proxy::NetworkAddr;
use async_trait::async_trait;
use russh::client::{connect_stream, Handle, Msg};
use russh::keys::key::KeyPair;
use russh::ChannelStream;
use std::sync::atomic::AtomicU16;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Clone)]
pub enum SshAuthentication {
    Password(String),
    PrivateKey(Arc<KeyPair>),
}

#[derive(Debug, Clone)]
pub struct SshConfig {
    internal_cfg: Arc<russh::client::Config>,
    user: String,
    auth: SshAuthentication,
}

impl SshConfig {
    pub fn new(user: String, auth: SshAuthentication) -> Self {
        Self {
            internal_cfg: Arc::new(russh::client::Config::default()),
            user,
            auth,
        }
    }
}

struct Client {}

#[async_trait]
impl russh::client::Handler for Client {
    type Error = TransportError;
}
pub struct SshTunnel {
    client: Handle<Client>,
    port_counter: AtomicU16,
}

impl SshTunnel {
    pub fn new<S>(config: SshConfig, outbound: S) -> Result<Self, TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Ok(Self {
            client: connect_ssh_tunnel(&config, outbound)?,
            port_counter: AtomicU16::new(1025),
        })
    }

    pub async fn new_mapped_connection(
        &self,
        dst: NetworkAddr,
    ) -> Result<ChannelStream<Msg>, TransportError> {
        let dst_port = dst.port();
        let channel = self
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
            .map_err(TransportError::Ssh)?;
        Ok(channel.into_stream())
    }
}

async fn connect_ssh_tunnel<S>(
    config: &SshConfig,
    outbound: S,
) -> Result<Handle<Client>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ssh_handler = Client {};
    let mut handle = connect_stream(config.internal_cfg.clone(), outbound, ssh_handler).await?;
    if !(match config.auth {
        SshAuthentication::Password(ref p) => handle.authenticate_password(&config.user, p).await,
        SshAuthentication::PrivateKey(ref k) => {
            handle.authenticate_publickey(&config.user, k.clone()).await
        }
    }
    .map_err(TransportError::Ssh)?)
    {
        return Err(TransportError::Ssh(russh::Error::NotAuthenticated));
    }
    Ok(handle)
}
