use crate::proxy::NetworkAddr;
use crate::proxy::error::TransportError;
use boltapi::{LinkEvidence, LinkHealth, LinkReason, LinkReasonCode, LinkState, ProbeEvidence};
use russh::client::{Handle, Msg, connect_stream};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelStream, SshId};
use std::hash::Hash;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

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
    client: Arc<Handle<Client>>,
    port_counter: AtomicU16,
    is_active: Arc<AtomicBool>,
    open_channels: Arc<AtomicU64>,
    last_channel_open_at_ms: AtomicU64,
    probe: Mutex<ProbeState>,
    probe_task: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Default)]
struct ProbeState {
    last_attempt_at_ms: Option<u64>,
    last_success_at_ms: Option<u64>,
    last_error: Option<LinkReason>,
}

impl SshTunnel {
    pub async fn new<S>(config: &SshConfig, outbound: S) -> Result<Self, TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ru_config = Arc::new(russh::client::Config {
            client_id: SshId::Standard("SSH-2.0-OpenSSH_8.2p1".into()),
            ..Default::default()
        });
        Ok(Self {
            client: Arc::new(connect_ssh_tunnel(config, ru_config, outbound).await?),
            port_counter: AtomicU16::new(1025),
            is_active: Arc::new(AtomicBool::new(true)),
            open_channels: Arc::new(AtomicU64::new(0)),
            last_channel_open_at_ms: AtomicU64::new(0),
            probe: Mutex::new(ProbeState::default()),
            probe_task: Mutex::new(None),
        })
    }

    pub async fn new_mapped_connection(
        &self,
        dst: NetworkAddr,
    ) -> Result<TrackedSshChannel, TransportError> {
        let dst_port = dst.port();
        let channel = match self
            .client
            .channel_open_direct_tcpip(
                match dst {
                    NetworkAddr::Socket { address: ip } => ip.ip().to_string(),
                    NetworkAddr::Domain {
                        name: domain_name, ..
                    } => domain_name,
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
        self.open_channels.fetch_add(1, Ordering::Relaxed);
        self.last_channel_open_at_ms
            .store(now_ms(), Ordering::Relaxed);
        Ok(TrackedSshChannel {
            stream: channel.into_stream(),
            open_channels: self.open_channels.clone(),
        })
    }

    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::Relaxed) && !self.client.is_closed()
    }

    /// Starts one low-frequency request/reply probe. The task uses a weak
    /// reference so retaining the probe handle cannot keep the tunnel alive.
    pub fn start_probe(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let Some(tunnel) = weak.upgrade() else {
                    return;
                };
                if !tunnel.is_active() {
                    return;
                }
                tunnel.probe_once().await;
            }
        });
        *self.probe_task.lock().unwrap() = Some(task);
    }

    async fn probe_once(&self) {
        let attempted_at_ms = now_ms();
        self.probe.lock().unwrap().last_attempt_at_ms = Some(attempted_at_ms);
        let result = tokio::time::timeout(Duration::from_secs(10), self.client.send_ping()).await;
        let mut probe = self.probe.lock().unwrap();
        match result {
            Ok(Ok(())) => {
                probe.last_success_at_ms = Some(now_ms());
                probe.last_error = None;
            }
            Ok(Err(error)) => {
                probe.last_error = Some(LinkReason {
                    code: LinkReasonCode::ProtocolFailed,
                    detail: Some(crate::proxy::bounded_error_detail(&error.to_string())),
                });
                self.is_active.store(false, Ordering::Relaxed);
            }
            Err(_) => {
                probe.last_error = Some(LinkReason {
                    code: LinkReasonCode::NoRecentProbe,
                    detail: Some("SSH probe timed out".to_string()),
                });
                self.is_active.store(false, Ordering::Relaxed);
            }
        }
    }

    pub fn link_snapshot(&self) -> (LinkState, LinkHealth, LinkEvidence) {
        let task_alive = self.is_active();
        let probe = self.probe.lock().unwrap();
        let evidence = LinkEvidence::Ssh {
            task_alive,
            open_channels: self.open_channels.load(Ordering::Relaxed),
            last_channel_open_at_ms: match self.last_channel_open_at_ms.load(Ordering::Relaxed) {
                0 => None,
                timestamp => Some(timestamp),
            },
            probe: (probe.last_attempt_at_ms.is_some()
                || probe.last_success_at_ms.is_some()
                || probe.last_error.is_some())
            .then(|| ProbeEvidence {
                last_attempt_at_ms: probe.last_attempt_at_ms,
                last_success_at_ms: probe.last_success_at_ms,
                last_error: probe.last_error.clone(),
            }),
        };
        let health = if !task_alive {
            LinkHealth::Unhealthy
        } else if probe.last_error.is_some() {
            LinkHealth::Degraded
        } else {
            LinkHealth::Healthy
        };
        let state = if task_alive {
            if self.open_channels.load(Ordering::Relaxed) == 0 {
                LinkState::Idle
            } else {
                LinkState::Ready
            }
        } else {
            LinkState::Failed
        };
        (state, health, evidence)
    }

    pub async fn close(&self) {
        self.is_active.store(false, Ordering::Relaxed);
        if let Some(task) = self.probe_task.lock().unwrap().take() {
            task.abort();
        }
        let _ = self
            .client
            .disconnect(russh::Disconnect::ByApplication, "link closed", "")
            .await;
    }
}

pub struct TrackedSshChannel {
    stream: ChannelStream<Msg>,
    open_channels: Arc<AtomicU64>,
}

impl Drop for TrackedSshChannel {
    fn drop(&mut self) {
        let _ = self
            .open_channels
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_sub(1))
            });
    }
}

impl AsyncRead for TrackedSshChannel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrackedSshChannel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
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
    let res = match config.auth {
        SshAuthentication::Password(ref p) => handle.authenticate_password(&config.user, p).await,
        SshAuthentication::PrivateKey(ref k) => {
            handle.authenticate_publickey(&config.user, k.clone()).await
        }
    }
    .map_err(TransportError::Ssh)?;
    if !res.success() {
        tracing::debug!(
            "SSH authentication to {}@{} failed: {:?}",
            config.user,
            config.server,
            res
        );
        return Err(TransportError::Ssh(russh::Error::NotAuthenticated));
    }
    Ok(handle)
}
