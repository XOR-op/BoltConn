use super::{AnytlsConfig, AnytlsSession, AnytlsSessionOptions, AnytlsStream};
use crate::proxy::NetworkAddr;
use crate::proxy::error::TransportError;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct AnytlsClient {
    inner: Arc<AnytlsClientInner>,
}

impl AnytlsClient {
    pub fn new(config: &AnytlsConfig) -> Self {
        Self::with_options(
            config.session_options(),
            config.reuse_session,
            config.idle_session_check_interval,
            config.idle_session_timeout,
            config.min_idle_session,
        )
    }

    pub fn with_options(
        options: AnytlsSessionOptions,
        reuse_session: bool,
        idle_session_check_interval: Duration,
        idle_session_timeout: Duration,
        min_idle_session: usize,
    ) -> Self {
        Self {
            inner: Arc::new(AnytlsClientInner {
                options,
                sessions: tokio::sync::Mutex::new(Vec::new()),
                problematic_session: Mutex::new(None),
                cleanup_handle: Mutex::new(None),
                next_seq: AtomicU64::new(0),
                closed: AtomicBool::new(false),
                reuse_session,
                idle_session_check_interval,
                idle_session_timeout,
                min_idle_session,
            }),
        }
    }

    pub async fn open_stream_with<S, F, Fut>(
        &self,
        dst: NetworkAddr,
        connect: F,
    ) -> Result<AnytlsStream, TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(S, Option<SocketAddr>), TransportError>>,
    {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(TransportError::Anytls("AnyTLS client is closed"));
        }

        self.cleanup_idle_sessions(false).await;
        while self.inner.reuse_session && !self.inner.closed.load(Ordering::Acquire) {
            let session = self.latest_idle_session().await;
            let Some(session) = session else {
                break;
            };
            match session.open_stream(dst.clone()).await {
                Ok(stream) => {
                    // A successful stream proves the pool recovered from any
                    // previously retained per-session failure.
                    *self.inner.problematic_session.lock().unwrap() = None;
                    return Ok(stream);
                }
                Err(err) => {
                    tracing::debug!(
                        "AnyTLS idle session {} failed while opening stream: {}",
                        session.seq(),
                        err
                    );
                    session.close();
                    self.remove_closed_sessions().await;
                }
            }
        }

        // check again
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(TransportError::Anytls("AnyTLS client is closed"));
        }

        let (stream, connected_endpoint) = connect().await?;
        let seq = self.inner.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let session = AnytlsSession::new_with_seq(
            stream,
            self.inner.options.clone(),
            seq,
            !self.inner.reuse_session,
        )
        .await?;
        let anytls_stream = session.open_stream(dst).await?;
        // Track non-reused sessions as well so evidence includes live streams;
        // reuse policy affects selection, not observability ownership.
        self.inner.sessions.lock().await.push(ManagedSession {
            session,
            connected_endpoint,
        });
        *self.inner.problematic_session.lock().unwrap() = None;
        Ok(anytls_stream)
    }

    pub fn spawn_idle_cleanup(&self) -> JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(this.inner.idle_session_check_interval);
            loop {
                interval.tick().await;
                if this.inner.closed.load(Ordering::Acquire) {
                    break;
                }
                this.cleanup_idle_sessions(true).await;
            }
        })
    }

    pub fn start_idle_cleanup(&self) {
        let mut handle = self.inner.cleanup_handle.lock().unwrap();
        if handle.is_none() {
            *handle = Some(self.spawn_idle_cleanup());
        }
    }

    async fn cleanup_idle_sessions(&self, send_heartbeat: bool) {
        let now = Instant::now();
        let mut sessions = self.inner.sessions.lock().await;
        retain_alive_sessions(&mut sessions, &self.inner.problematic_session);
        if send_heartbeat {
            // Reuse the pool's existing maintenance cadence for a lightweight
            // protocol heartbeat. Failed writes terminalize only that session;
            // the pool remains available to replace it on the next stream.
            for session in sessions.iter() {
                let _ = session.session.send_heartbeat();
            }
            retain_alive_sessions(&mut sessions, &self.inner.problematic_session);
        }

        let mut idle_sessions = sessions
            .iter()
            .filter(|session| session.session.is_idle())
            .cloned()
            .collect::<Vec<_>>();
        idle_sessions.sort_by_key(|session| std::cmp::Reverse(session.session.seq()));

        let mut retained_idle_count = 0usize;
        let mut close_seq = Vec::new();
        for session in idle_sessions {
            let expired = session
                .session
                .idle_since()
                .map(|idle_since| now.duration_since(idle_since) >= self.inner.idle_session_timeout)
                .unwrap_or(false);
            if !expired {
                retained_idle_count += 1;
                continue;
            }
            if retained_idle_count < self.inner.min_idle_session {
                retained_idle_count += 1;
                continue;
            }
            close_seq.push(session.session.seq());
        }

        if close_seq.is_empty() {
            return;
        }
        sessions.retain(|session| {
            if close_seq.contains(&session.session.seq()) {
                session.session.close();
                false
            } else {
                true
            }
        });
    }

    pub async fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        if let Some(handle) = self.inner.cleanup_handle.lock().unwrap().take() {
            handle.abort();
        }
        let mut sessions = self.inner.sessions.lock().await;
        for session in sessions.drain(..) {
            session.session.close();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub async fn link_snapshot(
        &self,
    ) -> (
        boltapi::LinkState,
        boltapi::LinkHealth,
        Vec<SocketAddr>,
        boltapi::LinkEvidence,
    ) {
        let mut sessions = self.inner.sessions.lock().await;
        retain_alive_sessions(&mut sessions, &self.inner.problematic_session);
        let session_count = sessions.len() as u64;
        let active_streams = sessions
            .iter()
            .map(|session| session.session.active_streams() as u64)
            .sum();
        let idle_sessions = sessions
            .iter()
            .filter(|session| session.session.is_idle())
            .count() as u64;
        let mut peer_versions = sessions
            .iter()
            .map(|session| session.session.peer_version())
            .collect::<Vec<_>>();
        peer_versions.sort_unstable();
        peer_versions.dedup();
        let mut endpoints = sessions
            .iter()
            .filter_map(|session| session.connected_endpoint)
            .collect::<Vec<_>>();
        endpoints.sort_unstable();
        endpoints.dedup();
        let problematic_session = self.inner.problematic_session.lock().unwrap().clone();
        let health = if self.is_closed() {
            boltapi::LinkHealth::Unhealthy
        } else if problematic_session.is_some() {
            boltapi::LinkHealth::Degraded
        } else {
            boltapi::LinkHealth::Healthy
        };
        let state = if self.is_closed() {
            boltapi::LinkState::Closed
        } else if active_streams == 0 {
            boltapi::LinkState::Idle
        } else {
            boltapi::LinkState::Ready
        };
        (
            state,
            health,
            endpoints,
            boltapi::LinkEvidence::Anytls {
                sessions: session_count,
                active_streams,
                idle_sessions,
                peer_versions,
                problematic_session,
            },
        )
    }

    async fn latest_idle_session(&self) -> Option<AnytlsSession> {
        self.inner
            .sessions
            .lock()
            .await
            .iter()
            .filter(|session| session.session.is_idle())
            .max_by_key(|session| session.session.seq())
            .map(|session| session.session.clone())
    }

    async fn remove_closed_sessions(&self) {
        let mut sessions = self.inner.sessions.lock().await;
        retain_alive_sessions(&mut sessions, &self.inner.problematic_session);
    }
}

struct AnytlsClientInner {
    options: AnytlsSessionOptions,
    sessions: tokio::sync::Mutex<Vec<ManagedSession>>,
    problematic_session: Mutex<Option<boltapi::AnytlsSessionEvidence>>,
    cleanup_handle: Mutex<Option<JoinHandle<()>>>,
    next_seq: AtomicU64,
    closed: AtomicBool,
    reuse_session: bool,
    idle_session_check_interval: Duration,
    idle_session_timeout: Duration,
    min_idle_session: usize,
}

#[derive(Clone)]
struct ManagedSession {
    session: AnytlsSession,
    connected_endpoint: Option<SocketAddr>,
}

fn retain_alive_sessions(
    sessions: &mut Vec<ManagedSession>,
    problematic: &Mutex<Option<boltapi::AnytlsSessionEvidence>>,
) {
    sessions.retain(|session| {
        if session.session.is_alive() {
            true
        } else {
            if let Some(evidence) = session.session.problematic_evidence() {
                *problematic.lock().unwrap() = Some(evidence);
            }
            false
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncReadExt;

    fn spawn_drain(mut server: tokio::io::DuplexStream) {
        tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            while server.read(&mut buffer).await.unwrap_or(0) != 0 {}
        });
    }

    #[tokio::test]
    async fn aggregate_evidence_tracks_sessions_streams_endpoints_and_close() {
        let client = AnytlsClient::with_options(
            AnytlsSessionOptions::new("secret"),
            true,
            Duration::from_secs(60),
            Duration::from_secs(60),
            0,
        );
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let stream = client
            .open_stream_with(NetworkAddr::from(endpoint), || async move {
                let (client, server) = tokio::io::duplex(8192);
                spawn_drain(server);
                Ok((client, Some(endpoint)))
            })
            .await
            .unwrap();

        let (state, health, endpoints, evidence) = client.link_snapshot().await;
        assert_eq!(state, boltapi::LinkState::Ready);
        assert_eq!(health, boltapi::LinkHealth::Healthy);
        assert_eq!(endpoints, vec![endpoint]);
        assert!(matches!(
            evidence,
            boltapi::LinkEvidence::Anytls {
                sessions: 1,
                active_streams: 1,
                idle_sessions: 0,
                ref peer_versions,
                problematic_session: None,
            } if peer_versions == &vec![1]
        ));

        drop(stream);
        let (state, _, _, evidence) = client.link_snapshot().await;
        assert_eq!(state, boltapi::LinkState::Idle);
        assert!(matches!(
            evidence,
            boltapi::LinkEvidence::Anytls {
                sessions: 1,
                active_streams: 0,
                idle_sessions: 1,
                ..
            }
        ));

        client.close().await;
        let (state, health, endpoints, evidence) = client.link_snapshot().await;
        assert_eq!(state, boltapi::LinkState::Closed);
        assert_eq!(health, boltapi::LinkHealth::Unhealthy);
        assert!(endpoints.is_empty());
        assert!(matches!(
            evidence,
            boltapi::LinkEvidence::Anytls { sessions: 0, .. }
        ));
    }
}
