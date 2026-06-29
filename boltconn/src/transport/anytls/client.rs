use super::{AnytlsConfig, AnytlsSession, AnytlsSessionOptions, AnytlsStream};
use crate::proxy::NetworkAddr;
use crate::proxy::error::TransportError;
use std::future::Future;
use std::sync::Arc;
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
        Fut: Future<Output = Result<S, TransportError>>,
    {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(TransportError::Anytls("AnyTLS client is closed"));
        }

        self.cleanup_idle_sessions().await;
        while self.inner.reuse_session && !self.inner.closed.load(Ordering::Acquire) {
            let session = self.latest_idle_session().await;
            let Some(session) = session else {
                break;
            };
            match session.open_stream(dst.clone()).await {
                Ok(stream) => return Ok(stream),
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

        let stream = connect().await?;
        let seq = self.inner.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let session = AnytlsSession::new_with_seq(
            stream,
            self.inner.options.clone(),
            seq,
            !self.inner.reuse_session,
        )
        .await?;
        let anytls_stream = session.open_stream(dst).await?;
        if self.inner.reuse_session {
            self.inner.sessions.lock().await.push(session);
        }
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
                this.cleanup_idle_sessions().await;
            }
        })
    }

    pub async fn cleanup_idle_sessions(&self) {
        let now = Instant::now();
        let mut sessions = self.inner.sessions.lock().await;
        sessions.retain(AnytlsSession::is_alive);

        let mut idle_sessions = sessions
            .iter()
            .filter(|session| session.is_idle())
            .cloned()
            .collect::<Vec<_>>();
        idle_sessions.sort_by_key(|session| std::cmp::Reverse(session.seq()));

        let mut retained_idle_count = 0usize;
        let mut close_seq = Vec::new();
        for session in idle_sessions {
            let expired = session
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
            close_seq.push(session.seq());
        }

        if close_seq.is_empty() {
            return;
        }
        sessions.retain(|session| {
            if close_seq.contains(&session.seq()) {
                session.close();
                false
            } else {
                true
            }
        });
    }

    pub async fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        let mut sessions = self.inner.sessions.lock().await;
        for session in sessions.drain(..) {
            session.close();
        }
    }

    async fn latest_idle_session(&self) -> Option<AnytlsSession> {
        self.inner
            .sessions
            .lock()
            .await
            .iter()
            .filter(|session| session.is_idle())
            .max_by_key(|session| session.seq())
            .cloned()
    }

    async fn remove_closed_sessions(&self) {
        self.inner
            .sessions
            .lock()
            .await
            .retain(AnytlsSession::is_alive);
    }
}

struct AnytlsClientInner {
    options: AnytlsSessionOptions,
    sessions: tokio::sync::Mutex<Vec<AnytlsSession>>,
    next_seq: AtomicU64,
    closed: AtomicBool,
    reuse_session: bool,
    idle_session_check_interval: Duration,
    idle_session_timeout: Duration,
    min_idle_session: usize,
}
