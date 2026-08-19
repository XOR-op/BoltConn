use super::padding::{PaddingScheme, PaddingWriter, build_authentication_request};
use super::stream::{AnytlsStream, StreamEntry, StreamEvent, StreamState};
use super::{
    AnytlsSessionOptions, Command, FrameRead, FrameWrite, encode_socks_addr, lock_mutex,
    parse_settings, read_frame, settings_payload,
};
use crate::proxy::NetworkAddr;
use crate::proxy::error::TransportError;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone)]
pub struct AnytlsSession {
    pub(super) shared: Arc<SessionShared>,
}

impl AnytlsSession {
    pub async fn new<S>(stream: S, options: AnytlsSessionOptions) -> Result<Self, TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new_with_seq(stream, options, 0, false).await
    }

    /// `auto_close` closes the session as soon as its last stream finishes,
    /// instead of keeping it idle in a pool for reuse.
    pub async fn new_with_seq<S>(
        mut stream: S,
        options: AnytlsSessionOptions,
        seq: u64,
        auto_close: bool,
    ) -> Result<Self, TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let padding_scheme = options.current_padding_scheme();
        let auth_request = build_authentication_request(&options.password, &padding_scheme)?;
        stream.write_all(&auth_request).await?;
        stream.flush().await?;

        let (reader, writer) = tokio::io::split(stream);
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(SessionShared {
            write_tx,
            streams: Mutex::new(HashMap::new()),
            next_stream_id: AtomicU32::new(0),
            settings_sent: AtomicBool::new(false),
            alive: AtomicBool::new(true),
            active_streams: AtomicUsize::new(0),
            idle_since: Mutex::new(Some(Instant::now())),
            peer_version: AtomicU8::new(1),
            padding_scheme: options.padding_store(),
            padding_md5: padding_scheme.md5_hex().to_string(),
            client_name: options.client_name,
            seq,
            auto_close,
        });

        let writer_shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let res = writer_loop(
                writer,
                write_rx,
                PaddingWriter::new(padding_scheme),
                Arc::clone(&writer_shared),
            )
            .await;
            if let Err(err) = res {
                tracing::debug!("AnyTLS writer stopped: {}", err);
            }
            writer_shared.abort();
        });

        let reader_shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let res = reader_loop(reader, Arc::clone(&reader_shared)).await;
            if let Err(err) = res {
                tracing::debug!("AnyTLS reader stopped: {}", err);
            }
            reader_shared.close();
        });

        Ok(Self { shared })
    }

    pub async fn open_stream(&self, dst: NetworkAddr) -> Result<AnytlsStream, TransportError> {
        let payload = Bytes::from(encode_socks_addr(&dst)?);
        self.open_stream_with_initial_payload(payload).await
    }

    pub async fn open_stream_with_initial_payload(
        &self,
        initial_payload: Bytes,
    ) -> Result<AnytlsStream, TransportError> {
        if !self.shared.is_alive() {
            return Err(TransportError::Internal("AnyTLS session is closed"));
        }

        let stream_id = self
            .shared
            .next_stream_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| TransportError::Anytls("AnyTLS stream id exhausted"))?
            + 1;
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (synack_tx, synack_rx) = oneshot::channel();
        let state = Arc::new(StreamState {
            id: stream_id,
            session: Arc::clone(&self.shared),
            closed: AtomicBool::new(false),
        });
        self.shared.stream_started();
        {
            let mut streams = lock_mutex(&self.shared.streams);
            streams.insert(
                stream_id,
                StreamEntry {
                    events: events_tx,
                    synack: Mutex::new(Some(synack_tx)),
                    state: Arc::clone(&state),
                },
            );
        }

        let mut frames = Vec::with_capacity(3);
        if !self.shared.settings_sent.swap(true, Ordering::AcqRel) {
            frames.push(FrameWrite {
                command: Command::Settings,
                stream_id: 0,
                data: settings_payload(&self.shared.client_name, &self.shared.padding_md5),
            });
        }
        frames.push(FrameWrite {
            command: Command::Syn,
            stream_id,
            data: Bytes::new(),
        });
        if !initial_payload.is_empty() {
            frames.push(FrameWrite {
                command: Command::Psh,
                stream_id,
                data: initial_payload,
            });
        }

        if self
            .shared
            .write_tx
            .send(WriteRequest::Frames(frames))
            .is_err()
        {
            state.close(false);
            return Err(TransportError::Anytls("AnyTLS writer is closed"));
        }

        Ok(AnytlsStream {
            id: stream_id,
            events: events_rx,
            pending_read: Bytes::new(),
            state,
            synack: Some(synack_rx),
        })
    }

    pub fn close(&self) {
        self.shared.close();
    }

    pub fn is_alive(&self) -> bool {
        self.shared.is_alive()
    }

    pub fn is_idle(&self) -> bool {
        self.shared.is_alive() && self.shared.active_streams.load(Ordering::Acquire) == 0
    }

    pub fn idle_since(&self) -> Option<Instant> {
        *lock_mutex(&self.shared.idle_since)
    }

    pub fn seq(&self) -> u64 {
        self.shared.seq
    }

    pub fn peer_version(&self) -> u8 {
        self.shared.peer_version.load(Ordering::Acquire)
    }

    pub fn send_heartbeat(&self) -> Result<(), TransportError> {
        self.shared
            .write_tx
            .send(WriteRequest::Frames(vec![FrameWrite {
                command: Command::HeartRequest,
                stream_id: 0,
                data: Bytes::new(),
            }]))
            .map_err(|_| TransportError::Anytls("AnyTLS writer is closed"))
    }
}

pub(super) struct SessionShared {
    pub(super) write_tx: mpsc::UnboundedSender<WriteRequest>,
    streams: Mutex<HashMap<u32, StreamEntry>>,
    next_stream_id: AtomicU32,
    settings_sent: AtomicBool,
    alive: AtomicBool,
    active_streams: AtomicUsize,
    idle_since: Mutex<Option<Instant>>,
    pub(super) peer_version: AtomicU8,
    padding_scheme: Arc<Mutex<PaddingScheme>>,
    padding_md5: String,
    client_name: String,
    seq: u64,
    auto_close: bool,
}

impl SessionShared {
    pub(super) fn close(&self) {
        self.close_inner(true);
    }

    fn abort(&self) {
        self.close_inner(false);
    }

    fn close_inner(&self, notify_writer: bool) {
        if self.alive.swap(false, Ordering::AcqRel) {
            if notify_writer {
                let _ = self.write_tx.send(WriteRequest::Close);
            }
            let entries = {
                let mut streams = lock_mutex(&self.streams);
                streams.drain().map(|(_, entry)| entry).collect::<Vec<_>>()
            };
            for entry in entries {
                let _ = entry
                    .events
                    .send(StreamEvent::Reset("AnyTLS session closed".to_string()));
                entry.state.close(false);
            }
            *lock_mutex(&self.idle_since) = None;
        }
    }

    pub(super) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn stream_started(&self) {
        self.active_streams.fetch_add(1, Ordering::AcqRel);
        *lock_mutex(&self.idle_since) = None;
    }

    pub(super) fn stream_finished(&self) {
        let mut current = self.active_streams.load(Ordering::Acquire);
        while current != 0 {
            match self.active_streams.compare_exchange(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if current == 1 && self.is_alive() {
                        if self.auto_close {
                            // Not reusing sessions: tear down once the last
                            // stream finishes instead of pooling it.
                            self.close();
                        } else {
                            *lock_mutex(&self.idle_since) = Some(Instant::now());
                        }
                    }
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }

    pub(super) fn remove_stream(&self, stream_id: u32) {
        lock_mutex(&self.streams).remove(&stream_id);
    }

    fn update_padding_scheme(&self, raw_scheme: &[u8]) {
        match PaddingScheme::parse(raw_scheme) {
            Ok(scheme) => {
                tracing::debug!("AnyTLS padding scheme updated: {}", scheme.md5_hex());
                *lock_mutex(&self.padding_scheme) = scheme;
            }
            Err(err) => {
                tracing::warn!("AnyTLS padding scheme update ignored: {}", err);
            }
        }
    }
}

pub(super) enum WriteRequest {
    Frames(Vec<FrameWrite>),
    Close,
}

async fn writer_loop<W>(
    mut writer: W,
    mut write_rx: mpsc::UnboundedReceiver<WriteRequest>,
    mut padding_writer: PaddingWriter,
    shared: Arc<SessionShared>,
) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    while let Some(request) = write_rx.recv().await {
        match request {
            WriteRequest::Frames(frames) => {
                if !shared.is_alive() {
                    return Ok(());
                }
                let mut packet = Vec::new();
                for frame in frames {
                    super::append_frame(&mut packet, frame.command, frame.stream_id, &frame.data)?;
                }
                padding_writer.write_packet(&mut writer, &packet).await?;
                writer.flush().await?;
            }
            WriteRequest::Close => {
                let _ = writer.shutdown().await;
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn reader_loop<R>(mut reader: R, shared: Arc<SessionShared>) -> Result<(), TransportError>
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = read_frame(&mut reader).await?;
        handle_frame(frame, &shared)?;
    }
}

fn handle_frame(frame: FrameRead, shared: &Arc<SessionShared>) -> Result<(), TransportError> {
    match frame.command {
        Command::Psh => {
            if frame.data.is_empty() {
                return Ok(());
            }
            let events = lock_mutex(&shared.streams)
                .get(&frame.stream_id)
                .map(|entry| entry.events.clone());
            if let Some(events) = events {
                let _ = events.send(StreamEvent::Data(frame.data));
            }
        }
        Command::SynAck => handle_synack(frame, shared),
        Command::Fin => {
            let entry = lock_mutex(&shared.streams).remove(&frame.stream_id);
            if let Some(entry) = entry {
                let _ = entry.events.send(StreamEvent::Fin);
                entry.state.close(false);
            }
        }
        Command::Waste => {}
        Command::Alert => {
            let message = String::from_utf8_lossy(&frame.data).to_string();
            tracing::warn!("AnyTLS alert from server: {}", message);
            return Err(TransportError::InternalExtra(format!(
                "AnyTLS alert from server: {message}"
            )));
        }
        Command::UpdatePaddingScheme => {
            shared.update_padding_scheme(&frame.data);
        }
        Command::HeartRequest => {
            shared
                .write_tx
                .send(WriteRequest::Frames(vec![FrameWrite {
                    command: Command::HeartResponse,
                    stream_id: frame.stream_id,
                    data: Bytes::new(),
                }]))
                .map_err(|_| TransportError::Anytls("AnyTLS writer is closed"))?;
        }
        Command::HeartResponse => {}
        Command::ServerSettings => {
            let settings = parse_settings(&frame.data);
            if let Some(version) = settings.get("v").and_then(|v| v.parse::<u8>().ok()) {
                shared.peer_version.store(version, Ordering::Release);
            }
        }
        Command::Syn | Command::Settings => {}
        Command::Unknown(value) => {
            tracing::debug!("AnyTLS ignored unknown command {}", value);
        }
    }
    Ok(())
}

fn handle_synack(frame: FrameRead, shared: &Arc<SessionShared>) {
    let error = (!frame.data.is_empty()).then(|| String::from_utf8_lossy(&frame.data).to_string());
    let mut close_entry = None;
    {
        let mut streams = lock_mutex(&shared.streams);
        if let Some(entry) = streams.get(&frame.stream_id)
            && let Some(sender) = lock_mutex(&entry.synack).take()
        {
            let _ = sender.send(match error.clone() {
                Some(message) => Err(message),
                None => Ok(()),
            });
        }
        if error.is_some() {
            close_entry = streams.remove(&frame.stream_id);
        }
    }

    if let Some(entry) = close_entry {
        let message = error.unwrap_or_else(|| "remote stream open failed".to_string());
        let _ = entry.events.send(StreamEvent::Reset(message));
        entry.state.close(false);
    }
}

#[cfg(test)]
mod tests {
    use super::AnytlsSession;
    use crate::proxy::NetworkAddr;
    use crate::transport::anytls::AnytlsSessionOptions;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, DuplexStream};

    /// Continuously drain the peer end so session writes never block.
    fn spawn_drain(mut server: DuplexStream) {
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok(n) = server.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });
    }

    fn dst() -> NetworkAddr {
        NetworkAddr::from("1.1.1.1:80".parse::<SocketAddr>().unwrap())
    }

    #[tokio::test]
    async fn auto_close_session_closes_after_last_stream() {
        let (client, server) = tokio::io::duplex(8192);
        spawn_drain(server);
        let session =
            AnytlsSession::new_with_seq(client, AnytlsSessionOptions::new("password"), 1, true)
                .await
                .unwrap();
        let stream = session.open_stream(dst()).await.unwrap();
        assert!(session.is_alive());

        // Dropping the last stream tears the (non-reused) session down.
        drop(stream);
        assert!(!session.is_alive());
    }

    #[tokio::test]
    async fn pooled_session_stays_idle_after_last_stream() {
        let (client, server) = tokio::io::duplex(8192);
        spawn_drain(server);
        let session =
            AnytlsSession::new_with_seq(client, AnytlsSessionOptions::new("password"), 1, false)
                .await
                .unwrap();
        let stream = session.open_stream(dst()).await.unwrap();

        // A reusable session survives its stream and becomes idle for pooling.
        drop(stream);
        assert!(session.is_alive());
        assert!(session.is_idle());
    }
}
