use crate::config::ConfigError;
use chrono::Timelike;
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tracing_subscriber::filter::Directive;
use tracing_subscriber::fmt::{MakeWriter, format::Writer, time::FormatTime};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct StreamLoggerSend {
    sender: broadcast::Sender<String>,
    backup: Arc<Mutex<VecDeque<String>>>,
}

impl StreamLoggerSend {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(50);
        Self {
            sender,
            backup: Arc::new(Mutex::new(Default::default())),
        }
    }

    pub fn subscribe(&self) -> StreamLoggerRecv {
        StreamLoggerRecv {
            receiver: self.sender.subscribe(),
            prior_buf: self.backup.lock().unwrap().clone(),
        }
    }
}

impl std::io::Write for StreamLoggerSend {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(s) = std::str::from_utf8(buf) {
            let _ = self.sender.send(s.to_string());
            let mut backup = self.backup.lock().unwrap();
            backup.push_back(s.to_string());
            if backup.len() > 20 {
                backup.pop_front();
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct StreamLoggerRecv {
    receiver: broadcast::Receiver<String>,
    prior_buf: VecDeque<String>,
}

impl StreamLoggerRecv {
    pub async fn recv(&mut self) -> Result<String, RecvError> {
        loop {
            if !self.prior_buf.is_empty() {
                return Ok(self.prior_buf.pop_front().unwrap());
            }
            match self.receiver.recv().await {
                Err(RecvError::Lagged(_)) => continue,
                r => return r,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SystemTime;

impl FormatTime for SystemTime {
    fn format_time(&self, w: &mut Writer<'_>) -> core::fmt::Result {
        let time = chrono::prelude::Local::now();
        write!(
            w,
            "{:02}:{:02}:{:02}.{:03}",
            time.hour() % 24,
            time.minute(),
            time.second(),
            time.timestamp_subsec_millis()
        )
    }
}

struct LoggerMaker {
    logger: StreamLoggerSend,
}

impl<'a> MakeWriter<'a> for LoggerMaker {
    type Writer = StreamLoggerSend;

    fn make_writer(&'a self) -> Self::Writer {
        self.logger.clone()
    }
}

pub fn init_tracing(logger: &StreamLoggerSend) -> Result<(), ConfigError> {
    #[cfg(not(feature = "tokio-console"))]
    {
        let stdout_layer = fmt::layer()
            .compact()
            .with_writer(std::io::stdout)
            .with_timer(SystemTime);
        let stream_layer = fmt::layer()
            .json()
            .with_writer(LoggerMaker {
                logger: logger.clone(),
            })
            .with_timer(SystemTime);
        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(stream_layer)
            .with(
                EnvFilter::builder()
                    .with_default_directive(
                        Directive::from_str("boltconn=trace")
                            .map_err(|_| ConfigError::Internal("Tracing filter"))?,
                    )
                    .from_env_lossy(),
            )
            .init();
        Ok(())
    }
    #[cfg(feature = "tokio-console")]
    {
        let console_layer = console_subscriber::ConsoleLayer::builder().spawn();
        tracing_subscriber::registry().with(console_layer).init();
        Ok(())
    }
}
