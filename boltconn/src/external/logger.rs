use chrono::Timelike;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tracing_subscriber::fmt::{format::Writer, time::FormatTime, MakeWriter};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Clone)]
pub struct StreamLoggerHandle {
    sender: broadcast::Sender<String>,
}

struct StreamLogger {
    sender: broadcast::Sender<String>,
}

impl StreamLoggerHandle {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(15);
        Self { sender }
    }

    pub fn subscribe(&self) -> StreamLoggerRecv {
        StreamLoggerRecv {
            receiver: self.sender.subscribe(),
        }
    }
}

impl std::io::Write for StreamLogger {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(s) = std::str::from_utf8(buf) {
            let _ = self.sender.send(s.to_string());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct StreamLoggerRecv {
    receiver: broadcast::Receiver<String>,
}

impl StreamLoggerRecv {
    pub async fn recv(&mut self) -> Result<String, RecvError> {
        loop {
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
    logger: broadcast::Sender<String>,
}
impl<'a> MakeWriter<'a> for LoggerMaker {
    type Writer = StreamLogger;

    fn make_writer(&'a self) -> Self::Writer {
        StreamLogger {
            sender: self.logger.clone(),
        }
    }
}

pub fn init_tracing(logger: &StreamLoggerHandle) {
    let stdout_layer = fmt::layer()
        .compact()
        .with_writer(std::io::stdout)
        .with_timer(SystemTime::default());
    let stream_layer = fmt::layer()
        .json()
        .with_writer(LoggerMaker {
            logger: logger.sender.clone(),
        })
        .with_timer(SystemTime::default());
    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(stream_layer)
        .with(EnvFilter::new("boltconn=trace"))
        .init();
}
