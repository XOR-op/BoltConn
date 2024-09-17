use crate::cli::request_uds::UdsConnector;
use boltapi::rpc::ClientStreamService;
use boltapi::{ConnectionSchema, TrafficResp};
use colored::Colorize;
use serde::Deserialize;
use std::sync::Arc;
use tarpc::context::Context;
use tarpc::server::{BaseChannel, Channel};
use tokio::sync::{mpsc, RwLock};

#[derive(Clone)]
struct ClientStreamServer {
    traffic_sender: Arc<RwLock<Option<ChannelCtx<TrafficResp>>>>,
    logs_sender: Arc<RwLock<Option<ChannelCtx<String>>>>,
    conn_sender: Arc<RwLock<Option<ChannelCtx<Vec<ConnectionSchema>>>>>,
}

struct ChannelCtx<T> {
    handle: mpsc::UnboundedSender<T>,
    ctx_id: u64,
}

impl<T> ChannelCtx<T> {
    pub fn new(handle: mpsc::UnboundedSender<T>) -> Self {
        let id = fastrand::u64(1..u64::MAX);
        Self { handle, ctx_id: id }
    }
}

#[tarpc::server]
impl ClientStreamService for ClientStreamServer {
    async fn post_traffic(self, _: Context, traffic: TrafficResp) -> u64 {
        let guard = self.traffic_sender.read().await;
        if let Some(inner) = &*guard {
            let _ = inner.handle.send(traffic);
            inner.ctx_id
        } else {
            0
        }
    }

    async fn post_connections(self, _: Context, connections: Vec<ConnectionSchema>) -> u64 {
        let guard = self.conn_sender.read().await;
        if let Some(inner) = &*guard {
            let _ = inner.handle.send(connections);
            inner.ctx_id
        } else {
            0
        }
    }

    async fn post_log(self, _: Context, log: String) -> u64 {
        let guard = self.logs_sender.read().await;
        if let Some(inner) = &*guard {
            let _ = inner.handle.send(log);
            inner.ctx_id
        } else {
            0
        }
    }
}

pub struct ConnectionState {
    pub client: UdsConnector,
    traffic_sender: Arc<RwLock<Option<ChannelCtx<TrafficResp>>>>,
    logs_sender: Arc<RwLock<Option<ChannelCtx<String>>>>,
    connection_sender: Arc<RwLock<Option<ChannelCtx<Vec<ConnectionSchema>>>>>,
}

impl ConnectionState {
    pub async fn new(bind_addr: &str) -> anyhow::Result<Self> {
        let (client, server_chan) = UdsConnector::new(bind_addr).await?;
        let traffic = Arc::new(RwLock::new(None));
        let logs = Arc::new(RwLock::new(None));
        let conn = Arc::new(RwLock::new(None));
        let t2 = traffic.clone();
        let l2 = logs.clone();
        let c2 = conn.clone();
        tokio::spawn(
            BaseChannel::with_defaults(server_chan).execute(
                ClientStreamServer {
                    traffic_sender: traffic,
                    logs_sender: logs,
                    conn_sender: conn,
                }
                .serve(),
            ),
        );
        Ok(Self {
            client,
            traffic_sender: t2,
            logs_sender: l2,
            connection_sender: c2,
        })
    }

    pub async fn stream_log(&self) -> anyhow::Result<()> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut guard = self.logs_sender.write().await;
        let cctx = ChannelCtx::new(tx);
        let ctx_id = cctx.ctx_id;
        *guard = Some(cctx);
        drop(guard);
        self.client.get_log_stream(ctx_id).await?;
        colored::control::SHOULD_COLORIZE.set_override(true);
        loop {
            tokio::select! {
                Some(log) = rx.recv() => {
                    Self::print_line(log);
                }
                _ = tokio::signal::ctrl_c() => break,
                else => break,
            }
        }
        Ok(())
    }

    fn print_line(log: String) {
        if let Ok(item) = serde_json::from_str::<LogItem>(log.as_str()) {
            let space = match item.level {
                LogLevel::Trace | LogLevel::Debug | LogLevel::Error => " ",
                LogLevel::Info | LogLevel::Warn => "  ",
            };
            println!(
                "{}{}{} {}: {}",
                item.timestamp.dimmed(),
                space,
                item.level.colorize(),
                item.target.bold(),
                item.fields.message
            );
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
struct LogItem {
    timestamp: String,
    level: LogLevel,
    fields: LogFields,
    target: String,
}

#[derive(Deserialize, Clone, Debug)]
struct LogFields {
    message: String,
}

#[derive(Deserialize, Copy, Clone, Debug)]
#[serde(rename_all = "UPPERCASE")]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn colorize(&self) -> colored::ColoredString {
        match self {
            LogLevel::Trace => "TRACE".purple(),
            LogLevel::Debug => "DEBUG".blue(),
            LogLevel::Info => "INFO".green(),
            LogLevel::Warn => "WARN".yellow(),
            LogLevel::Error => "ERROR".red(),
        }
    }
}
