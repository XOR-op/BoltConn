mod dispatching;
mod proxy;
mod rule;
mod ruleset;

use crate::adapter::{Connector, Outbound};
use crate::common::create_tls_connector;
use crate::common::duplex_chan::DuplexChan;
use crate::proxy::ConnAbortHandle;
pub use dispatching::*;
use http::Request;
use hyper::client::conn;
pub use proxy::*;
use std::sync::Arc;
use std::time::{Duration, SystemTime, SystemTimeError};

pub async fn latency_test(
    proxy: Arc<Proxy>,
    creator: Box<dyn Outbound>,
    url: &str,
    timeout: Duration,
) -> tokio::task::JoinHandle<()> {
    let tls_conector = create_tls_connector();
    let req = Request::builder().method("GET").uri(url).body(()).unwrap();
    let (inbound, outbound) = Connector::new_pair(10);
    let abort_handle = ConnAbortHandle::new();
    abort_handle.fulfill(vec![]).await;
    let proxy_handle = creator.spawn_tcp(inbound, abort_handle.clone());
    let http_handle = tokio::spawn(async move {
        let start_timer = SystemTime::now();
        let (mut sender, connection) = if url.starts_with("https") {
            let outbound = tls_conector
                .connect(server_name, DuplexChan::new(outbound))
                .await?;
            conn::Builder::new().handshake(outbound).await?
        } else {
            conn::Builder::new()
                .handshake(DuplexChan::new(outbound))
                .await?
        };
        tokio::spawn(async move { connection.await });
        let resp = sender.send_request(req).await?;
        let end_timer = SystemTime::now();
        match end_timer.duration_since(start_timer) {
            Ok(duration) => Latency::Value(duration.as_millis() as u32),
            Err(_) => Latency::Failed,
        }
    });
}
