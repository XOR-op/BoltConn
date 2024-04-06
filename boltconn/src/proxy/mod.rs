mod context;
mod dispatcher;
mod http_inbound;
mod manager;
mod mixed_inbound;
mod session_ctl;
mod socks5_inbound;
mod tun_inbound;
mod tun_udp_inbound;

use crate::adapter::{Connector, Outbound};
use crate::common::create_tls_connector;
use crate::common::duplex_chan::DuplexChan;
use crate::dispatch::{Latency, Proxy, ProxyImpl};
use bytes::Bytes;
pub use context::*;
pub use dispatcher::*;
use http::Request;
pub use http_inbound::*;
use hyper::client::conn;
use hyper_util::rt::TokioIo;
pub use manager::*;
pub use mixed_inbound::*;
use rand::{Rng, SeedableRng};
pub use socks5_inbound::*;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::ServerName;
pub use tun_inbound::*;
pub use tun_udp_inbound::*;
use url::Host;

fn get_random_local_addr(dst: &NetworkAddr, port: u16) -> SocketAddr {
    match dst {
        NetworkAddr::Raw(SocketAddr::V4(_)) | NetworkAddr::DomainName { .. } => {
            SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), port)
        }
        NetworkAddr::Raw(SocketAddr::V6(_)) => {
            SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(), port)
        }
    }
}

pub async fn latency_test(
    dispatcher: &Dispatcher,
    proxy: Arc<Proxy>,
    url: &str,
    timeout: Duration,
    iface: Option<String>,
) -> anyhow::Result<JoinHandle<()>> {
    let tls_conector = create_tls_connector(None);
    let req = Request::builder()
        .method("GET")
        .uri(url)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let (inbound, outbound) = Connector::new_pair(10);
    let parsed_url = url::Url::parse(url)?;
    let port = match parsed_url.port() {
        Some(p) => p,
        None => match parsed_url.scheme() {
            "https" => 443,
            "http" => 80,
            _ => return Err(anyhow::anyhow!("Invalid test url scheme")),
        },
    };
    let dst_addr = match parsed_url
        .host()
        .ok_or(anyhow::anyhow!("No host in test url"))?
    {
        Host::Domain(domain) => NetworkAddr::DomainName {
            domain_name: domain.to_string(),
            port,
        },
        Host::Ipv4(ip) => NetworkAddr::Raw(SocketAddr::new(ip.into(), port)),
        Host::Ipv6(ip) => NetworkAddr::Raw(SocketAddr::new(ip.into(), port)),
    };
    let server_name = match &dst_addr {
        NetworkAddr::Raw(s) => ServerName::IpAddress(s.ip().into()),
        NetworkAddr::DomainName {
            domain_name,
            port: _,
        } => ServerName::try_from(domain_name.as_str())?,
    }
    .to_owned();
    let mut rng = rand::rngs::SmallRng::seed_from_u64(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::default())
            .as_secs(),
    );
    let iface = iface.unwrap_or(dispatcher.get_iface_name());

    // create outbound
    let creator: Box<dyn Outbound> = match proxy.get_impl().as_ref() {
        ProxyImpl::Chain(vec) => {
            match dispatcher.create_chain(
                vec,
                get_random_local_addr(&dst_addr, rng.gen_range(32768..65535)),
                &dst_addr,
                iface.as_str(),
            ) {
                Ok(o) => Box::new(o),
                Err(_) => {
                    proxy.set_latency(Latency::Failed);
                    return Err(anyhow::anyhow!("Create outbound failed"));
                }
            }
        }
        proxy_config => {
            let creator = match dispatcher.build_normal_outbound(
                iface.as_str(),
                proxy_config,
                get_random_local_addr(&dst_addr, rng.gen_range(32768..65535)),
                &dst_addr,
                None,
            ) {
                Ok((o, _)) => o,
                Err(_) => {
                    proxy.set_latency(Latency::Failed);
                    return Err(anyhow::anyhow!("Create outbound failed"));
                }
            };
            creator
        }
    };

    let proxy_handle = creator.spawn_tcp(inbound, ConnAbortHandle::placeholder());

    // connect to the url
    let http_handle: JoinHandle<anyhow::Result<Latency>> = tokio::spawn(async move {
        let start_timer = SystemTime::now();
        if parsed_url.scheme() == "https" {
            let outbound = tls_conector
                .connect(server_name, DuplexChan::new(outbound))
                .await?;
            let (mut sender, connection) = conn::http1::Builder::new()
                .handshake(TokioIo::new(outbound))
                .await?;
            tokio::spawn(connection);
            let _ = sender.send_request(req).await?;
        } else {
            let (mut sender, connection) = conn::http1::Builder::new()
                .handshake(TokioIo::new(DuplexChan::new(outbound)))
                .await?;
            tokio::spawn(connection);
            let _ = sender.send_request(req).await?;
        };
        let end_timer = SystemTime::now();
        match end_timer.duration_since(start_timer) {
            Ok(duration) => Ok(Latency::Value(duration.as_millis() as u32)),
            Err(_) => Ok(Latency::Failed),
        }
    });

    let timeout_future = tokio::spawn(async move {
        if let Ok(Ok(Ok(l))) = tokio::time::timeout(timeout, http_handle).await {
            proxy.set_latency(l);
        } else {
            proxy.set_latency(Latency::Failed)
        }
        proxy_handle.abort()
    });
    Ok(timeout_future)
}
