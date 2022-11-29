#![allow(unused_imports)]
#![allow(dead_code)]

extern crate core;

use crate::config::{LinkedState, RawRootCfg, RawState};
use crate::dispatch::{Dispatching, DispatchingBuilder};
use crate::external::ApiServer;
use crate::proxy::{HttpCapturer, StatCenter};
use crate::sniff::Recorder;
use chrono::Timelike;
use common::buf_pool::PktBufPool;
use ipnet::Ipv4Net;
use network::tun_device::TunDevice;
use network::{
    dns::{Dns, DnsRoutingHandle},
    packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt},
};
use platform::get_default_route;
use proxy::Dispatcher;
use proxy::{Nat, SessionManager};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::{fs, io};
use tokio_rustls::rustls::{Certificate, PrivateKey};
use tracing::{event, Level};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod adapter;
mod common;
mod config;
mod dispatch;
mod external;
mod network;
mod platform;
mod proxy;
mod sniff;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SystemTime;

impl FormatTime for SystemTime {
    fn format_time(&self, w: &mut Writer<'_>) -> core::fmt::Result {
        let time = chrono::prelude::Local::now();
        write!(
            w,
            "{:02}:{:02}:{:02}.{:03}",
            (time.hour() + 8) % 24,
            time.minute(),
            time.second(),
            time.timestamp_subsec_millis()
        )
    }
}

fn load_cert_and_key(
    cert_path: &str,
    key_path: &str,
) -> io::Result<(Vec<Certificate>, PrivateKey)> {
    let cert_raw = fs::read(cert_path)?;
    let mut cert_bytes = cert_raw.as_slice();
    let key_raw = fs::read(key_path)?;
    let mut key_bytes = key_raw.as_slice();
    let cert = Certificate(rustls_pemfile::certs(&mut cert_bytes)?.remove(0));
    let key = PrivateKey(rustls_pemfile::pkcs8_private_keys(&mut key_bytes)?.remove(0));
    Ok((vec![cert], key))
}

fn load_config(config_path: &str, state_path: &str) -> anyhow::Result<(RawRootCfg, RawState)> {
    let config_text = fs::read_to_string(config_path)?;
    let raw_config: RawRootCfg = serde_yaml::from_str(&config_text).unwrap();
    let state_text = fs::read_to_string(state_path)?;
    let raw_state: RawState = serde_yaml::from_str(&state_text).unwrap();
    Ok((raw_config, raw_state))
}

fn initialize_dispatching(
    raw_config: &RawRootCfg,
    raw_state: &RawState,
) -> anyhow::Result<Arc<Dispatching>> {
    let builder = DispatchingBuilder::new_from_config(&raw_config, &raw_state)?;
    Ok(Arc::new(builder.build()))
}

fn main() {
    let config_path = "./_private/config/config.yml";
    let state_path = "./_private/config/state.yml";
    let crt_path = "_private/ca/crt.pem";
    let privkey_path = "_private/ca/key.pem";

    // tokio and tracing
    let rt = tokio::runtime::Runtime::new().expect("Tokio failed to initialize");
    let formatting_layer = fmt::layer()
        .compact()
        .with_writer(std::io::stdout)
        .with_timer(SystemTime::default());
    tracing_subscriber::registry()
        .with(formatting_layer)
        .with(EnvFilter::new("boltconn=trace"))
        .init();

    // configuration
    let (config, state) = load_config(config_path, state_path).expect("Failed to load config");
    let dns_config = config
        .dns
        .iter()
        .map(|s| s.parse().ok())
        .flatten()
        .collect();
    let dispatching =
        initialize_dispatching(&config, &state).expect("Failed to initialize dispatching");

    // interface
    let (gateway_address, real_iface_name) = get_default_route().expect("failed to get default route");

    // guards
    let _guard = rt.enter();
    let dns_guard = platform::SystemDnsHandle::new("198.18.99.88".parse().unwrap())
        .expect("fail to replace /etc/resolv.conf");
    let dns_routing_guard = DnsRoutingHandle::new(gateway_address, real_iface_name.as_str(), &dns_config)
        .expect("fail to add dns route table");

    // initialize resources
    let manager = Arc::new(SessionManager::new());
    let dns = Arc::new(Dns::new(&dns_config).expect("DNS failed to initialize"));
    let tun = rt.block_on(async {
        let pool = PktBufPool::new(512, 4096);
        let mut tun = TunDevice::open(manager.clone(), pool, real_iface_name.as_str(), dns.clone())
            .expect("fail to create TUN");
        // create tun device
        event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
        tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 1), 16).unwrap())
            .expect("TUN failed to set address");
        tun.up().expect("TUN failed to up");
        tun
    });

    // dispatcher and statistics
    let stat_center = Arc::new(StatCenter::new());
    let http_capturer = Arc::new(HttpCapturer::new());
    let dispatcher = {
        // tls mitm
        let (cert, priv_key) =
            load_cert_and_key(crt_path, privkey_path).expect("Failed to parse cert & key");
        let proxy_allocator = PktBufPool::new(512, 4096);
        Arc::new(Dispatcher::new(
            real_iface_name.as_str(),
            proxy_allocator,
            dns.clone(),
            stat_center.clone(),
            dispatching.clone(),
            cert,
            priv_key,
            Arc::new(Recorder::new(http_capturer.clone())),
        ))
    };

    // external controller
    let api_server = ApiServer::new(
        manager.clone(),
        stat_center.clone(),
        Some(http_capturer.clone()),
        dispatching.clone(),
        LinkedState {
            state_path: state_path.to_string(),
            state,
        },
    );
    let api_port = config.api_port;

    // run
    let nat_addr = SocketAddr::new(
        platform::get_iface_address(tun.get_name()).expect("failed to get tun address"),
        9961,
    );
    let nat = Nat::new(nat_addr, manager.clone(), dispatcher, dns);
    let _nat_handle = rt.spawn(async move { nat.run_tcp().await });
    let _tun_handle = rt.spawn(async move { tun.run(nat_addr).await });
    let _api_handle = rt.spawn(async move { api_server.run(api_port).await });
    rt.block_on(async { tokio::signal::ctrl_c().await })
        .expect("Tokio runtime error");
    drop(dns_guard);
    drop(dns_routing_guard);
    // rt.shutdown_timeout(Duration::from_millis(3000));
    rt.shutdown_background();
}
