#![allow(unused_imports)]
#![allow(dead_code)]

extern crate core;

use crate::common::host_matcher::{HostMatcher, HostMatcherBuilder};
use crate::config::{LinkedState, RawRootCfg, RawState, RuleSchema};
use crate::dispatch::{Dispatching, DispatchingBuilder};
use crate::external::ApiServer;
use crate::network::dns::{new_bootstrap_resolver, parse_dns_config};
use crate::proxy::{AgentCenter, HttpCapturer};
use crate::sniff::Recorder;
use chrono::Timelike;
use common::buf_pool::PktBufPool;
use ipnet::Ipv4Net;
use is_root::is_root;
use network::tun_device::TunDevice;
use network::{
    dns::Dns,
    packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt},
};
use platform::get_default_route;
use proxy::Dispatcher;
use proxy::{Nat, SessionManager};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
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

async fn load_config(
    config_path: &str,
    state_path: &str,
) -> anyhow::Result<(RawRootCfg, RawState, HashMap<String, RuleSchema>)> {
    let config_text = fs::read_to_string(config_path)?;
    let raw_config: RawRootCfg = serde_yaml::from_str(&config_text).unwrap();
    let state_text = fs::read_to_string(state_path)?;
    let raw_state: RawState = serde_yaml::from_str(&state_text).unwrap();
    let config_folder = PathBuf::from_str(config_path)
        .unwrap()
        .parent()
        .unwrap()
        .display()
        .to_string();
    let schema = tokio::join!(config::read_schema(
        config_folder.as_str(),
        &raw_config.rule_provider,
        false
    ))
    .0?;
    Ok((raw_config, raw_state, schema))
}

fn initialize_dispatching(
    raw_config: &RawRootCfg,
    raw_state: &RawState,
    schema: HashMap<String, RuleSchema>,
) -> anyhow::Result<Arc<Dispatching>> {
    let builder = DispatchingBuilder::new_from_config(&raw_config, &raw_state, schema)?;
    Ok(Arc::new(builder.build()))
}

fn read_mitm_hosts(arr: &Option<Vec<String>>) -> HostMatcher {
    let mut builder = HostMatcherBuilder::new();
    if let Some(arr) = arr.as_ref() {
        for s in arr {
            if s.starts_with("*") {
                let st: String = s.chars().skip(1).collect();
                builder.add_suffix(st.as_str());
            } else {
                builder.add_exact(s.as_str())
            }
        }
    }
    builder.build()
}

fn main() {
    let config_path = "./_private/config/config.yml";
    let state_path = "./_private/config/state.yml";
    let crt_path = "_private/ca/crt.pem";
    let privkey_path = "_private/ca/key.pem";

    if !is_root() {
        println!("BoltConn must be run with root privilege.");
        exit(-1);
    }

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
    let (config, state, schema) = rt
        .block_on(load_config(config_path, state_path))
        .expect("Failed to load config");

    let dispatching =
        initialize_dispatching(&config, &state, schema).expect("Failed to initialize dispatching");

    // interface
    let (_, real_iface_name) = get_default_route().expect("failed to get default route");

    // guards
    let _guard = rt.enter();
    let fake_dns_server = "198.18.99.88".parse().unwrap();
    let dns_guard =
        platform::SystemDnsHandle::new(fake_dns_server).expect("fail to replace /etc/resolv.conf");

    // initialize resources
    let manager = Arc::new(SessionManager::new());
    let dns = {
        let bootstrap = new_bootstrap_resolver(config.dns.bootstrap.as_slice()).unwrap();
        let group = rt
            .block_on(parse_dns_config(&config.dns.nameserver, Some(bootstrap)))
            .unwrap();
        Arc::new(Dns::new(group).expect("DNS failed to initialize"))
    };
    let tun = rt.block_on(async {
        let pool = PktBufPool::new(512, 4096);
        let mut tun = TunDevice::open(
            manager.clone(),
            pool,
            real_iface_name.as_str(),
            dns.clone(),
            fake_dns_server,
        )
        .expect("fail to create TUN");
        // create tun device
        event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
        tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 1), 16).unwrap())
            .expect("TUN failed to set address");
        tun.up().expect("TUN failed to up");
        tun
    });

    // dispatcher and statistics
    let stat_center = Arc::new(AgentCenter::new());
    let http_capturer = Arc::new(HttpCapturer::new());
    let hcap_copy = http_capturer.clone();
    let proxy_allocator = PktBufPool::new(512, 4096);
    let dispatcher = {
        // tls mitm
        let (cert, priv_key) =
            load_cert_and_key(crt_path, privkey_path).expect("Failed to parse cert & key");
        Arc::new(Dispatcher::new(
            real_iface_name.as_str(),
            proxy_allocator.clone(),
            dns.clone(),
            stat_center.clone(),
            dispatching.clone(),
            cert,
            priv_key,
            Box::new(move |pi| Arc::new(Recorder::new(hcap_copy.clone(), pi))),
            read_mitm_hosts(&config.mitm_hosts),
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
    let nat = Arc::new(Nat::new(
        nat_addr,
        manager.clone(),
        dispatcher,
        dns,
        proxy_allocator,
    ));
    let nat_udp = nat.clone();
    let _mgr_flush_handle = manager.flush_with_interval(Duration::from_secs(30));
    let _nat_tcp_handle = rt.spawn(async move { nat.run_tcp().await });
    let _nat_udp_handle = rt.spawn(async move { nat_udp.run_udp().await });
    let _tun_handle = rt.spawn(async move { tun.run(nat_addr).await });
    let _api_handle = rt.spawn(async move { api_server.run(api_port).await });
    rt.block_on(async { tokio::signal::ctrl_c().await })
        .expect("Tokio runtime error");
    rt.shutdown_background();
    drop(dns_guard);
}
