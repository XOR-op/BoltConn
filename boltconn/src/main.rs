#![allow(unused_imports)]
#![allow(dead_code)]

extern crate core;

use crate::config::RawDnsCfg;
use crate::network::dns::DnsRoutingHandle;
use crate::platform::get_default_route;
use chrono::Timelike;
use common::buf_pool::PktBufPool;
use dispatch::Dispatcher;
use ipnet::Ipv4Net;
use network::dns::Dns;
use network::packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt};
use network::tun_device::TunDevice;
use session::{Nat, SessionManager};
use smoltcp::wire;
use smoltcp::wire::IpProtocol;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{fs, io};
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::{Certificate, PrivateKey};
use tracing::{event, Level};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod adapter;
mod common;
mod config;
mod dispatch;
mod network;
mod platform;
mod session;
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

fn load_cert_and_key() -> io::Result<(Vec<Certificate>, PrivateKey)> {
    let cert_raw = fs::read("_private/ca/crt.pem")?;
    let mut cert_bytes = cert_raw.as_slice();
    let key_raw = fs::read("_private/ca/key.pem")?;
    let mut key_bytes = key_raw.as_slice();
    let cert = Certificate(rustls_pemfile::certs(&mut cert_bytes)?.remove(0));
    let key = PrivateKey(rustls_pemfile::pkcs8_private_keys(&mut key_bytes)?.remove(0));
    Ok((vec![cert], key))
}

fn main() {
    let rt = tokio::runtime::Runtime::new().expect("Tokio failed to initialize");
    let formatting_layer = fmt::layer()
        .compact()
        .with_writer(std::io::stdout)
        .with_timer(SystemTime::default());
    tracing_subscriber::registry()
        .with(formatting_layer)
        .with(EnvFilter::new("boltconn=trace"))
        .init();

    let (gateway_address, real_iface_name) =
        get_default_route().expect("failed to get default route");
    let real_iface_name = real_iface_name.as_str();

    let (cert, priv_key) = load_cert_and_key().expect("Failed to parse cert & key");

    let dns_config = RawDnsCfg {
        list: vec!["114.114.114.114:53".parse().unwrap()],
    };

    let _guard = rt.enter();
    let dns_guard = platform::SystemDnsHandle::new("198.18.99.88".parse().unwrap())
        .expect("fail to replace /etc/resolv.conf");

    let dns_routing_guard =
        DnsRoutingHandle::new(gateway_address, real_iface_name, dns_config.clone())
            .expect("fail to add dns route table");

    // initialize resources
    let pool = PktBufPool::new(512, 4096);
    let manager = Arc::new(SessionManager::new());
    let dns = Arc::new(Dns::new(&dns_config).expect("DNS failed to initialize"));
    let mut tun = rt
        .block_on(async {
            TunDevice::open(manager.clone(), pool.clone(), real_iface_name, dns.clone())
        })
        .expect("fail to create TUN");

    event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
    tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 1), 16).unwrap())
        .expect("TUN failed to set address");
    tun.up().expect("TUN failed to up");
    let nat_addr = SocketAddr::new(
        platform::get_iface_address(tun.get_name()).expect("failed to get tun address"),
        9961,
    );
    let proxy_allocator = PktBufPool::new(512, 4096);

    let dispatcher = Arc::new(Dispatcher::new(
        real_iface_name,
        proxy_allocator.clone(),
        dns.clone(),
        cert,
        priv_key,
    ));
    let nat = Nat::new(nat_addr, manager, dispatcher, dns);

    // run
    let _nat_handle = rt.spawn(async move { nat.run_tcp().await });
    let _tun_handle = rt.spawn(async move { tun.run(nat_addr).await });
    rt.block_on(async { tokio::signal::ctrl_c().await })
        .expect("Tokio runtime error");
    drop(dns_guard);
    drop(dns_routing_guard);
    // rt.shutdown_timeout(Duration::from_millis(3000));
    rt.shutdown_background();
}
