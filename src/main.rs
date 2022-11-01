#![allow(unused_imports)]
#![allow(unused_variables)]

extern crate core;

use common::buf_slab::PktBufPool;
use dispatch::Dispatcher;
use ipnet::Ipv4Net;
use network::dns::Dns;
use network::packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt};
use network::tun_device::TunDevice;
use session::{Nat, SessionManager};
use smoltcp::wire;
use smoltcp::wire::IpProtocol;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::{event, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use crate::config::DnsConfig;
use crate::network::dns::DnsRoutingHandle;

mod common;
mod config;
mod dispatch;
mod network;
mod outbound;
mod platform;
mod session;

fn main() {
    let mut rt = tokio::runtime::Runtime::new().expect("Tokio failed to initialize");
    let handle = rt.handle();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::new("catalyst=trace"))
        .init();
    #[cfg(target_os = "macos")]
        let real_iface_name = "en0";
    #[cfg(target_os = "linux")]
        let real_iface_name = "ens18";

    let dns_config = DnsConfig { list: vec!["114.114.114.114:53".parse().unwrap()] };

    let _guard = rt.enter();
    let dns_guard = platform::SystemDnsHandle::new("198.18.99.88".parse().unwrap()).expect("fail to replace /etc/resolv.conf");

    let dns_routing_guard = DnsRoutingHandle::new(real_iface_name, dns_config.clone()).expect("fail to add dns route table");

    let pool = PktBufPool::new(512, 4096);
    let manager = Arc::new(SessionManager::new());
    let dns = Arc::new(Dns::new(real_iface_name, &dns_config).expect("DNS failed to initialize"));
    let mut tun = rt.block_on(async {
        TunDevice::open(manager.clone(), pool.clone(), real_iface_name, dns.clone())
    }).expect("fail to create TUN");

    event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
    tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 1), 24).unwrap()).expect("TUN failed to set address");
    tun.up().expect("TUN failed to up");
    let nat_addr = SocketAddr::new(platform::get_iface_address(tun.get_name()).expect("failed to get tun address"), 9961);
    let dispatcher = Arc::new(Dispatcher::new(real_iface_name));
    let nat = Nat::new(nat_addr, manager, dispatcher, dns);
    let nat_handle = rt.spawn(async move { nat.run_tcp().await });
    let tun_handle = rt.spawn(async move { tun.run(nat_addr).await });
    rt.block_on(async { tokio::signal::ctrl_c().await }).expect("Tokio runtime error");
    drop(dns_guard);
    drop(dns_routing_guard);
    // rt.shutdown_timeout(Duration::from_millis(3000));
    rt.shutdown_background();
}
