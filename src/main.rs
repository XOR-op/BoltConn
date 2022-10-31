#![allow(unused_imports)]
#![allow(unused_variables)]

extern crate core;

use crate::dispatch::Dispatcher;
use crate::dns::Dns;
use crate::packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt};
use crate::resource::buf_slab::PktBufPool;
use crate::session::{Nat, SessionManager};
use ipnet::Ipv4Net;
use network::tun_device::TunDevice;
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

mod config;
mod dispatch;
mod dns;
mod network;
mod outbound;
mod packet;
mod process;
mod resource;
mod session;

fn main() -> io::Result<()> {
    let mut rt = tokio::runtime::Runtime::new()?;
    let handle = rt.handle();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::new("catalyst=trace"))
        .init();
    #[cfg(target_os = "macos")]
        let real_iface_name = "en0";
    #[cfg(target_os = "linux")]
        let real_iface_name = "ens18";

    let _guard = rt.enter();

    let pool = PktBufPool::new(512, 4096);
    let manager = Arc::new(SessionManager::new());
    let dns = Arc::new(Dns::new(real_iface_name)?);
    let mut tun = rt.block_on(async {
        TunDevice::open(manager.clone(), pool.clone(), real_iface_name, dns.clone())
    })?;

    event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
    tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 1), 24).unwrap())?;
    tun.up()?;
    let nat_addr = SocketAddr::new(network::get_iface_address(tun.get_name())?, 9961);
    let dispatcher = Arc::new(Dispatcher::new(real_iface_name));
    let nat = Nat::new(nat_addr, manager, dispatcher, dns);
    let nat_handle = rt.spawn(async move { nat.run_tcp().await });
    let tun_handle = rt.spawn(async move { tun.run(nat_addr).await });
    rt.block_on(async { tokio::signal::ctrl_c().await })?;
    // rt.shutdown_timeout(Duration::from_millis(3000));
    rt.shutdown_background();
    Ok(())
}
