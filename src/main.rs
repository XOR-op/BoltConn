extern crate core;

use crate::dispatch::Dispatcher;
#[allow(unused_imports)]
use crate::packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt};
use crate::resource::buf_slab::PktBufPool;
use crate::session::{Nat, SessionManager};
use ipnet::Ipv4Net;
use network::tun_device::TunDevice;
use smoltcp::wire;
use smoltcp::wire::IpProtocol;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::{event, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod dispatch;
mod dns;
mod network;
mod outbound;
mod packet;
mod resource;
mod session;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::new("catalyst=trace"))
        .init();
    #[cfg(target_os = "macos")]
    let real_iface_name = "en0";
    #[cfg(target_os = "linux")]
    let real_iface_name = "ens18";
    let pool = PktBufPool::new(512, 4096);
    let manager = Arc::new(SessionManager::new());
    let raw_tun = TunDevice::open(manager.clone(), pool.clone(), real_iface_name);
    match raw_tun {
        Ok(mut tun) => {
            event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
            tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(172, 20, 1, 1), 24).unwrap())?;
            tun.up()?;
            let nat_addr = SocketAddr::new(network::get_iface_address(tun.get_name())?, 9961);
            let dispatcher = Arc::new(Dispatcher::new(real_iface_name));
            let nat = Nat::new(nat_addr, manager, dispatcher);
            let nat_handle = tokio::spawn(async move { nat.run_tcp().await });
            // let tun_handle = tokio::spawn(async move {
            // });
            event!(Level::INFO, "Start running...");
            // tokio::join!(nat_handle,tun_handle);
            tun.run(nat_addr).await?;
        }
        Err(err) => println!("{}", err),
    }
    Ok(())
}
