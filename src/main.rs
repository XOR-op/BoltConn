extern crate core;

use crate::packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt};
use crate::resource::state::Shared;
use network::tun_device::TunDevice;
use ipnet::Ipv4Net;
use smoltcp::wire::IpProtocol;
use std::net::Ipv4Addr;
use std::ops::Deref;
use smoltcp::wire;
use tokio::io::AsyncWriteExt;
use tracing::{event, Level};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use crate::network::outbound::tcpv4_stream;

mod dns;
mod network;
mod packet;
mod resource;
mod session_mgr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::registry().with(fmt::layer()).with(EnvFilter::new("catalyst=trace")).init();
    let mut resource = Shared::new();
    #[cfg(target_os = "macos")]
        let name = "en0";
    #[cfg(target_os = "linux")]
        let name = "ens18";
    let raw_tun = TunDevice::open(resource.clone(), name);
    const PARSE_PACKET: bool = true;
    match raw_tun {
        Ok(mut tun) => {
            event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
            tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(172, 20, 1, 1), 24).unwrap())?;
            tun.up()?;
            event!(Level::INFO, "TUN Device {} is up.", tun.get_name());
            let mut stream = tcpv4_stream(name).await?;
            stream.write("Hello,world".as_bytes()).await?;
            loop {
                match tun.recv_ip().await {
                    Ok(pkt) => match pkt.repr.protocol() {
                        IpProtocol::Tcp => {
                            let pkt = TcpPkt::new(pkt);
                            event!(Level::INFO, "{}", pkt);
                            tun.send_outbound(pkt.ip_pkt()).await?;
                            let handle = pkt.into_handle();
                            resource.pool.release(handle);
                        }
                        IpProtocol::Udp => {
                            let pkt = UdpPkt::new(pkt);
                            event!(Level::INFO, "{}", pkt);
                            tun.send_outbound(pkt.ip_pkt()).await?;
                            let handle = pkt.into_handle();
                            resource.pool.release(handle);
                        }
                        _ => {
                            event!(Level::INFO, "{}", pkt);
                            tun.send_outbound(&pkt).await?;
                            let handle = pkt.into_handle();
                            resource.pool.release(handle);
                        }
                    },
                    Err(err) => event!(Level::WARN, "{}", err),
                }
            }
        }
        Err(err) => println!("{}", err),
    }
    Ok(())
}
