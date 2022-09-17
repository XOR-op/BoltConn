extern crate core;

use crate::packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt};
use crate::resource::state::Shared;
use iface::tun_device::TunDevice;
use ipnet::Ipv4Net;
use smoltcp::wire::IpProtocol;
use std::net::Ipv4Addr;
use std::ops::Deref;
use smoltcp::wire;
use tracing::{event, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod dns;
mod iface;
mod packet;
mod resource;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::registry().with(fmt::layer()).init();
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
            loop {
                match tun.read_ip().await {
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
                            // let mut expr = wire::Ipv4Repr::parse(&wire::Ipv4Packet::new_unchecked(pkt.packet_data()), &smoltcp::phy::ChecksumCapabilities::default()).unwrap();
                            // let mut back = pkt.packet_data().to_vec();
                            // let mut new_pkt = wire::Ipv4Packet::new_unchecked(back);
                            // (expr.src_addr, expr.dst_addr) = (expr.dst_addr, expr.src_addr);
                            // expr.emit(&mut new_pkt, &smoltcp::phy::ChecksumCapabilities::default());
                            // let size = self.fd.write(new_pkt.as_ref()).await?;

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
