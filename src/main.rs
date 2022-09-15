use crate::resource::state::Shared;
use iface::tun_device::TunDevice;
use tracing::{event, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod dns;
mod iface;
mod packet;
mod resource;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::registry().with(fmt::layer()).init();
    let resource = Shared::new();
    let raw_tun = TunDevice::open(resource.clone());
    const PARSE_PACKET: bool = true;
    match raw_tun {
        Ok(mut tun) => {
            event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
            loop {
                if PARSE_PACKET {
                    match tun.recv_ip().await {
                        Ok(pkt) => {
                            event!(Level::INFO, "{}", pkt);
                        }
                        Err(err) => event!(Level::WARN, "{}", err),
                    }
                } else {
                    match tun.recv_raw().await {
                        Ok(pkt) => {
                            let data = pkt.data;
                            let mut str = String::new();
                            for i in 0..pkt.len {
                                if i % 16 == 0 {
                                    println!("{}", str);
                                    str.clear();
                                }
                                str += &*format!("{:02X?} ", data[i]);
                            }
                            println!("{}\n", str);
                        }
                        Err(err) => event!(Level::WARN, "{}", err),
                    }
                }
            }
        }
        Err(err) => println!("{}", err),
    }
    Ok(())
}
