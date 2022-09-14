use iface::tun_device::TunDevice;
use std::thread::sleep;
use std::time;
use tracing::{event, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use crate::resource::state::Shared;

mod dns;
mod iface;
mod resource;
mod packet;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::registry().with(fmt::layer()).init();
    let resource = Shared::new();
    let raw_tun = TunDevice::open(resource.clone());
    match raw_tun {
        Ok(mut tun) => {
            event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
            loop {
                match tun.recv_raw().await {
                    Ok(pkt) => {
                        let mut str = String::new();
                        let data = pkt.data.read().unwrap();
                        for i in 0..pkt.len {
                            if i % 16 == 0 {
                                println!("{}", str);
                                str.clear();
                            }
                            str += &*format!("{:02X?} ", data[i]);
                        }
                        println!("{}\n", str);
                        // event!(Level::INFO, "Received IPv4 packet: [src={}, dst={}, proto={:?}, size={}]",
                        // pkt.src_addr,pkt.dst_addr,pkt.proto,pkt.payload_offset);
                    }
                    Err(err) => event!(Level::WARN, "{}",err),
                }
            }
        }
        Err(err) => println!("{}", err),
    }
    Ok(())
}
