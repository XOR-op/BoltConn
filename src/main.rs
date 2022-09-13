use iface::tun_device::TunDevice;
use std::thread::sleep;
use std::time;
use tracing::{event, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod dns;
mod iface;
mod packet;

fn main() {
    tracing_subscriber::registry().with(fmt::layer()).init();
    let raw_tun = TunDevice::open();
    match raw_tun {
        Ok(tun) => {
            event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
            sleep(time::Duration::from_secs(120));
        }
        Err(err) => println!("{}", err),
    }
}
