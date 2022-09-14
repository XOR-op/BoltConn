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

fn main() {
    tracing_subscriber::registry().with(fmt::layer()).init();
    let resource = Shared::new();
    let raw_tun = TunDevice::open(resource.clone());
    match raw_tun {
        Ok(tun) => {
            event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
            sleep(time::Duration::from_secs(120));
        }
        Err(err) => println!("{}", err),
    }
}
