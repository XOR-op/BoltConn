use ipnet::Ipv4Net;
use std::path::Path;

use crate::platform;

fn delete_route_entry(addr: Ipv4Net) {
    let _ = platform::delete_route_entry(addr.into());
}

fn ipv4_relay_addresses() -> Vec<Ipv4Net> {
    Ipv4Net::aggregate(&vec![
        "1.0.0.0/8".parse::<Ipv4Net>().unwrap(),
        "2.0.0.0/7".parse().unwrap(),
        "4.0.0.0/6".parse().unwrap(),
        "8.0.0.0/5".parse().unwrap(),
        "16.0.0.0/4".parse().unwrap(),
        "32.0.0.0/3".parse().unwrap(),
        "64.0.0.0/2".parse().unwrap(),
        "96.0.0.0/3".parse().unwrap(),
        "128.0.0.0/2".parse().unwrap(),
        "192.0.0.0/3".parse().unwrap(),
    ])
}

pub(crate) fn clean_route_table() {
    for ip in ipv4_relay_addresses() {
        delete_route_entry(ip);
    }
}

pub(crate) fn remove_unix_socket<P: AsRef<Path>>(path: P) {
    let _ = std::fs::remove_file(path);
}
