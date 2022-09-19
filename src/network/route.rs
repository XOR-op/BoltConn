use crate::network::platform;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::io;

/// All IANA reserved IPv4 addresses
#[allow(dead_code)]
pub fn ipv4_reserved_addresses() -> Vec<Ipv4Net> {
    Ipv4Net::aggregate(&vec![
        "0.0.0.0/8".parse::<Ipv4Net>().unwrap(),
        "10.0.0.0/8".parse().unwrap(),
        "100.64.0.0/10".parse().unwrap(),
        "127.0.0.0/8".parse().unwrap(),
        "169.254.0.0/16".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
        "192.0.0.0/24".parse().unwrap(),
        "192.0.2.0/24".parse().unwrap(),
        "192.88.99.0/24".parse().unwrap(),
        "192.168.0.0/16".parse().unwrap(),
        "198.18.0.0/15".parse().unwrap(),
        "198.51.100.0/24".parse().unwrap(),
        "203.0.113.0/24".parse().unwrap(),
        "224.0.0.0/4".parse().unwrap(),
        "233.252.0.0/24".parse().unwrap(),
        "240.0.0.0/4".parse().unwrap(),
        "255.255.255.255/32".parse().unwrap(),
    ])
}

/// Common private IPv4 addresses
#[allow(dead_code)]
pub fn ipv4_private_addresses() -> Vec<Ipv4Net> {
    Ipv4Net::aggregate(&vec![
        "10.0.0.0/8".parse::<Ipv4Net>().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
        "192.0.0.0/24".parse().unwrap(),
        "192.168.0.0/24".parse().unwrap(),
        "198.18.0.0/15".parse().unwrap(),
    ])
}

/// We only bypass 0.0.0.0/8 and 127.0.0.0/8
#[allow(dead_code)]
pub fn ipv4_relay_addresses() -> Vec<Ipv4Net> {
    Ipv4Net::aggregate(&vec![
        "1.0.0.0/8".parse::<Ipv4Net>().unwrap(),
        "2.0.0.0/7".parse().unwrap(),
        "4.0.0.0/6".parse().unwrap(),
        "8.0.0.0/5".parse().unwrap(),
        "16.0.0.0/4".parse().unwrap(),
        "32.0.0.0/3".parse().unwrap(),
        "64.0.0.0/3".parse().unwrap(),
        "96.0.0.0/4".parse().unwrap(),
        "112.0.0.0/5".parse().unwrap(),
        "120.0.0.0/6".parse().unwrap(),
        "124.0.0.0/7".parse().unwrap(),
        "126.0.0.0/8".parse().unwrap(),
        "128.0.0.0/2".parse().unwrap(),
        "192.0.0.0/3".parse().unwrap(),
        "192.0.0.0/3".parse().unwrap(),
        // Not sure if multicast is needed
        // "224.0.0.0/4".parse().unwrap(),
    ])
}

/// Common private IPv6 addresses
#[allow(dead_code)]
pub fn ipv6_private_addresses() -> Vec<Ipv6Net> {
    Ipv6Net::aggregate(&vec![
        "fc00::/7".parse::<Ipv6Net>().unwrap(),
        "fc80::/10".parse().unwrap(),
    ])
}

pub fn setup_ipv4_routing_table(name: &str) -> io::Result<()> {
    for item in ipv4_relay_addresses() {
        unsafe { platform::add_route_entry(IpNet::V4(item), name) }?;
    }
    Ok(())
}
