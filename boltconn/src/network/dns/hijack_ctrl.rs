use crate::config::PortOrSocketAddr;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

enum AddressType {
    All,
    Limited(HashSet<IpAddr>),
}

pub struct DnsHijackController {
    hijack_list: HashMap<u16, AddressType>,
    bypass_list: HashMap<u16, AddressType>,
    fake_server: SocketAddr,
}

impl DnsHijackController {
    pub fn new(
        hijack_list: Option<Vec<PortOrSocketAddr>>,
        bypass_list: Option<Vec<PortOrSocketAddr>>,
        fake_server: SocketAddr,
    ) -> Self {
        Self {
            hijack_list: hijack_list.map_or_else(HashMap::new, parse_list),
            bypass_list: bypass_list.map_or_else(HashMap::new, parse_list),
            fake_server,
        }
    }

    pub fn should_hijack(&self, addr: &SocketAddr) -> bool {
        if *addr == self.fake_server {
            return true;
        }
        if let Some(addr_type) = self.bypass_list.get(&addr.port()) {
            match addr_type {
                AddressType::All => return false,
                AddressType::Limited(addrs) => {
                    if addrs.contains(&addr.ip()) {
                        return false;
                    }
                }
            }
        }
        if let Some(addr_type) = self.hijack_list.get(&addr.port()) {
            match addr_type {
                AddressType::All => true,
                AddressType::Limited(addrs) => addrs.contains(&addr.ip()),
            }
        } else {
            false
        }
    }
}

fn parse_list(list: Vec<PortOrSocketAddr>) -> HashMap<u16, AddressType> {
    let mut map = HashMap::new();
    for item in list {
        match item {
            PortOrSocketAddr::Port(port) => {
                map.insert(port, AddressType::All);
            }
            PortOrSocketAddr::SocketAddr(addr) => {
                match map.entry(addr.port()) {
                    Entry::Occupied(mut e) => {
                        // When all addresses are hijacked, we don't need to store the addresses
                        if let AddressType::Limited(addrs) = e.get_mut() {
                            addrs.insert(addr.ip());
                        }
                    }
                    Entry::Vacant(e) => {
                        let mut addrs = HashSet::new();
                        addrs.insert(addr.ip());
                        e.insert(AddressType::Limited(addrs));
                    }
                }
            }
        }
    }
    map
}
