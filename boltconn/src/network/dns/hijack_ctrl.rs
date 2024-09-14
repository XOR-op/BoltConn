use crate::config::PortOrSocketAddr;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

enum AddressType {
    All,
    Limited(HashSet<IpAddr>),
}

pub struct DnsHijackController {
    hijack_list: HashMap<u16, AddressType>,
    bypass_list: HashMap<u16, AddressType>,
}

impl DnsHijackController {
    pub fn new(
        hijack_list: Option<Vec<PortOrSocketAddr>>,
        bypass_list: Option<Vec<PortOrSocketAddr>>,
    ) -> Self {
        Self {
            hijack_list: hijack_list.map_or_else(
                || {
                    let mut map = HashMap::new();
                    map.insert(53, AddressType::All);
                    map
                },
                parse_list,
            ),
            bypass_list: bypass_list.map_or_else(HashMap::new, parse_list),
        }
    }

    pub fn should_hijack(&self, port: u16, addr: IpAddr) -> bool {
        if let Some(addr_type) = self.bypass_list.get(&port) {
            match addr_type {
                AddressType::All => return false,
                AddressType::Limited(addrs) => {
                    if addrs.contains(&addr) {
                        return false;
                    }
                }
            }
        }
        if let Some(addr_type) = self.hijack_list.get(&port) {
            match addr_type {
                AddressType::All => true,
                AddressType::Limited(addrs) => addrs.contains(&addr),
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
