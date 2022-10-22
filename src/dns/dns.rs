use crate::dns::dns_table::DnsTable;
use crate::network::get_iface_address;
use std::io::Result;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

pub struct Dns {
    table: DnsTable,
    resolvers: Vec<Resolver>,
}

impl Dns {
    pub fn new(gw: &str) -> Result<Dns> {
        // todo: by config
        let gw_ip = get_iface_address(gw)?;
        let nameserver_cfg = NameServerConfig {
            socket_addr: SocketAddr::V4(SocketAddrV4::new("114.114.114.114".parse().unwrap(), 53)),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
            bind_addr: Some(SocketAddr::new(gw_ip, 1101)),
        };
        let cfg = ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from(vec![nameserver_cfg]),
        );
        let resolver = Resolver::new(cfg, ResolverOpts::default())?;
        Ok(Dns {
            table: DnsTable::new(),
            resolvers: vec![resolver],
        })
    }

    /// Return fake ip for the domain name instantly.
    pub fn query_by_domain(&self, domain_name: &str) -> IpAddr {
        self.table.query_by_domain_name(domain_name).ip
    }

    /// If no corresponding record, return fake ip itself.
    pub fn query_real_ip(&self, fake_ip: IpAddr) -> IpAddr {
        if let Some(record) = self.table.query_by_ip(fake_ip) {
            for r in &self.resolvers {
                if let Ok(result) = r.ipv4_lookup(&record.domain_name) {
                    for i in result {
                        return IpAddr::V4(i);
                    }
                }
            }
            fake_ip
        } else {
            fake_ip
        }
    }

    pub fn respond_to_query(&self, pkt: &dns_parser::Packet) -> Vec<u8> {
        todo!()
    }
}
