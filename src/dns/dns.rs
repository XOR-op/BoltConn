use crate::dns::dns_table::DnsTable;
use crate::network::get_iface_address;
use std::io::Result;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use simple_dns::{QTYPE, ResourceRecord};
use simple_dns::rdata::RData;
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

    pub fn respond_to_query(&self, pkt: &simple_dns::Packet) -> Option<Vec<u8>> {
        // https://stackoverflow.com/questions/55092830/how-to-perform-dns-lookup-with-multiple-questions
        // There should be no >1 questions in on query
        for q in &pkt.questions {
            let domain = q.qname.to_string();
            if q.qtype != QTYPE::TYPE(simple_dns::TYPE::A) {
                continue;
            }
            let fake_ip = match self.query_by_domain(&domain) {
                IpAddr::V4(addr) => addr,
                IpAddr::V6(_) => return None,
            };
            let mut resp = simple_dns::Packet::new_reply(pkt.header.id);
            resp.header.authoritative_answer = true;
            resp.answers.push(ResourceRecord {
                name: match simple_dns::Name::new(&domain) {
                    Ok(v) => v,
                    Err(_) => return None,
                },
                class: simple_dns::CLASS::IN,
                ttl: 60,
                rdata: RData::A(simple_dns::rdata::A::from(fake_ip)),
                cache_flush: true,
            });
            return resp.build_bytes_vec().ok();
        }
        None
    }
}
