use crate::network::dns::dns_table::DnsTable;
use crate::network::dns::provider::IfaceProvider;
use std::io;
use std::io::Result;
use std::net::IpAddr;
use tokio::sync::RwLock;
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::rr::{DNSClass, RData, Record, RecordType};
use trust_dns_resolver::config::*;
use trust_dns_resolver::name_server::GenericConnector;
use trust_dns_resolver::AsyncResolver;

pub struct Dns {
    table: DnsTable,
    resolvers: RwLock<Vec<AsyncResolver<GenericConnector<IfaceProvider>>>>,
}

impl Dns {
    pub fn with_config(
        iface_name: &str,
        configs: Vec<NameServerConfigGroup>,
    ) -> anyhow::Result<Dns> {
        let mut resolvers = Vec::new();
        for config in configs {
            let cfg = ResolverConfig::from_parts(None, vec![], config);
            resolvers.push(AsyncResolver::new(
                cfg,
                ResolverOpts::default(),
                GenericConnector::new(IfaceProvider::new(iface_name)),
            ));
        }
        Ok(Dns {
            table: DnsTable::new(),
            resolvers: RwLock::new(resolvers),
        })
    }

    pub fn new() -> Dns {
        Dns {
            table: DnsTable::new(),
            resolvers: RwLock::new(vec![]),
        }
    }

    pub async fn replace_resolvers(
        &self,
        iface_name: &str,
        configs: Vec<NameServerConfigGroup>,
    ) -> Result<()> {
        let mut resolvers = Vec::new();
        for config in configs {
            let cfg = ResolverConfig::from_parts(None, vec![], config);
            resolvers.push(AsyncResolver::new(
                cfg,
                ResolverOpts::default(),
                GenericConnector::new(IfaceProvider::new(iface_name)),
            ));
        }
        *self.resolvers.write().await = resolvers;
        Ok(())
    }

    /// Return fake ip for the domain name instantly.
    pub fn domain_to_fake_ip(&self, domain_name: &str) -> IpAddr {
        self.table.query_by_domain_name(domain_name).ip
    }

    /// Return fake ip for the domain name instantly.
    pub fn fake_ip_to_domain(&self, fake_ip: IpAddr) -> Option<String> {
        self.table.query_by_ip(fake_ip).map(|record| {
            let domain = &record.domain_name;
            if domain.ends_with('.') {
                domain[..domain.len() - 1].to_string()
            } else {
                domain.clone()
            }
        })
    }

    pub async fn genuine_lookup(&self, domain_name: &str) -> Option<IpAddr> {
        for r in self.resolvers.read().await.iter() {
            if let Ok(result) = r.ipv4_lookup(domain_name).await {
                if let Some(i) = result.iter().next() {
                    return Some(IpAddr::V4(i.0));
                }
            }
        }
        None
    }

    /// If no corresponding record, return fake ip itself.
    pub async fn ip_to_real_ip(&self, fake_ip: IpAddr) -> IpAddr {
        if let Some(record) = self.table.query_by_ip(fake_ip) {
            self.genuine_lookup(&record.domain_name)
                .await
                .unwrap_or(fake_ip)
        } else {
            tracing::trace!("Failed to extract fake_ip: {}", fake_ip);
            fake_ip
        }
    }

    pub fn respond_to_query(&self, pkt: &[u8]) -> Result<Vec<u8>> {
        // https://stackoverflow.com/questions/55092830/how-to-perform-dns-lookup-with-multiple-questions
        // There should be no >1 questions in on query
        let err = Err(io::Error::new(io::ErrorKind::InvalidData, "fail to answer"));
        let req = Message::from_vec(pkt)?;
        if req.queries().is_empty() {
            return err;
        }
        let q = &req.queries()[0];
        // validate
        let domain = q.name().to_string();

        let mut resp = Message::new();
        resp.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_op_code(req.op_code())
            .set_response_code(ResponseCode::NoError)
            .set_recursion_desired(req.recursion_desired())
            .set_recursion_available(req.recursion_desired()) // not a typo
            .set_checking_disabled(req.checking_disabled())
            .add_query(q.clone());
        match q.query_type() {
            RecordType::A => {
                let fake_ip = match self.domain_to_fake_ip(&domain) {
                    IpAddr::V4(addr) => addr,
                    IpAddr::V6(_) => return err,
                };
                let mut ans = Record::new();
                ans.set_name(domain.parse()?)
                    .set_rr_type(RecordType::A)
                    .set_dns_class(DNSClass::IN)
                    .set_ttl(60)
                    .set_data(Some(RData::A(trust_dns_proto::rr::rdata::A(fake_ip))));
                resp.add_answer(ans);
                Ok(resp.to_vec()?)
            }
            RecordType::AAAA => Ok(resp.to_vec()?),
            _ => err,
        }
    }
}
