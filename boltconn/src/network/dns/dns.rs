use crate::config::DnsPreference;
use crate::network::dns::dns_table::DnsTable;
use crate::network::dns::hosts::HostsResolver;
use crate::network::dns::ns_policy::{DispatchedDnsResolver, NameserverPolicies};
use crate::network::dns::provider::IfaceProvider;
use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_resolver::config::*;
use hickory_resolver::name_server::{GenericConnector, RuntimeProvider};
use hickory_resolver::AsyncResolver;
use std::collections::HashMap;
use std::io;
use std::io::Result;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct GenericDns<P: RuntimeProvider> {
    table: DnsTable,
    preference: DnsPreference,
    host_resolver: ArcSwap<HostsResolver>,
    ns_policy: ArcSwap<NameserverPolicies>,
    resolvers: ArcSwap<Vec<AsyncResolver<GenericConnector<P>>>>,
}

pub type Dns = GenericDns<IfaceProvider>;

impl Dns {
    pub fn with_config(
        iface_name: &str,
        preference: DnsPreference,
        hosts: &HashMap<String, IpAddr>,
        ns_policy: NameserverPolicies,
        configs: Vec<NameServerConfigGroup>,
    ) -> Dns {
        let mut resolvers = Vec::new();
        for config in configs {
            let cfg = ResolverConfig::from_parts(None, vec![], config);
            resolvers.push(AsyncResolver::new(
                cfg,
                ResolverOpts::default(),
                GenericConnector::new(IfaceProvider::new(iface_name)),
            ));
        }
        let host_resolver = HostsResolver::new(hosts);
        Dns {
            table: DnsTable::new(),
            preference,
            host_resolver: ArcSwap::new(Arc::new(host_resolver)),
            ns_policy: ArcSwap::new(Arc::new(ns_policy)),
            resolvers: ArcSwap::new(Arc::new(resolvers)),
        }
    }

    pub fn replace_hosts(&self, hosts: &HashMap<String, IpAddr>) {
        self.host_resolver
            .store(Arc::new(HostsResolver::new(hosts)));
    }

    pub fn replace_ns_policy(&self, ns_policy: NameserverPolicies) {
        self.ns_policy.store(Arc::new(ns_policy));
    }

    pub fn replace_resolvers(&self, iface_name: &str, configs: Vec<NameServerConfigGroup>) {
        let mut resolvers = Vec::new();
        for config in configs {
            let cfg = ResolverConfig::from_parts(None, vec![], config);
            resolvers.push(AsyncResolver::new(
                cfg,
                ResolverOpts::default(),
                GenericConnector::new(IfaceProvider::new(iface_name)),
            ));
        }
        self.resolvers.store(Arc::new(resolvers));
    }
}

impl<P: RuntimeProvider> GenericDns<P> {
    pub fn new_with_resolver(
        resolver: AsyncResolver<GenericConnector<P>>,
        preference: DnsPreference,
    ) -> Self {
        Self {
            table: DnsTable::new(),
            preference,
            host_resolver: ArcSwap::new(Arc::new(HostsResolver::empty())),
            ns_policy: ArcSwap::new(Arc::new(NameserverPolicies::empty())),
            resolvers: ArcSwap::new(Arc::new(vec![resolver])),
        }
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

    async fn genuine_lookup_v4(&self, domain_name: &str) -> Option<IpAddr> {
        for r in self.resolvers.load().iter() {
            if let Some(ip) = Self::genuine_lookup_one_v4(domain_name, r).await {
                return Some(ip);
            }
        }
        None
    }

    async fn genuine_lookup_one_v4<R: RuntimeProvider>(
        domain_name: &str,
        resolver: &AsyncResolver<GenericConnector<R>>,
    ) -> Option<IpAddr> {
        if let Ok(r) =
            tokio::time::timeout(Duration::from_secs(5), resolver.ipv4_lookup(domain_name)).await
        {
            if let Ok(result) = r {
                if let Some(i) = result.iter().next() {
                    return Some(i.0.into());
                }
            }
        } else {
            tracing::debug!("DNS lookup for {domain_name} timeout");
        }
        None
    }

    async fn genuine_lookup_v6(&self, domain_name: &str) -> Option<IpAddr> {
        for r in self.resolvers.load().iter() {
            if let Some(ip) = Self::genuine_lookup_one_v6(domain_name, r).await {
                return Some(ip);
            }
        }
        None
    }

    async fn genuine_lookup_one_v6<R: RuntimeProvider>(
        domain_name: &str,
        resolver: &AsyncResolver<GenericConnector<R>>,
    ) -> Option<IpAddr> {
        if let Ok(r) =
            tokio::time::timeout(Duration::from_secs(5), resolver.ipv6_lookup(domain_name)).await
        {
            if let Ok(result) = r {
                if let Some(i) = result.iter().next() {
                    return Some(i.0.into());
                }
            }
        } else {
            tracing::debug!("DNS lookup for {domain_name} timeout");
        }
        None
    }

    async fn one_v4_wrapper(domain_name: &str, resolver: &DispatchedDnsResolver) -> Option<IpAddr> {
        match resolver {
            DispatchedDnsResolver::Iface(resolver) => {
                Self::genuine_lookup_one_v4(domain_name, resolver).await
            }
            DispatchedDnsResolver::Plain(resolver) => {
                Self::genuine_lookup_one_v4(domain_name, resolver).await
            }
        }
    }

    async fn one_v6_wrapper(domain_name: &str, resolver: &DispatchedDnsResolver) -> Option<IpAddr> {
        match resolver {
            DispatchedDnsResolver::Iface(resolver) => {
                Self::genuine_lookup_one_v6(domain_name, resolver).await
            }
            DispatchedDnsResolver::Plain(resolver) => {
                Self::genuine_lookup_one_v6(domain_name, resolver).await
            }
        }
    }

    pub async fn genuine_lookup(&self, domain_name: &str) -> Option<IpAddr> {
        self.genuine_lookup_with(domain_name, self.preference).await
    }

    pub async fn genuine_lookup_with(
        &self,
        domain_name: &str,
        pref: DnsPreference,
    ) -> Option<IpAddr> {
        if let Some(ip) = self.host_resolver.load().resolve(domain_name) {
            if (matches!(pref, DnsPreference::Ipv6Only) && ip.is_ipv6())
                || (matches!(pref, DnsPreference::Ipv4Only) && ip.is_ipv4())
            {
                return Some(ip);
            }
        }
        if let Some(resolver) = self.ns_policy.load().resolve(domain_name) {
            return match pref {
                DnsPreference::Ipv4Only => Self::one_v4_wrapper(domain_name, resolver).await,
                DnsPreference::Ipv6Only => Self::one_v6_wrapper(domain_name, resolver).await,
                DnsPreference::PreferIpv4 => {
                    if let Some(a) = Self::one_v4_wrapper(domain_name, resolver).await {
                        Some(a)
                    } else {
                        Self::one_v6_wrapper(domain_name, resolver).await
                    }
                }
                DnsPreference::PreferIpv6 => {
                    if let Some(a) = Self::one_v6_wrapper(domain_name, resolver).await {
                        Some(a)
                    } else {
                        Self::one_v4_wrapper(domain_name, resolver).await
                    }
                }
            };
        }
        match pref {
            DnsPreference::Ipv4Only => self.genuine_lookup_v4(domain_name).await,
            DnsPreference::Ipv6Only => self.genuine_lookup_v6(domain_name).await,
            DnsPreference::PreferIpv4 => {
                if let Some(a) = self.genuine_lookup_v4(domain_name).await {
                    Some(a)
                } else {
                    self.genuine_lookup_v6(domain_name).await
                }
            }
            DnsPreference::PreferIpv6 => {
                if let Some(a) = self.genuine_lookup_v6(domain_name).await {
                    Some(a)
                } else {
                    self.genuine_lookup_v4(domain_name).await
                }
            }
        }
    }

    /// If no corresponding record, return fake ip itself.
    pub async fn ip_to_real_ip(&self, fake_ip: IpAddr) -> IpAddr {
        if let Some(record) = self.table.query_by_ip(fake_ip) {
            self.genuine_lookup(&record.domain_name)
                .await
                .unwrap_or(fake_ip)
        } else {
            tracing::debug!("Failed to extract fake_ip: {}", fake_ip);
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
                    .set_data(Some(RData::A(hickory_proto::rr::rdata::A(fake_ip))));
                resp.add_answer(ans);
                Ok(resp.to_vec()?)
            }
            RecordType::AAAA | RecordType::PTR => Ok(resp.to_vec()?),
            _ => err,
        }
    }
}
