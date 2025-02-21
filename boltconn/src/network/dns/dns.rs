use crate::config::DnsPreference;
use crate::network::dns::dns_table::DnsTable;
use crate::network::dns::hosts::HostsResolver;
use crate::network::dns::ns_policy::{DispatchedDnsResolver, NameserverPolicies};
use crate::network::dns::provider::IfaceProvider;
use crate::proxy::error::TransportError;
use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_resolver::config::*;
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::name_server::{GenericConnector, RuntimeProvider};
use hickory_resolver::AsyncResolver;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

macro_rules! impl_genuine_lookup {
    ($func_name:ident, $lookup_type:ident) => {
        async fn $func_name<R: RuntimeProvider>(
            name: &str,
            domain_name: &str,
            resolver: &AsyncResolver<GenericConnector<R>>,
        ) -> Result<Option<IpAddr>, TransportError> {
            const TIMEOUT_SEC: u64 = 5;
            if let Ok(r) = tokio::time::timeout(
                Duration::from_secs(TIMEOUT_SEC),
                resolver.$lookup_type(domain_name),
            )
            .await
            {
                return match r {
                    Ok(result) => Ok(result.iter().next().map(|i| i.0.into())),
                    Err(e) => match e.kind().clone() {
                        ResolveErrorKind::Io(err) => Err(TransportError::Io(err)),
                        _ => Ok(None),
                    },
                };
            } else {
                tracing::debug!(
                    "DNS {} {} lookup for {} timeout: {}s",
                    name,
                    stringify!($lookup_type),
                    domain_name,
                    TIMEOUT_SEC
                );
            }
            Ok(None)
        }
    };
}

pub struct GenericDns<P: RuntimeProvider> {
    name: String,
    table: DnsTable,
    preference: DnsPreference,
    host_resolver: ArcSwap<HostsResolver>,
    ns_policy: ArcSwap<NameserverPolicies>,
    resolvers: ArcSwap<Vec<AsyncResolver<GenericConnector<P>>>>,
}

pub type Dns = GenericDns<IfaceProvider>;

impl Dns {
    pub fn with_config(
        name: &str,
        iface_name: &str,
        preference: DnsPreference,
        hosts: &HashMap<String, IpAddr>,
        ns_policy: NameserverPolicies,
        configs: Vec<NameServerConfigGroup>,
    ) -> Dns {
        let resolvers = configs
            .into_iter()
            .map(|config| {
                let cfg = ResolverConfig::from_parts(None, vec![], config);
                AsyncResolver::new(
                    cfg,
                    Self::default_resolver_opt(),
                    GenericConnector::new(IfaceProvider::new(iface_name)),
                )
            })
            .collect();
        let host_resolver = HostsResolver::new(hosts);
        Dns {
            name: name.to_string(),
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
        let resolvers = configs
            .into_iter()
            .map(|config| {
                let cfg = ResolverConfig::from_parts(None, vec![], config);
                AsyncResolver::new(
                    cfg,
                    Self::default_resolver_opt(),
                    GenericConnector::new(IfaceProvider::new(iface_name)),
                )
            })
            .collect();
        self.resolvers.store(Arc::new(resolvers));
    }

    fn default_resolver_opt() -> ResolverOpts {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(1600);
        opts.attempts = 3;
        opts
    }
}

impl<P: RuntimeProvider> GenericDns<P> {
    pub fn new_with_resolver(
        name: &str,
        resolver: AsyncResolver<GenericConnector<P>>,
        preference: DnsPreference,
    ) -> Self {
        Self {
            name: name.to_string(),
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

    async fn genuine_lookup_v4(&self, domain_name: &str) -> Result<Option<IpAddr>, TransportError> {
        for r in self.resolvers.load().iter() {
            if let Some(ip) = Self::genuine_lookup_one_v4(&self.name, domain_name, r).await? {
                return Ok(Some(ip));
            }
        }
        Ok(None)
    }
    async fn genuine_lookup_v6(&self, domain_name: &str) -> Result<Option<IpAddr>, TransportError> {
        for r in self.resolvers.load().iter() {
            if let Some(ip) = Self::genuine_lookup_one_v6(&self.name, domain_name, r).await? {
                return Ok(Some(ip));
            }
        }
        Ok(None)
    }

    impl_genuine_lookup!(genuine_lookup_one_v4, ipv4_lookup);
    impl_genuine_lookup!(genuine_lookup_one_v6, ipv6_lookup);

    async fn one_v4_wrapper(
        name: &str,
        domain_name: &str,
        resolver: &DispatchedDnsResolver,
    ) -> Result<Option<IpAddr>, TransportError> {
        match resolver {
            DispatchedDnsResolver::Iface(resolver) => {
                Self::genuine_lookup_one_v4(name, domain_name, resolver).await
            }
            DispatchedDnsResolver::Plain(resolver) => {
                Self::genuine_lookup_one_v4(name, domain_name, resolver).await
            }
        }
    }

    async fn one_v6_wrapper(
        name: &str,
        domain_name: &str,
        resolver: &DispatchedDnsResolver,
    ) -> Result<Option<IpAddr>, TransportError> {
        match resolver {
            DispatchedDnsResolver::Iface(resolver) => {
                Self::genuine_lookup_one_v6(name, domain_name, resolver).await
            }
            DispatchedDnsResolver::Plain(resolver) => {
                Self::genuine_lookup_one_v6(name, domain_name, resolver).await
            }
        }
    }

    pub async fn genuine_lookup(
        &self,
        domain_name: &str,
    ) -> Result<Option<IpAddr>, TransportError> {
        self.genuine_lookup_with(domain_name, self.preference).await
    }

    pub async fn genuine_lookup_with(
        &self,
        domain_name: &str,
        pref: DnsPreference,
    ) -> Result<Option<IpAddr>, TransportError> {
        if let Some(ip) = self.host_resolver.load().resolve(domain_name) {
            if (matches!(pref, DnsPreference::Ipv6Only) && ip.is_ipv6())
                || (matches!(pref, DnsPreference::Ipv4Only) && ip.is_ipv4())
            {
                return Ok(Some(ip));
            }
        }
        if let Some(resolver) = self.ns_policy.load().resolve(domain_name) {
            return match pref {
                DnsPreference::Ipv4Only => {
                    Self::one_v4_wrapper(&self.name, domain_name, resolver).await
                }
                DnsPreference::Ipv6Only => {
                    Self::one_v6_wrapper(&self.name, domain_name, resolver).await
                }
                DnsPreference::PreferIpv4 => {
                    if let Ok(Some(a)) =
                        Self::one_v4_wrapper(&self.name, domain_name, resolver).await
                    {
                        Ok(Some(a))
                    } else {
                        Self::one_v6_wrapper(&self.name, domain_name, resolver).await
                    }
                }
                DnsPreference::PreferIpv6 => {
                    if let Ok(Some(a)) =
                        Self::one_v6_wrapper(&self.name, domain_name, resolver).await
                    {
                        Ok(Some(a))
                    } else {
                        Self::one_v4_wrapper(&self.name, domain_name, resolver).await
                    }
                }
            };
        }
        match pref {
            DnsPreference::Ipv4Only => self.genuine_lookup_v4(domain_name).await,
            DnsPreference::Ipv6Only => self.genuine_lookup_v6(domain_name).await,
            DnsPreference::PreferIpv4 => {
                if let Ok(Some(a)) = self.genuine_lookup_v4(domain_name).await {
                    Ok(Some(a))
                } else {
                    self.genuine_lookup_v6(domain_name).await
                }
            }
            DnsPreference::PreferIpv6 => {
                if let Ok(Some(a)) = self.genuine_lookup_v6(domain_name).await {
                    Ok(Some(a))
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
                .ok()
                .flatten()
                .unwrap_or(fake_ip)
        } else {
            tracing::debug!("Failed to extract fake_ip: {}", fake_ip);
            fake_ip
        }
    }

    pub fn respond_to_query(&self, pkt: &[u8]) -> io::Result<Vec<u8>> {
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
