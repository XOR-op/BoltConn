mod bootstrap;
#[allow(clippy::module_inception)]
mod dns;
mod dns_table;
mod hijack_ctrl;
mod hosts;
mod ns_policy;
mod observability;
mod provider;

use crate::config::{DnsConfigError, RawDnsConfig};
use crate::proxy::error::DnsError;
pub use bootstrap::BootstrapResolver;
pub use dns::{Dns, GenericDns};
pub(crate) use dns::{sort_resolver_summaries, validate_diagnostic_domain};
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    CLOUDFLARE, ConnectionConfig, GOOGLE, NameServerConfig, QUAD9, ResolverConfig, ResolverOpts,
};
pub use hijack_ctrl::DnsHijackController;
pub use ns_policy::NameserverPolicies;
use provider::IfaceProvider;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub enum NameServerConfigEnum {
    Normal(Vec<NameServerConfig>),
    Dhcp(String),
}

fn encrypted_server_configs(ips: &[IpAddr], connection: ConnectionConfig) -> Vec<NameServerConfig> {
    ips.iter()
        .map(|ip| NameServerConfig::new(*ip, false, vec![connection.clone()]))
        .collect()
}

async fn resolve_dns(bootstrap: &BootstrapResolver, dn: &str) -> Result<Vec<IpAddr>, DnsError> {
    let Ok(ips) = bootstrap.lookup_ip(dn).await else {
        return Err(DnsError::ResolveServer(dn.to_string()));
    };
    if ips.is_empty() {
        Err(DnsError::ResolveServer(dn.to_string()))
    } else {
        Ok(ips)
    }
}

pub fn new_bootstrap_resolver(iface_name: &str, addr: &[IpAddr]) -> BootstrapResolver {
    let cfg = ResolverConfig::from_parts(
        None,
        vec![],
        addr.iter().copied().map(NameServerConfig::udp).collect(),
    );
    BootstrapResolver::new(
        Resolver::builder_with_config(cfg, IfaceProvider::new(iface_name))
            .build()
            .expect("rustls miscompiled"),
    )
}

pub async fn parse_dns_config(
    lines: impl Iterator<Item = &String>,
    bootstrap: &BootstrapResolver,
) -> Result<Vec<NameServerConfigEnum>, DnsConfigError> {
    let mut arr = Vec::new();
    for l in lines {
        let parts: Vec<&str> = l.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return Err(DnsConfigError::Invalid(l.clone()));
        }
        let (proto, content) = (
            parts.first().unwrap().to_string(),
            parts.get(1).unwrap().to_string(),
        );
        arr.push(parse_single_dns(proto.as_str(), content.as_str(), bootstrap).await?);
    }
    Ok(arr)
}

/// Validate DNS entries without discovering interfaces or performing lookups.
pub(crate) async fn validate_dns_config(config: &RawDnsConfig) -> Result<(), DnsConfigError> {
    let bootstrap = BootstrapResolver::for_validation();
    if parse_dns_config(config.nameserver.iter(), &bootstrap)
        .await?
        .is_empty()
    {
        return Err(DnsConfigError::Invalid("No DNS specified".to_string()));
    }
    NameserverPolicies::validate(&config.nameserver_policy, &bootstrap).await
}

pub async fn parse_single_dns(
    proto: &str,
    content: &str,
    bootstrap: &BootstrapResolver,
) -> Result<NameServerConfigEnum, DnsConfigError> {
    Ok(NameServerConfigEnum::Normal(match proto {
        "dhcp" => return Ok(NameServerConfigEnum::Dhcp(content.to_string())),
        "udp" => vec![NameServerConfig::udp(
            content
                .parse::<IpAddr>()
                .map_err(|_| DnsConfigError::Invalid(content.to_string()))?,
        )],
        "dot" => encrypted_server_configs(
            resolve_dns(bootstrap, content).await?.as_slice(),
            ConnectionConfig::tls(content.into()),
        ),
        "doh" => encrypted_server_configs(
            resolve_dns(bootstrap, content).await?.as_slice(),
            ConnectionConfig::https(content.into(), None),
        ),
        "dot-preset" => match content {
            "cloudflare" | "cf" => ResolverConfig::tls(&CLOUDFLARE).name_servers,
            "quad9" => ResolverConfig::tls(&QUAD9).name_servers,
            _ => return Err(DnsConfigError::InvalidPreset("dot", content.to_string())),
        },
        "doh-preset" => match content {
            "cloudflare" | "cf" => ResolverConfig::https(&CLOUDFLARE).name_servers,
            "quad9" => ResolverConfig::https(&QUAD9).name_servers,
            "google" => ResolverConfig::https(&GOOGLE).name_servers,
            _ => return Err(DnsConfigError::InvalidPreset("doh", content.to_string())),
        },
        _ => return Err(DnsConfigError::InvalidType(proto.to_string())),
    }))
}

pub fn extract_address(group: &[Vec<NameServerConfig>]) -> Vec<IpAddr> {
    group
        .iter()
        .flat_map(|configs| configs.iter().map(|config| config.ip))
        .collect()
}

fn default_resolver_opt() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(1600);
    opts.attempts = 3;
    opts
}

struct DhcpDnsRecord {
    iface: String,
    endpoint: Option<(IpAddr, IpAddr)>,
    last_checked: Option<std::time::Instant>,
    refreshing: bool,
    ready: Arc<tokio::sync::Notify>,
    resolver: Option<Arc<Resolver<IfaceProvider>>>,
}

impl DhcpDnsRecord {
    pub fn new(iface: &str) -> Arc<Mutex<Self>> {
        // Share discovery across nameservers, policies and configuration reloads.
        // Weak entries do not keep unused resolvers alive.
        type Records = std::collections::HashMap<String, std::sync::Weak<Mutex<DhcpDnsRecord>>>;
        static RECORDS: std::sync::OnceLock<Mutex<Records>> = std::sync::OnceLock::new();
        let mut records = RECORDS.get_or_init(Mutex::default).lock().unwrap();
        records.retain(|_, record| record.strong_count() != 0);
        #[cfg(windows)]
        let key = iface.to_ascii_lowercase();
        #[cfg(not(windows))]
        let key = iface.to_string();
        if let Some(record) = records.get(&key).and_then(std::sync::Weak::upgrade) {
            return record;
        }
        let record = Arc::new(Mutex::new(Self {
            iface: iface.to_string(),
            endpoint: None,
            last_checked: None,
            refreshing: false,
            ready: Arc::new(tokio::sync::Notify::new()),
            resolver: None,
        }));
        records.insert(key, Arc::downgrade(&record));
        Self::refresh(&record);
        record
    }

    fn refresh(record: &Arc<Mutex<Self>>) {
        Self::refresh_with(record, |iface| {
            let addr = crate::platform::get_iface_address(iface)
                .map_err(|_| DnsError::DhcpNameServer("failed to get iface address"))?;
            let dns = crate::platform::dhcp::get_dhcp_dns(iface)?;
            Ok((addr, dns))
        });
    }

    fn refresh_with(
        record: &Arc<Mutex<Self>>,
        probe: impl FnOnce(&str) -> Result<(IpAddr, IpAddr), DnsError> + Send + 'static,
    ) {
        let mut guard = record.lock().unwrap();
        if guard.refreshing
            || guard
                .last_checked
                .is_some_and(|checked| checked.elapsed() < Duration::from_secs(15))
        {
            return;
        }
        guard.refreshing = true;
        let iface = guard.iface.clone();
        let state = record.clone();
        // DhcpRequestParams can take two minutes. A dedicated thread keeps both
        // async workers and runtime shutdown independent of this blocking call.
        if let Err(error) = std::thread::Builder::new()
            .name("dhcp-dns".into())
            .spawn(move || {
                let result = probe(&iface);
                let mut guard = state.lock().unwrap();
                guard.apply(result);
                guard.ready.notify_waiters();
            })
        {
            guard.apply(Err(DnsError::DhcpNameServer(
                "failed to start DHCP discovery",
            )));
            tracing::warn!("failed to start DHCP DNS worker: {error}");
        }
    }

    fn apply(&mut self, result: Result<(IpAddr, IpAddr), DnsError>) {
        self.refreshing = false;
        self.last_checked = Some(std::time::Instant::now());
        match result {
            Ok(endpoint) => {
                if self.endpoint != Some(endpoint) {
                    self.resolver = Some(Self::create_resolver(endpoint.1, &self.iface));
                    self.endpoint = Some(endpoint);
                }
            }
            Err(error) => {
                tracing::warn!("DHCP DNS discovery on {} failed: {error}", self.iface);
                self.endpoint = None;
                self.resolver = None;
            }
        }
    }

    fn create_resolver(new_dns: IpAddr, iface: &str) -> Arc<Resolver<IfaceProvider>> {
        let cfg = ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp(new_dns)]);
        Arc::new(
            Resolver::builder_with_config(cfg, IfaceProvider::new(iface))
                .with_options(default_resolver_opt())
                .build()
                .expect("rustls miscompiled"),
        )
    }

    async fn get_resolver(record: &Arc<Mutex<Self>>) -> Option<Arc<Resolver<IfaceProvider>>> {
        let ready = record.lock().unwrap().ready.clone();
        let notified = ready.notified();
        tokio::pin!(notified);
        // Register before inspecting state so completion cannot be missed.
        notified.as_mut().enable();
        Self::refresh(record);
        {
            let guard = record.lock().unwrap();
            if guard.resolver.is_some() || !guard.refreshing {
                return guard.resolver.clone();
            }
        }
        // Bound the first lookup while discovery continues in the background.
        let _ = tokio::time::timeout(Duration::from_millis(1600), notified).await;
        record.lock().unwrap().resolver.clone()
    }

    fn current_server(&self) -> Option<std::net::SocketAddr> {
        self.endpoint
            .map(|(_, dns)| std::net::SocketAddr::new(dns, 53))
    }
}

enum AuxiliaryResolver<T> {
    Resolver(T),
    Dhcp(Arc<Mutex<DhcpDnsRecord>>),
}

impl<T> AuxiliaryResolver<T> {
    pub fn new_normal(resolver: T) -> Self {
        Self::Resolver(resolver)
    }

    pub fn new_dhcp(iface: &str) -> Self {
        let record = DhcpDnsRecord::new(iface);
        Self::Dhcp(record)
    }

    fn current_dhcp_endpoint(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Resolver(_) => None,
            Self::Dhcp(record) => record.lock().unwrap().current_server(),
        }
    }
}

#[cfg(test)]
mod config_validation_tests {
    use super::validate_dns_config;
    use crate::config::{DnsPreference, RawDnsConfig};
    use std::collections::HashMap;

    fn config(nameservers: &[&str], policies: &[(&str, &str)]) -> RawDnsConfig {
        RawDnsConfig {
            preference: DnsPreference::PreferIpv4,
            bootstrap: vec!["1.1.1.1".parse().unwrap()],
            nameserver: nameservers
                .iter()
                .map(|nameserver| (*nameserver).to_string())
                .collect(),
            hosts: HashMap::new(),
            nameserver_policy: policies
                .iter()
                .map(|(host, policy)| ((*host).to_string(), (*policy).to_string()))
                .collect(),
            tun_hijack_list: None,
            tun_bypass_list: None,
        }
    }

    #[tokio::test]
    async fn validates_nameservers_and_policies_offline() {
        validate_dns_config(&config(
            &["doh, dns.example", "udp, 8.8.8.8"],
            &[("*.internal", "udp, 192.0.2.53, plain")],
        ))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn validates_dhcp_discovery_offline() {
        for config in [
            config(&["dhcp, Ethernet"], &[]),
            config(&["udp, 1.1.1.1"], &[("*.internal", "dhcp, Ethernet")]),
        ] {
            validate_dns_config(&config).await.unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_invalid_nameservers() {
        for nameservers in [
            Vec::new(),
            vec!["missing-delimiter"],
            vec!["udp, not-an-ip"],
            vec!["unknown, 1.1.1.1"],
            vec!["doh-preset, unknown"],
        ] {
            assert!(
                validate_dns_config(&config(&nameservers, &[]))
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn rejects_invalid_nameserver_policies() {
        for policy in ["udp", "udp, 192.0.2.53, bypass"] {
            assert!(
                validate_dns_config(&config(&["udp, 8.8.8.8"], &[("*.internal", policy)],))
                    .await
                    .is_err()
            );
        }
    }
}

#[cfg(test)]
mod dhcp_tests {
    use super::*;

    fn empty_record() -> Arc<Mutex<DhcpDnsRecord>> {
        Arc::new(Mutex::new(DhcpDnsRecord {
            iface: "test-interface".into(),
            endpoint: None,
            last_checked: None,
            refreshing: false,
            ready: Arc::new(tokio::sync::Notify::new()),
            resolver: None,
        }))
    }

    #[test]
    fn refresh_tracks_dns_changes_without_address_change_and_offline_state() {
        let record = empty_record();
        let mut record = record.lock().unwrap();
        assert!(record.current_server().is_none());
        assert!(record.resolver.is_none());
        let addr = "192.0.2.10".parse().unwrap();
        let first_dns = "192.0.2.53".parse().unwrap();
        record.apply(Ok((addr, first_dns)));
        let first = record.resolver.clone().unwrap();
        record.apply(Ok((addr, first_dns)));
        assert!(Arc::ptr_eq(&first, record.resolver.as_ref().unwrap()));
        let second_dns = "192.0.2.54".parse().unwrap();
        record.apply(Ok((addr, second_dns)));
        assert_eq!(record.current_server().unwrap().ip(), second_dns);
        assert!(!Arc::ptr_eq(&first, record.resolver.as_ref().unwrap()));
        record.apply(Err(DnsError::DhcpNameServer("offline")));
        assert!(record.current_server().is_none());
        assert!(record.resolver.is_none());
        assert!(record.last_checked.is_some());
        record.apply(Ok((addr, first_dns)));
        assert_eq!(record.current_server().unwrap().ip(), first_dns);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_discovery_is_single_flight_and_does_not_block_queries() {
        let record = empty_record();
        let (release, hold) = std::sync::mpsc::channel();
        let (started, wait_started) = std::sync::mpsc::channel();
        DhcpDnsRecord::refresh_with(&record, move |_| {
            started.send(()).unwrap();
            hold.recv_timeout(Duration::from_secs(10)).unwrap();
            Err(DnsError::DhcpNameServer("offline"))
        });
        wait_started.recv_timeout(Duration::from_secs(2)).unwrap();
        DhcpDnsRecord::refresh_with(&record, |_| panic!("duplicate probe"));
        assert!(DhcpDnsRecord::get_resolver(&record).await.is_none());
        assert!(record.lock().unwrap().refreshing);
        let ready = record.lock().unwrap().ready.clone();
        let completed = ready.notified();
        tokio::pin!(completed);
        completed.as_mut().enable();
        release.send(()).unwrap();
        // Real time here so the OS worker gets a chance to finish.
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(2), completed)
            .await
            .unwrap();
        DhcpDnsRecord::refresh_with(&record, |_| panic!("retry was not throttled"));
        assert!(!record.lock().unwrap().refreshing);
    }

    #[tokio::test]
    #[cfg(windows)]
    #[ignore = "uses DHCP and resolves example.com on BOLTCONN_TEST_DHCP_INTERFACE"]
    async fn live_windows_dhcp_resolver() {
        let iface = std::env::var("BOLTCONN_TEST_DHCP_INTERFACE").unwrap();
        let expected: IpAddr = std::env::var("BOLTCONN_TEST_DHCP_DNS")
            .unwrap()
            .parse()
            .unwrap();
        let record = DhcpDnsRecord::new(&iface);
        assert!(Arc::ptr_eq(
            &record,
            &DhcpDnsRecord::new(&iface.to_ascii_uppercase())
        ));
        let resolver = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(resolver) = DhcpDnsRecord::get_resolver(&record).await {
                    break resolver;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            record.lock().unwrap().current_server().unwrap().ip(),
            expected
        );
        assert!(
            !resolver
                .ipv4_lookup("example.com")
                .await
                .unwrap()
                .answers()
                .is_empty()
        );
    }
}
