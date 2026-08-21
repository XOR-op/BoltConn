use crate::config::DnsPreference;
use crate::network::dns::dns_table::DnsTable;
use crate::network::dns::hosts::HostsResolver;
use crate::network::dns::ns_policy::{DispatchedDnsResolver, NameserverPolicies, PolicyResolver};
use crate::network::dns::observability::{
    CACHE_HIT_THRESHOLD, DnsResolverIdentity, DnsResolverRecord, identity_from_config,
    identity_from_normal,
};
use crate::network::dns::provider::IfaceProvider;
use crate::network::dns::{AuxiliaryResolver, NameServerConfigEnum, default_resolver_opt};
use crate::proxy::error::TransportError;
use crate::proxy::{ConnHandle, bounded_error_detail};
use arc_swap::ArcSwap;
use boltapi::{
    ApiError, ApiErrorCode, DnsActivity, DnsAnswer, DnsAttemptScope, DnsCacheStatus, DnsErrorCode,
    DnsErrorCount, DnsLookupDetail, DnsLookupPurpose, DnsLookupRequest, DnsOutcome,
    DnsOutcomeCounts, DnsProtocol, DnsRecordType, DnsResolverAttempt, DnsResolverDetail,
    DnsResolverSummary, DnsResponseKind, DnsScope, DnsSelection, FakeIpMapping, RouteEgress,
    Snapshot,
};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::Resolver;
use hickory_resolver::config::*;
use hickory_resolver::net::{DnsError as HickoryDnsError, NetError, runtime::RuntimeProvider};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const OUTER_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn validate_diagnostic_domain(domain: &str) -> Result<(), ApiError> {
    if domain.trim().is_empty() || Name::from_ascii(domain).is_err() {
        return Err(ApiError {
            code: ApiErrorCode::InvalidRequest,
            message: "invalid DNS name".to_string(),
        });
    }
    Ok(())
}

struct ResolverEntry<P: RuntimeProvider> {
    resolver: AuxiliaryResolver<Resolver<P>>,
    identity: DnsResolverIdentity,
    record: Arc<DnsResolverRecord>,
    scope: DnsScope,
    attempt_scope: DnsAttemptScope,
}

struct DnsRuntime<P: RuntimeProvider> {
    preference: DnsPreference,
    hosts: HostsResolver,
    policies: NameserverPolicies,
    resolvers: Vec<ResolverEntry<P>>,
    /// Contains only identities present in this runtime. Holding the previous
    /// runtime for an in-flight lookup cannot accidentally resurrect a record
    /// after it has been removed and later re-added.
    records: HashMap<String, Arc<DnsResolverRecord>>,
}

#[derive(Clone)]
struct ResolverView {
    identity: DnsResolverIdentity,
    record: Arc<DnsResolverRecord>,
    scopes: Vec<DnsScope>,
}

struct QueryAttemptResult {
    answers: Vec<IpAddr>,
    outcome: DnsOutcome,
    duration: Duration,
    cache_hit: bool,
    io_error: Option<(io::ErrorKind, String)>,
}

struct LookupExecution {
    selected: Option<IpAddr>,
    detail: DnsLookupDetail,
    io_error: Option<(io::ErrorKind, String)>,
}

pub struct GenericDns<P: RuntimeProvider> {
    name: String,
    table: DnsTable,
    runtime: ArcSwap<DnsRuntime<P>>,
    activity: Mutex<DnsActivity>,
}

pub type Dns = GenericDns<IfaceProvider>;

impl Dns {
    pub fn with_config(
        name: &str,
        iface_name: &str,
        preference: DnsPreference,
        hosts: &HashMap<String, IpAddr>,
        policies: NameserverPolicies,
        configs: Vec<NameServerConfigEnum>,
    ) -> Dns {
        let runtime = Self::build_runtime(iface_name, preference, hosts, policies, configs, None);
        Dns {
            name: name.to_string(),
            table: DnsTable::new(),
            runtime: ArcSwap::new(Arc::new(runtime)),
            activity: Mutex::new(empty_dns_activity()),
        }
    }

    /// Publishes hosts, policy selection, preference, and upstream resolvers as
    /// one generation. In-flight queries retain the old Arc and finish against
    /// a coherent old configuration.
    pub fn replace_runtime(
        &self,
        iface_name: &str,
        preference: DnsPreference,
        hosts: &HashMap<String, IpAddr>,
        policies: NameserverPolicies,
        configs: Vec<NameServerConfigEnum>,
    ) {
        let previous = self.runtime.load_full();
        let runtime = Self::build_runtime(
            iface_name,
            preference,
            hosts,
            policies,
            configs,
            Some(previous.as_ref()),
        );
        self.runtime.store(Arc::new(runtime));
    }

    fn build_runtime(
        iface_name: &str,
        preference: DnsPreference,
        hosts: &HashMap<String, IpAddr>,
        mut policies: NameserverPolicies,
        configs: Vec<NameServerConfigEnum>,
        previous: Option<&DnsRuntime<IfaceProvider>>,
    ) -> DnsRuntime<IfaceProvider> {
        let mut records = HashMap::new();
        let mut resolvers = Vec::with_capacity(configs.len());

        for (index, config) in configs.into_iter().enumerate() {
            let via = match &config {
                NameServerConfigEnum::Dhcp(interface) => RouteEgress::Interface {
                    name: interface.clone(),
                },
                NameServerConfigEnum::Normal(_) => RouteEgress::Interface {
                    name: iface_name.to_string(),
                },
            };
            let identity = identity_from_config(&config, via, 1600, 3);
            let record = active_record(&identity, &mut records, previous.map(|old| &old.records));
            let resolver = match config {
                NameServerConfigEnum::Normal(config) => {
                    let cfg = ResolverConfig::from_parts(None, vec![], config);
                    AuxiliaryResolver::new_normal(
                        Resolver::builder_with_config(cfg, IfaceProvider::new(iface_name))
                            .with_options(default_resolver_opt())
                            .build()
                            .expect("rustls miscompiled"),
                    )
                }
                NameServerConfigEnum::Dhcp(interface) => AuxiliaryResolver::new_dhcp(&interface),
            };
            let order = u32::try_from(index + 1).unwrap_or(u32::MAX);
            resolvers.push(ResolverEntry {
                resolver,
                identity,
                record,
                scope: DnsScope::Global { order },
                attempt_scope: DnsAttemptScope::Global { order },
            });
        }

        for policy in policies.entries_mut() {
            let record = active_record(
                &policy.identity,
                &mut records,
                previous.map(|old| &old.records),
            );
            policy.record = record;
        }

        // The same logical identity may be selected by several scopes. Merge
        // their variable endpoints once per generation instead of allowing the
        // last binding to overwrite evidence from earlier bindings.
        let mut current_endpoints = HashMap::<String, Vec<SocketAddr>>::new();
        for entry in &resolvers {
            let endpoints = current_endpoints
                .entry(entry.identity.id.clone())
                .or_default();
            endpoints.extend(entry.identity.current_endpoints.iter().copied());
            endpoints.extend(entry.resolver.current_dhcp_endpoint());
        }
        for policy in policies.entries() {
            let endpoints = current_endpoints
                .entry(policy.identity.id.clone())
                .or_default();
            endpoints.extend(policy.identity.current_endpoints.iter().copied());
            if let DispatchedDnsResolver::Iface(resolver) = &policy.resolver {
                endpoints.extend(resolver.current_dhcp_endpoint());
            }
        }
        for (id, endpoints) in current_endpoints {
            if let Some(record) = records.get(&id) {
                record.set_current_endpoints(endpoints);
            }
        }

        DnsRuntime {
            preference,
            hosts: HostsResolver::new(hosts),
            policies,
            resolvers,
            records,
        }
    }
}

fn active_record(
    identity: &DnsResolverIdentity,
    active: &mut HashMap<String, Arc<DnsResolverRecord>>,
    previous: Option<&HashMap<String, Arc<DnsResolverRecord>>>,
) -> Arc<DnsResolverRecord> {
    if let Some(record) = active.get(&identity.id) {
        return record.clone();
    }
    let record = previous
        .and_then(|records| records.get(&identity.id))
        .cloned()
        .unwrap_or_else(|| Arc::new(DnsResolverRecord::new(identity)));
    active.insert(identity.id.clone(), record.clone());
    record
}

impl<P: RuntimeProvider> GenericDns<P> {
    pub fn new_with_resolver_config(
        name: &str,
        resolver: Resolver<P>,
        preference: DnsPreference,
        configs: &[NameServerConfig],
    ) -> Self {
        let identity = identity_from_normal(
            configs,
            RouteEgress::Link {
                name: name.to_string(),
            },
            1500,
            3,
        );
        let record = Arc::new(DnsResolverRecord::new(&identity));
        let records = HashMap::from([(identity.id.clone(), record.clone())]);
        let runtime = DnsRuntime {
            preference,
            hosts: HostsResolver::empty(),
            policies: NameserverPolicies::empty(),
            resolvers: vec![ResolverEntry {
                resolver: AuxiliaryResolver::new_normal(resolver),
                identity,
                record,
                scope: DnsScope::Link {
                    name: name.to_string(),
                },
                attempt_scope: DnsAttemptScope::Link {
                    name: name.to_string(),
                },
            }],
            records,
        };
        Self {
            name: name.to_string(),
            table: DnsTable::new(),
            runtime: ArcSwap::new(Arc::new(runtime)),
            activity: Mutex::new(empty_dns_activity()),
        }
    }

    /// Return fake IP for the domain name instantly.
    pub fn domain_to_fake_ip(&self, domain_name: &str) -> IpAddr {
        self.table.query_by_domain_name(domain_name).ip
    }

    /// Return the mapped domain for a fake IP, when present.
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

    pub fn fake_ip_mapping(&self, fake_ip: IpAddr) -> Result<FakeIpMapping, ApiError> {
        self.fake_ip_to_domain(fake_ip)
            .map(|domain| FakeIpMapping { fake_ip, domain })
            .ok_or_else(|| ApiError {
                code: ApiErrorCode::DnsMappingNotFound,
                message: format!("no fake-DNS mapping exists for {fake_ip}"),
            })
    }

    pub async fn genuine_lookup(
        &self,
        domain_name: &str,
    ) -> Result<Option<IpAddr>, TransportError> {
        let runtime = self.runtime.load_full();
        self.genuine_lookup_in_runtime(
            runtime,
            domain_name,
            None,
            DnsLookupPurpose::Destination,
            None,
        )
        .await
    }

    /// Performs a normal dataplane lookup and retains its structured evidence
    /// on the supplied connection. Passing no connection still updates resolver
    /// statistics, which is required for diagnostics and shared-link setup.
    pub async fn genuine_lookup_for(
        &self,
        domain_name: &str,
        purpose: DnsLookupPurpose,
        conn: Option<&ConnHandle>,
    ) -> Result<Option<IpAddr>, TransportError> {
        let runtime = self.runtime.load_full();
        self.genuine_lookup_in_runtime(runtime, domain_name, None, purpose, conn)
            .await
    }

    /// Returns the lookup outcome and evidence independently so link generations
    /// can retain setup/reconnect failures without attributing them to whichever
    /// child triggered lazy creation.
    pub async fn genuine_lookup_with_evidence(
        &self,
        domain_name: &str,
        purpose: DnsLookupPurpose,
    ) -> (Result<Option<IpAddr>, TransportError>, DnsLookupDetail) {
        let runtime = self.runtime.load_full();
        let execution = self
            .execute_normal_lookup(runtime.as_ref(), domain_name, runtime.preference, purpose)
            .await;
        self.remember_lookup(execution.detail.clone());
        let detail = execution.detail.clone();
        (
            execution_result(execution).map(|(selected, _)| selected),
            detail,
        )
    }

    pub async fn genuine_lookup_with_for(
        &self,
        domain_name: &str,
        preference: DnsPreference,
        purpose: DnsLookupPurpose,
        conn: Option<&ConnHandle>,
    ) -> Result<Option<IpAddr>, TransportError> {
        let runtime = self.runtime.load_full();
        self.genuine_lookup_in_runtime(runtime, domain_name, Some(preference), purpose, conn)
            .await
    }

    async fn genuine_lookup_in_runtime(
        &self,
        runtime: Arc<DnsRuntime<P>>,
        domain_name: &str,
        preference: Option<DnsPreference>,
        purpose: DnsLookupPurpose,
        conn: Option<&ConnHandle>,
    ) -> Result<Option<IpAddr>, TransportError> {
        let execution = self
            .execute_normal_lookup(
                runtime.as_ref(),
                domain_name,
                preference.unwrap_or(runtime.preference),
                purpose,
            )
            .await;
        self.remember_lookup(execution.detail.clone());
        if let Some(conn) = conn {
            conn.record_dns_lookup(execution.detail.clone());
        }
        execution_result(execution).map(|(selected, _)| selected)
    }

    pub(crate) fn resolver_snapshot_at(&self, observed_at_ms: u64) -> Snapshot<DnsResolverSummary> {
        let runtime = self.runtime.load_full();
        let mut items = resolver_views(runtime.as_ref())
            .into_iter()
            .filter(|view| view.record.lookups() > 0)
            .map(|mut view| {
                sort_dns_scopes(&mut view.scopes);
                view.record.summary(&view.identity, view.scopes)
            })
            .collect::<Vec<_>>();
        sort_resolver_summaries(&mut items);
        Snapshot {
            observed_at_ms,
            items,
        }
    }

    pub(crate) fn resolver_detail_at(
        &self,
        id_prefix: &str,
        observed_at_ms: u64,
    ) -> Result<DnsResolverDetail, ApiError> {
        let runtime = self.runtime.load_full();
        let id = resolve_prefix(runtime.as_ref(), id_prefix, true)?;
        let mut view = resolver_views(runtime.as_ref())
            .into_iter()
            .find(|view| view.identity.id == id)
            .ok_or_else(|| resolver_not_found(id_prefix))?;
        sort_dns_scopes(&mut view.scopes);
        Ok(view
            .record
            .detail(observed_at_ms, &view.identity, view.scopes, Vec::new()))
    }

    pub(crate) fn resolver_ids(&self) -> Vec<String> {
        let runtime = self.runtime.load_full();
        let mut ids = runtime.records.keys().cloned().collect::<Vec<_>>();
        ids.sort_unstable();
        ids
    }

    pub(crate) async fn diagnostic_lookup_detail(
        &self,
        request: DnsLookupRequest,
    ) -> Result<DnsLookupDetail, ApiError> {
        validate_diagnostic_domain(&request.domain)?;
        let runtime = self.runtime.load_full();
        let execution = if let Some(prefix) = request.resolver_id.as_deref() {
            let id = resolve_prefix(runtime.as_ref(), prefix, false)?;
            self.execute_explicit_lookup(runtime.as_ref(), &request.domain, runtime.preference, &id)
                .await?
        } else {
            self.execute_normal_lookup(
                runtime.as_ref(),
                &request.domain,
                runtime.preference,
                DnsLookupPurpose::Diagnostic,
            )
            .await
        };
        self.remember_lookup(execution.detail.clone());
        Ok(execution.detail)
    }

    pub(crate) fn dns_activity(&self) -> DnsActivity {
        self.activity.lock().unwrap().clone()
    }

    fn remember_lookup(&self, lookup: DnsLookupDetail) {
        let mut activity = self.activity.lock().unwrap();
        activity.lookups = activity.lookups.saturating_add(1);
        if matches!(lookup.cache, DnsCacheStatus::Hit { .. }) {
            activity.outcomes.cache_hits = activity.outcomes.cache_hits.saturating_add(1);
        }
        match &lookup.result {
            DnsOutcome::Answered { .. } => {
                activity.outcomes.answered = activity.outcomes.answered.saturating_add(1);
            }
            DnsOutcome::Timeout => {
                activity.outcomes.timeout = activity.outcomes.timeout.saturating_add(1);
            }
            DnsOutcome::Error { code, .. } => {
                activity.outcomes.error = activity.outcomes.error.saturating_add(1);
                if let Some(error) = activity
                    .outcomes
                    .errors
                    .iter_mut()
                    .find(|error| error.code == *code)
                {
                    error.count = error.count.saturating_add(1);
                } else {
                    activity.outcomes.errors.push(DnsErrorCount {
                        code: *code,
                        count: 1,
                    });
                    activity
                        .outcomes
                        .errors
                        .sort_by_key(|error| error.code as u8);
                }
            }
        }
        activity.latest_lookup = Some(lookup);
    }

    async fn execute_normal_lookup(
        &self,
        runtime: &DnsRuntime<P>,
        domain_name: &str,
        preference: DnsPreference,
        purpose: DnsLookupPurpose,
    ) -> LookupExecution {
        let started = Instant::now();
        if let Some(address) = runtime.hosts.resolve(domain_name)
            && preference_accepts(preference, address)
        {
            let record_type = if address.is_ipv4() {
                DnsRecordType::A
            } else {
                DnsRecordType::Aaaa
            };
            return LookupExecution {
                selected: Some(address),
                detail: DnsLookupDetail {
                    purpose,
                    name: domain_name.to_string(),
                    selection: DnsSelection::Hosts,
                    cache: DnsCacheStatus::NotApplicable,
                    attempts: Vec::new(),
                    answers: vec![DnsAnswer {
                        record_type,
                        address,
                        selected: true,
                    }],
                    result: DnsOutcome::Answered {
                        response: DnsResponseKind::Answer,
                    },
                    duration_ms: elapsed_ms(started.elapsed()),
                },
                io_error: None,
            };
        }

        if let Some(policy) = runtime.policies.resolve(domain_name) {
            let selection = DnsSelection::Policy {
                matcher: policy.matcher_summary.clone(),
            };
            return self
                .execute_policy_lookup(domain_name, preference, purpose, selection, policy, started)
                .await;
        }

        self.execute_global_lookup(domain_name, preference, purpose, runtime, started)
            .await
    }

    async fn execute_global_lookup(
        &self,
        domain_name: &str,
        preference: DnsPreference,
        purpose: DnsLookupPurpose,
        runtime: &DnsRuntime<P>,
        started: Instant,
    ) -> LookupExecution {
        let mut attempts = Vec::new();
        let mut io_error = None;
        let mut last_outcome = no_resolver_outcome();
        let mut final_cache_hit = None;
        for record_type in record_type_order(preference) {
            for entry in &runtime.resolvers {
                let result = query_auxiliary(
                    &self.name,
                    domain_name,
                    record_type,
                    &entry.resolver,
                    &entry.identity,
                    &entry.record,
                )
                .await;
                if result.io_error.is_some() {
                    io_error = result.io_error.clone();
                }
                final_cache_hit = result.cache_hit.then(|| entry.record.id().to_string());
                let attempt = resolver_attempt(
                    entry.record.id(),
                    entry.attempt_scope.clone(),
                    record_type,
                    &result,
                );
                last_outcome = result.outcome.clone();
                if !result.answers.is_empty() {
                    return finish_lookup(
                        purpose,
                        domain_name,
                        DnsSelection::Global,
                        attempts,
                        attempt,
                        result,
                        record_type,
                        started.elapsed(),
                        io_error,
                    );
                }
                attempts.push(attempt);
            }
        }
        LookupExecution {
            selected: None,
            detail: DnsLookupDetail {
                purpose,
                name: domain_name.to_string(),
                selection: DnsSelection::Global,
                cache: final_cache_hit
                    .clone()
                    .map(|resolver_id| DnsCacheStatus::Hit { resolver_id })
                    .unwrap_or(DnsCacheStatus::Miss),
                attempts: if final_cache_hit.is_some() {
                    Vec::new()
                } else {
                    attempts
                },
                answers: Vec::new(),
                result: last_outcome,
                duration_ms: elapsed_ms(started.elapsed()),
            },
            io_error,
        }
    }

    async fn execute_policy_lookup(
        &self,
        domain_name: &str,
        preference: DnsPreference,
        purpose: DnsLookupPurpose,
        selection: DnsSelection,
        policy: &PolicyResolver,
        started: Instant,
    ) -> LookupExecution {
        let mut attempts = Vec::new();
        let mut io_error = None;
        let mut last_outcome = no_resolver_outcome();
        let mut final_cache_hit = None;
        for record_type in record_type_order(preference) {
            let result = query_dispatched(
                &self.name,
                domain_name,
                record_type,
                &policy.resolver,
                &policy.identity,
                &policy.record,
            )
            .await;
            policy.refresh_dhcp_endpoint();
            if result.io_error.is_some() {
                io_error = result.io_error.clone();
            }
            final_cache_hit = result.cache_hit.then(|| policy.record.id().to_string());
            let attempt = resolver_attempt(
                policy.record.id(),
                if matches!(&selection, DnsSelection::Explicit { .. }) {
                    DnsAttemptScope::Explicit
                } else {
                    policy.attempt_scope()
                },
                record_type,
                &result,
            );
            last_outcome = result.outcome.clone();
            if !result.answers.is_empty() {
                return finish_lookup(
                    purpose,
                    domain_name,
                    selection,
                    attempts,
                    attempt,
                    result,
                    record_type,
                    started.elapsed(),
                    io_error,
                );
            }
            attempts.push(attempt);
        }
        LookupExecution {
            selected: None,
            detail: DnsLookupDetail {
                purpose,
                name: domain_name.to_string(),
                selection,
                cache: final_cache_hit
                    .clone()
                    .map(|resolver_id| DnsCacheStatus::Hit { resolver_id })
                    .unwrap_or(DnsCacheStatus::Miss),
                attempts: if final_cache_hit.is_some() {
                    Vec::new()
                } else {
                    attempts
                },
                answers: Vec::new(),
                result: last_outcome,
                duration_ms: elapsed_ms(started.elapsed()),
            },
            io_error,
        }
    }

    async fn execute_explicit_lookup(
        &self,
        runtime: &DnsRuntime<P>,
        domain_name: &str,
        preference: DnsPreference,
        resolver_id: &str,
    ) -> Result<LookupExecution, ApiError> {
        let started = Instant::now();
        if let Some(entry) = runtime
            .resolvers
            .iter()
            .find(|entry| entry.identity.id == resolver_id)
        {
            let mut attempts = Vec::new();
            let mut io_error = None;
            let mut last_outcome = no_resolver_outcome();
            let mut final_cache_hit = None;
            for record_type in record_type_order(preference) {
                let result = query_auxiliary(
                    &self.name,
                    domain_name,
                    record_type,
                    &entry.resolver,
                    &entry.identity,
                    &entry.record,
                )
                .await;
                if result.io_error.is_some() {
                    io_error = result.io_error.clone();
                }
                final_cache_hit = result.cache_hit.then(|| entry.record.id().to_string());
                let attempt = resolver_attempt(
                    entry.record.id(),
                    DnsAttemptScope::Explicit,
                    record_type,
                    &result,
                );
                last_outcome = result.outcome.clone();
                if !result.answers.is_empty() {
                    return Ok(finish_lookup(
                        DnsLookupPurpose::Diagnostic,
                        domain_name,
                        DnsSelection::Explicit {
                            resolver_id: resolver_id.to_string(),
                        },
                        attempts,
                        attempt,
                        result,
                        record_type,
                        started.elapsed(),
                        io_error,
                    ));
                }
                attempts.push(attempt);
            }
            return Ok(failed_explicit_lookup(
                domain_name,
                resolver_id,
                attempts,
                last_outcome,
                started.elapsed(),
                io_error,
                final_cache_hit,
            ));
        }

        if let Some(policy) = runtime
            .policies
            .entries()
            .find(|entry| entry.identity.id == resolver_id)
        {
            return Ok(self
                .execute_policy_lookup(
                    domain_name,
                    preference,
                    DnsLookupPurpose::Diagnostic,
                    DnsSelection::Explicit {
                        resolver_id: resolver_id.to_string(),
                    },
                    policy,
                    started,
                )
                .await);
        }

        Err(ApiError {
            code: ApiErrorCode::ResolverUnavailable,
            message: format!("resolver {resolver_id} is not available in the live runtime"),
        })
    }

    /// If no corresponding record exists, return the fake IP itself.
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
        // There should be no more than one question in a normal DNS request.
        let err = Err(io::Error::new(io::ErrorKind::InvalidData, "fail to answer"));
        let req = Message::from_vec(pkt)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if req.queries.is_empty() {
            return err;
        }
        let query = &req.queries[0];
        let domain = query.name().to_string();

        let mut response = Message::new(req.id, MessageType::Response, req.op_code);
        response.metadata.response_code = ResponseCode::NoError;
        response.metadata.recursion_desired = req.recursion_desired;
        response.metadata.recursion_available = req.recursion_desired;
        response.metadata.checking_disabled = req.checking_disabled;
        response.add_query(query.clone());
        match query.query_type() {
            RecordType::A => {
                let fake_ip = match self.domain_to_fake_ip(&domain) {
                    IpAddr::V4(address) => address,
                    IpAddr::V6(_) => return err,
                };
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::A(hickory_proto::rr::rdata::A(fake_ip)),
                ));
                response
                    .to_vec()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            }
            // Fake DNS only synthesizes A records. Other valid query types get
            // NODATA so clients do not treat the resolver as unavailable.
            _ => response
                .to_vec()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        }
    }
}

fn execution_result(
    execution: LookupExecution,
) -> Result<(Option<IpAddr>, DnsLookupDetail), TransportError> {
    if execution.selected.is_none()
        && matches!(
            &execution.detail.result,
            DnsOutcome::Error {
                code: DnsErrorCode::Transport,
                ..
            }
        )
        && let Some((kind, detail)) = execution.io_error
    {
        return Err(TransportError::Io(io::Error::new(kind, detail)));
    }
    Ok((execution.selected, execution.detail))
}

fn resolver_views<P: RuntimeProvider>(runtime: &DnsRuntime<P>) -> Vec<ResolverView> {
    let mut indexes = HashMap::<String, usize>::new();
    let mut views = Vec::<ResolverView>::new();
    for entry in &runtime.resolvers {
        add_resolver_view(
            &mut indexes,
            &mut views,
            &entry.identity,
            &entry.record,
            entry.scope.clone(),
        );
    }
    for policy in runtime.policies.entries() {
        add_resolver_view(
            &mut indexes,
            &mut views,
            &policy.identity,
            &policy.record,
            policy.scope(),
        );
    }
    views
}

fn sort_dns_scopes(scopes: &mut [DnsScope]) {
    scopes.sort_by(compare_dns_scopes);
}

fn compare_dns_scopes(left: &DnsScope, right: &DnsScope) -> std::cmp::Ordering {
    match (left, right) {
        (DnsScope::Global { order: left }, DnsScope::Global { order: right }) => left.cmp(right),
        (DnsScope::Global { .. }, _) => std::cmp::Ordering::Less,
        (_, DnsScope::Global { .. }) => std::cmp::Ordering::Greater,
        (
            DnsScope::Policy {
                matchers: left_matchers,
            },
            DnsScope::Policy {
                matchers: right_matchers,
            },
        ) => left_matchers.cmp(right_matchers),
        (DnsScope::Policy { .. }, DnsScope::Link { .. }) => std::cmp::Ordering::Less,
        (DnsScope::Link { .. }, DnsScope::Policy { .. }) => std::cmp::Ordering::Greater,
        (DnsScope::Link { name: left }, DnsScope::Link { name: right }) => left.cmp(right),
    }
}

pub(crate) fn sort_resolver_summaries(items: &mut [DnsResolverSummary]) {
    for item in items.iter_mut() {
        sort_dns_scopes(&mut item.scopes);
    }
    items.sort_by(|left, right| {
        match (left.scopes.first(), right.scopes.first()) {
            (Some(left), Some(right)) => compare_dns_scopes(left, right),
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, None) => std::cmp::Ordering::Equal,
        }
        .then_with(|| left.id.cmp(&right.id))
    });
}

fn add_resolver_view(
    indexes: &mut HashMap<String, usize>,
    views: &mut Vec<ResolverView>,
    identity: &DnsResolverIdentity,
    record: &Arc<DnsResolverRecord>,
    scope: DnsScope,
) {
    if let Some(index) = indexes.get(&identity.id).copied() {
        views[index].scopes.push(scope);
    } else {
        indexes.insert(identity.id.clone(), views.len());
        views.push(ResolverView {
            identity: identity.clone(),
            record: record.clone(),
            scopes: vec![scope],
        });
    }
}

fn resolve_prefix<P: RuntimeProvider>(
    runtime: &DnsRuntime<P>,
    prefix: &str,
    observed_only: bool,
) -> Result<String, ApiError> {
    if prefix.is_empty() {
        return Err(resolver_not_found(prefix));
    }
    let mut matches = runtime
        .records
        .iter()
        .filter(|(id, record)| id.starts_with(prefix) && (!observed_only || record.lookups() > 0))
        .map(|(id, _)| id.clone());
    let Some(first) = matches.next() else {
        return Err(resolver_not_found(prefix));
    };
    if matches.next().is_some() {
        return Err(ApiError {
            code: ApiErrorCode::ResolverIdAmbiguous,
            message: format!("resolver ID prefix {prefix:?} is ambiguous"),
        });
    }
    Ok(first)
}

fn resolver_not_found(prefix: &str) -> ApiError {
    ApiError {
        code: ApiErrorCode::ResolverNotFound,
        message: format!("resolver ID prefix {prefix:?} was not found"),
    }
}

async fn query_auxiliary<P: RuntimeProvider>(
    dns_name: &str,
    domain_name: &str,
    record_type: DnsRecordType,
    resolver: &AuxiliaryResolver<Resolver<P>>,
    identity: &DnsResolverIdentity,
    record: &DnsResolverRecord,
) -> QueryAttemptResult {
    match resolver {
        AuxiliaryResolver::Dhcp(inner) => {
            let resolver = {
                let mut guard = inner.lock().unwrap();
                if let Err(error) = guard.refresh() {
                    tracing::warn!(
                        "failed to update DHCP DNS at ({},{},{}): {:?}",
                        guard.iface,
                        guard.iface_addr,
                        guard.ns_addr,
                        error
                    );
                }
                record.set_current_endpoints(vec![guard.current_server()]);
                guard.get_resolver()
            };
            query_one(
                dns_name,
                domain_name,
                record_type,
                resolver.as_ref(),
                identity.protocol,
                record,
            )
            .await
        }
        AuxiliaryResolver::Resolver(inner) => {
            query_one(
                dns_name,
                domain_name,
                record_type,
                inner,
                identity.protocol,
                record,
            )
            .await
        }
    }
}

async fn query_dispatched(
    dns_name: &str,
    domain_name: &str,
    record_type: DnsRecordType,
    resolver: &DispatchedDnsResolver,
    identity: &DnsResolverIdentity,
    record: &DnsResolverRecord,
) -> QueryAttemptResult {
    match resolver {
        DispatchedDnsResolver::Iface(resolver) => {
            query_auxiliary(
                dns_name,
                domain_name,
                record_type,
                resolver,
                identity,
                record,
            )
            .await
        }
        DispatchedDnsResolver::Plain(resolver) => {
            query_one(
                dns_name,
                domain_name,
                record_type,
                resolver,
                identity.protocol,
                record,
            )
            .await
        }
    }
}

async fn query_one<R: RuntimeProvider>(
    dns_name: &str,
    domain_name: &str,
    record_type: DnsRecordType,
    resolver: &Resolver<R>,
    protocol: DnsProtocol,
    record: &DnsResolverRecord,
) -> QueryAttemptResult {
    let started = Instant::now();
    let result = match record_type {
        DnsRecordType::A => {
            tokio::time::timeout(OUTER_LOOKUP_TIMEOUT, resolver.ipv4_lookup(domain_name))
                .await
                .map(|result| {
                    result.map(|lookup| {
                        lookup
                            .answers()
                            .iter()
                            .filter_map(|record| match record.data {
                                RData::A(address) => Some(IpAddr::V4(address.0)),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                    })
                })
        }
        DnsRecordType::Aaaa => {
            tokio::time::timeout(OUTER_LOOKUP_TIMEOUT, resolver.ipv6_lookup(domain_name))
                .await
                .map(|result| {
                    result.map(|lookup| {
                        lookup
                            .answers()
                            .iter()
                            .filter_map(|record| match record.data {
                                RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                    })
                })
        }
    };
    let duration = started.elapsed();
    let (answers, outcome, io_error) = match result {
        Err(_) => {
            tracing::debug!(
                "DNS {} {:?} lookup for {} timed out after {:?}",
                dns_name,
                record_type,
                domain_name,
                OUTER_LOOKUP_TIMEOUT
            );
            (Vec::new(), DnsOutcome::Timeout, None)
        }
        Ok(Ok(answers)) if answers.is_empty() => (
            answers,
            DnsOutcome::Answered {
                response: DnsResponseKind::NoData,
            },
            None,
        ),
        Ok(Ok(answers)) => (
            answers,
            DnsOutcome::Answered {
                response: DnsResponseKind::Answer,
            },
            None,
        ),
        Ok(Err(error)) => classify_net_error(&error, protocol),
    };
    let cache_hit =
        duration < CACHE_HIT_THRESHOLD && matches!(outcome, DnsOutcome::Answered { .. });
    // Resolver-wide state must not retain queried names. Per-connection and
    // one-shot lookup evidence keeps the bounded instance detail instead.
    let retained_outcome = match &outcome {
        DnsOutcome::Error { code, .. } => DnsOutcome::Error {
            code: *code,
            detail: None,
        },
        _ => outcome.clone(),
    };
    record.observe(duration, retained_outcome);
    QueryAttemptResult {
        answers,
        outcome,
        duration,
        cache_hit,
        io_error,
    }
}

fn classify_net_error(
    error: &NetError,
    protocol: DnsProtocol,
) -> (Vec<IpAddr>, DnsOutcome, Option<(io::ErrorKind, String)>) {
    match error {
        NetError::Dns(HickoryDnsError::NoRecordsFound(no_records)) => {
            let response = if no_records.response_code == ResponseCode::NXDomain {
                DnsResponseKind::NxDomain
            } else {
                DnsResponseKind::NoData
            };
            (Vec::new(), DnsOutcome::Answered { response }, None)
        }
        NetError::Dns(HickoryDnsError::ResponseCode(code)) => {
            let code = match *code {
                ResponseCode::ServFail => DnsErrorCode::Servfail,
                ResponseCode::Refused => DnsErrorCode::Refused,
                _ => DnsErrorCode::Response,
            };
            (
                Vec::new(),
                DnsOutcome::Error {
                    code,
                    detail: Some(bounded_error_detail(&error.to_string())),
                },
                None,
            )
        }
        NetError::Timeout => (Vec::new(), DnsOutcome::Timeout, None),
        NetError::Io(source) => {
            let detail = bounded_error_detail(&source.to_string());
            (
                Vec::new(),
                DnsOutcome::Error {
                    code: DnsErrorCode::Transport,
                    detail: Some(detail.clone()),
                },
                Some((source.kind(), detail)),
            )
        }
        _ => {
            let code = match protocol {
                DnsProtocol::Doh => DnsErrorCode::Http,
                DnsProtocol::Dot => DnsErrorCode::Tls,
                DnsProtocol::Udp | DnsProtocol::Tcp => DnsErrorCode::Local,
            };
            (
                Vec::new(),
                DnsOutcome::Error {
                    code,
                    detail: Some(bounded_error_detail(&error.to_string())),
                },
                None,
            )
        }
    }
}

fn resolver_attempt(
    resolver_id: &str,
    scope: DnsAttemptScope,
    record_type: DnsRecordType,
    result: &QueryAttemptResult,
) -> DnsResolverAttempt {
    DnsResolverAttempt {
        resolver_id: resolver_id.to_string(),
        scope,
        record_type,
        duration_ms: elapsed_ms(result.duration),
        result: result.outcome.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_lookup(
    purpose: DnsLookupPurpose,
    domain_name: &str,
    selection: DnsSelection,
    mut previous_attempts: Vec<DnsResolverAttempt>,
    successful_attempt: DnsResolverAttempt,
    result: QueryAttemptResult,
    record_type: DnsRecordType,
    duration: Duration,
    io_error: Option<(io::ErrorKind, String)>,
) -> LookupExecution {
    let resolver_id = successful_attempt.resolver_id.clone();
    let cache = if result.cache_hit {
        previous_attempts.clear();
        DnsCacheStatus::Hit { resolver_id }
    } else {
        previous_attempts.push(successful_attempt);
        DnsCacheStatus::Miss
    };
    let selected = result.answers.first().copied();
    LookupExecution {
        selected,
        detail: DnsLookupDetail {
            purpose,
            name: domain_name.to_string(),
            selection,
            cache,
            attempts: previous_attempts,
            answers: result
                .answers
                .into_iter()
                .map(|address| DnsAnswer {
                    record_type,
                    address,
                    selected: true,
                })
                .collect(),
            result: result.outcome,
            duration_ms: elapsed_ms(duration),
        },
        io_error,
    }
}

fn failed_explicit_lookup(
    domain_name: &str,
    resolver_id: &str,
    attempts: Vec<DnsResolverAttempt>,
    result: DnsOutcome,
    duration: Duration,
    io_error: Option<(io::ErrorKind, String)>,
    cache_hit: Option<String>,
) -> LookupExecution {
    LookupExecution {
        selected: None,
        detail: DnsLookupDetail {
            purpose: DnsLookupPurpose::Diagnostic,
            name: domain_name.to_string(),
            selection: DnsSelection::Explicit {
                resolver_id: resolver_id.to_string(),
            },
            cache: cache_hit
                .clone()
                .map(|resolver_id| DnsCacheStatus::Hit { resolver_id })
                .unwrap_or(DnsCacheStatus::Miss),
            attempts: if cache_hit.is_some() {
                Vec::new()
            } else {
                attempts
            },
            answers: Vec::new(),
            result,
            duration_ms: elapsed_ms(duration),
        },
        io_error,
    }
}

fn no_resolver_outcome() -> DnsOutcome {
    DnsOutcome::Error {
        code: DnsErrorCode::Dependency,
        detail: Some("no resolver configured".to_string()),
    }
}

fn record_type_order(preference: DnsPreference) -> Vec<DnsRecordType> {
    match preference {
        DnsPreference::Ipv4Only => vec![DnsRecordType::A],
        DnsPreference::Ipv6Only => vec![DnsRecordType::Aaaa],
        DnsPreference::PreferIpv4 => vec![DnsRecordType::A, DnsRecordType::Aaaa],
        DnsPreference::PreferIpv6 => vec![DnsRecordType::Aaaa, DnsRecordType::A],
    }
}

fn preference_accepts(preference: DnsPreference, address: IpAddr) -> bool {
    match preference {
        DnsPreference::Ipv4Only => address.is_ipv4(),
        DnsPreference::Ipv6Only => address.is_ipv6(),
        DnsPreference::PreferIpv4 | DnsPreference::PreferIpv6 => true,
    }
}

fn elapsed_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn empty_dns_activity() -> DnsActivity {
    DnsActivity {
        lookups: 0,
        outcomes: DnsOutcomeCounts {
            cache_hits: 0,
            answered: 0,
            timeout: 0,
            error: 0,
            errors: Vec::new(),
        },
        latest_lookup: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};

    #[test]
    fn respond_to_query_returns_nodata_for_svcb() {
        let dns = Dns::with_config(
            "test",
            "unused",
            DnsPreference::PreferIpv4,
            &HashMap::new(),
            NameserverPolicies::empty(),
            Vec::new(),
        );
        let mut request = Message::new(0x1234, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("_dns.resolver.arpa.").unwrap(),
            RecordType::SVCB,
        ));

        let response = dns
            .respond_to_query(&request.to_vec().unwrap())
            .expect("SVCB queries should receive an empty DNS response");
        let response = Message::from_vec(&response).unwrap();

        assert_eq!(response.id, request.id);
        assert_eq!(response.message_type, MessageType::Response);
        assert_eq!(response.response_code, ResponseCode::NoError);
        assert_eq!(response.queries, request.queries);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn compatible_reload_reuses_record_and_removed_identity_does_not() {
        let config = || {
            NameServerConfigEnum::Normal(vec![NameServerConfig::new(
                "1.1.1.1".parse().unwrap(),
                true,
                vec![ConnectionConfig::udp()],
            )])
        };
        let dns = Dns::with_config(
            "test",
            "en0",
            DnsPreference::PreferIpv4,
            &HashMap::new(),
            NameserverPolicies::empty(),
            vec![config()],
        );
        let first = dns.runtime.load_full();
        let first_record = first.resolvers[0].record.clone();

        dns.replace_runtime(
            "en0",
            DnsPreference::PreferIpv6,
            &HashMap::new(),
            NameserverPolicies::empty(),
            vec![config()],
        );
        let second = dns.runtime.load_full();
        assert!(Arc::ptr_eq(&first_record, &second.resolvers[0].record));
        assert!(matches!(second.preference, DnsPreference::PreferIpv6));

        dns.replace_runtime(
            "en0",
            DnsPreference::PreferIpv4,
            &HashMap::new(),
            NameserverPolicies::empty(),
            Vec::new(),
        );
        dns.replace_runtime(
            "en0",
            DnsPreference::PreferIpv4,
            &HashMap::new(),
            NameserverPolicies::empty(),
            vec![config()],
        );
        let readded = dns.runtime.load_full();
        assert!(!Arc::ptr_eq(&first_record, &readded.resolvers[0].record));
    }

    #[test]
    fn prefix_resolution_reports_missing_and_ambiguous_ids() {
        // Seventeen identities guarantee that at least two SHA-256 IDs share
        // their first hexadecimal character.
        let configs = (1..=17)
            .map(|last_octet| {
                NameServerConfigEnum::Normal(vec![NameServerConfig::udp(IpAddr::from([
                    10, 0, 0, last_octet,
                ]))])
            })
            .collect();
        let dns = Dns::with_config(
            "test",
            "en0",
            DnsPreference::PreferIpv4,
            &HashMap::new(),
            NameserverPolicies::empty(),
            configs,
        );
        let runtime = dns.runtime.load_full();

        let missing = resolve_prefix(runtime.as_ref(), "not-an-id", false).unwrap_err();
        assert_eq!(missing.code, ApiErrorCode::ResolverNotFound);
        let mut seen = HashMap::new();
        let ambiguous_prefix = runtime
            .records
            .keys()
            .find_map(|id| {
                let prefix = &id[..1];
                seen.insert(prefix.to_string(), id.clone())
                    .map(|_| prefix.to_string())
            })
            .expect("pigeonhole principle guarantees a shared first digit");
        let ambiguous = resolve_prefix(runtime.as_ref(), &ambiguous_prefix, false).unwrap_err();
        assert_eq!(ambiguous.code, ApiErrorCode::ResolverIdAmbiguous);

        let id = runtime.resolvers[0].identity.id.clone();
        assert_eq!(
            resolve_prefix(runtime.as_ref(), &id[..12], false).unwrap(),
            id
        );
    }

    #[test]
    fn resolver_views_keep_scope_order_and_merge_shared_identity() {
        let repeated = || {
            NameServerConfigEnum::Normal(vec![NameServerConfig::udp("1.1.1.1".parse().unwrap())])
        };
        let dns = Dns::with_config(
            "test",
            "en0",
            DnsPreference::PreferIpv4,
            &HashMap::new(),
            NameserverPolicies::empty(),
            vec![repeated(), repeated()],
        );
        let runtime = dns.runtime.load_full();
        let views = resolver_views(runtime.as_ref());

        assert_eq!(views.len(), 1);
        assert_eq!(views[0].scopes.len(), 2);
        assert!(matches!(views[0].scopes[0], DnsScope::Global { order: 1 }));
        assert!(matches!(views[0].scopes[1], DnsScope::Global { order: 2 }));
    }

    #[test]
    fn facade_snapshots_use_supplied_time_and_preserve_counter_invariants() {
        let dns = Dns::with_config(
            "test",
            "en0",
            DnsPreference::PreferIpv4,
            &HashMap::new(),
            NameserverPolicies::empty(),
            vec![NameServerConfigEnum::Normal(vec![NameServerConfig::udp(
                "1.1.1.1".parse().unwrap(),
            )])],
        );
        let runtime = dns.runtime.load_full();
        let record = runtime.resolvers[0].record.clone();
        record.observe(
            Duration::from_millis(10),
            DnsOutcome::Answered {
                response: DnsResponseKind::Answer,
            },
        );
        record.observe(Duration::from_millis(20), DnsOutcome::Timeout);
        record.observe(
            Duration::from_millis(30),
            DnsOutcome::Error {
                code: DnsErrorCode::Servfail,
                detail: None,
            },
        );

        let observed_at_ms = 123_456;
        let snapshot = dns.resolver_snapshot_at(observed_at_ms);
        assert_eq!(snapshot.observed_at_ms, observed_at_ms);
        assert_eq!(snapshot.items.len(), 1);
        assert_eq!(snapshot.items[0].lookups, 3);
        let detail = dns
            .resolver_detail_at(&snapshot.items[0].id, observed_at_ms)
            .unwrap();
        assert_eq!(detail.observed_at_ms, observed_at_ms);
        assert_eq!(
            detail.summary.lookups,
            detail
                .outcomes
                .answered
                .saturating_add(detail.outcomes.timeout)
                .saturating_add(detail.outcomes.error)
        );
        assert!(detail.outcomes.cache_hits <= detail.outcomes.answered);
        assert_eq!(detail.latency.sample_count, 1);
        assert_eq!(detail.failure_episodes.len(), 1);

        assert_eq!(
            dns.fake_ip_mapping(IpAddr::from([198, 18, 0, 1]))
                .unwrap_err()
                .code,
            ApiErrorCode::DnsMappingNotFound
        );
    }

    #[test]
    fn held_runtime_remains_coherent_after_atomic_reload() {
        let old_hosts = HashMap::from([("old.example".to_string(), IpAddr::from([192, 0, 2, 1]))]);
        let dns = Dns::with_config(
            "test",
            "en0",
            DnsPreference::Ipv4Only,
            &old_hosts,
            NameserverPolicies::empty(),
            vec![NameServerConfigEnum::Normal(vec![NameServerConfig::udp(
                "1.1.1.1".parse().unwrap(),
            )])],
        );
        let held_by_in_flight_lookup = dns.runtime.load_full();
        let new_hosts = HashMap::from([("new.example".to_string(), IpAddr::from([192, 0, 2, 2]))]);

        dns.replace_runtime(
            "en1",
            DnsPreference::Ipv6Only,
            &new_hosts,
            NameserverPolicies::empty(),
            vec![NameServerConfigEnum::Normal(vec![NameServerConfig::udp(
                "8.8.8.8".parse().unwrap(),
            )])],
        );
        let current = dns.runtime.load_full();

        assert!(matches!(
            held_by_in_flight_lookup.preference,
            DnsPreference::Ipv4Only
        ));
        assert_eq!(
            held_by_in_flight_lookup.hosts.resolve("old.example"),
            Some(IpAddr::from([192, 0, 2, 1]))
        );
        assert_eq!(held_by_in_flight_lookup.resolvers.len(), 1);
        assert!(matches!(current.preference, DnsPreference::Ipv6Only));
        assert_eq!(current.hosts.resolve("old.example"), None);
        assert_eq!(
            current.hosts.resolve("new.example"),
            Some(IpAddr::from([192, 0, 2, 2]))
        );
    }

    #[tokio::test]
    async fn hosts_lookup_attaches_structured_connection_evidence() {
        use crate::dispatch::{ConnInfo, InboundInfo};
        use crate::platform::process::NetworkType;
        use crate::proxy::{ConnAbortHandle, ContextManager, NetworkAddr};

        let hosts = HashMap::from([("host.example".to_string(), IpAddr::from([192, 0, 2, 10]))]);
        let dns = Dns::with_config(
            "test",
            "en0",
            DnsPreference::PreferIpv4,
            &hosts,
            NameserverPolicies::empty(),
            Vec::new(),
        );
        let manager = ContextManager::new(1);
        let target = NetworkAddr::Domain {
            name: "host.example".to_string(),
            port: 443,
        };
        let conn = manager.begin(
            ConnInfo {
                src: "127.0.0.1:12345".parse().unwrap(),
                dst: target.clone(),
                local_ip: None,
                inbound: InboundInfo::Tun,
                resolved_dst: None,
                connection_type: NetworkType::Tcp,
                process_info: None,
            },
            target,
            None,
            ConnAbortHandle::placeholder(),
        );

        let address = dns
            .genuine_lookup_for("host.example", DnsLookupPurpose::Destination, Some(&conn))
            .await
            .unwrap();
        let activity = conn.snapshot().state.dns;

        assert_eq!(address, Some(IpAddr::from([192, 0, 2, 10])));
        assert_eq!(activity.total_lookups, 1);
        assert_eq!(activity.lookups.len(), 1);
        assert!(matches!(activity.lookups[0].selection, DnsSelection::Hosts));
        assert!(matches!(
            activity.lookups[0].cache,
            DnsCacheStatus::NotApplicable
        ));
        assert!(
            dns.resolver_snapshot_at(crate::network::dns::observability::now_ms())
                .items
                .is_empty()
        );
    }
}
