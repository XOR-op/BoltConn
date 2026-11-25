use super::*;
use crate::common::cert::CertVerify;
use crate::config::DnsPreference;
use crate::dispatch::{ConnInfo, InboundInfo};
use crate::platform::process::NetworkType;
use crate::proxy::{ConnAbortHandle, ContextManager};
use boltapi::ConnState;
use std::sync::Barrier;

fn anytls(password: &str) -> NamedLinkConfig {
    named_anytls("link", password)
}

fn named_anytls(name: &str, password: &str) -> NamedLinkConfig {
    NamedLinkConfig::new(
        LinkConfig::Anytls(AnytlsConfig::new(
            NetworkAddr::Domain {
                name: format!("{name}.example"),
                port: 443,
            },
            password,
            format!("{name}.example"),
            CertVerify::Verify,
        )),
        vec![ConfiguredLinkRoute {
            chain: "route".to_string(),
            hops: vec!["ordinary".to_string(), name.to_string()],
            interface: None,
        }],
    )
}

fn configs(config: NamedLinkConfig) -> HashMap<String, NamedLinkConfig> {
    HashMap::from([("link".to_string(), config)])
}

fn acquire(table: &LinkTable, config: &NamedLinkConfig) -> Result<LinkLease, LinkAcquireError> {
    acquire_named(table, "link", config, Vec::new())
}

fn acquire_named(
    table: &LinkTable,
    name: &str,
    config: &NamedLinkConfig,
    creation_route: Vec<LinkRouteSpec>,
) -> Result<LinkLease, LinkAcquireError> {
    let LinkConfig::Anytls(protocol) = &config.config else {
        panic!("test helper expects AnyTLS")
    };
    table.acquire(
        name,
        &LinkRuntimeConfig::new(protocol.clone(), config.routes.clone(), creation_route),
    )
}

fn ordinary(group: Option<&str>, name: &str, proxy_type: &str) -> LinkRouteSpec {
    LinkRouteSpec {
        group: group.map(str::to_string),
        proxy: name.to_string(),
        proxy_type: proxy_type.to_string(),
        link_kind: None,
    }
}

fn shared(name: &str) -> LinkRouteSpec {
    LinkRouteSpec {
        group: None,
        proxy: name.to_string(),
        proxy_type: "anytls".to_string(),
        link_kind: Some(LinkKind::Anytls),
    }
}

fn acquire_ready(
    table: &LinkTable,
    name: &str,
    config: &NamedLinkConfig,
    route: Vec<LinkRouteSpec>,
) -> Arc<LinkGeneration> {
    let generation = acquire_named(table, name, config, route.clone())
        .unwrap()
        .generation;
    table
        .publish_creation_route(name, generation.number(), &route)
        .unwrap();
    assert!(generation.set_live_state(LinkState::Ready, LinkHealth::Healthy));
    generation
}

fn begin_connection(manager: &ContextManager, port: u16) -> ConnHandle {
    let destination = NetworkAddr::from(SocketAddr::from(([192, 0, 2, 10], 443)));
    manager.begin(
        ConnInfo {
            src: SocketAddr::from(([127, 0, 0, 1], port)),
            dst: destination.clone(),
            local_ip: None,
            inbound: InboundInfo::Tun,
            resolved_dst: None,
            connection_type: NetworkType::Tcp,
            process_info: None,
        },
        destination,
        None,
        ConnAbortHandle::placeholder(),
    )
}

#[test]
fn configured_but_never_used_is_omitted() {
    let table = LinkTable::new(configs(anytls("secret")));
    assert!(table.snapshot(now_ms()).items.is_empty());
    assert_eq!(
        table.detail_result("link", now_ms()).unwrap_err().code,
        ApiErrorCode::LinkNotInitialized
    );
    assert_eq!(
        table.stop("link").unwrap_err().code,
        ApiErrorCode::LinkNotInitialized
    );
    assert_eq!(
        table.detail_result("missing", now_ms()).unwrap_err().code,
        ApiErrorCode::LinkNotFound
    );
}

#[test]
fn unchanged_config_preserves_generation() {
    let config = anytls("secret");
    let table = LinkTable::new(configs(config.clone()));
    let first = acquire(&table, &config).unwrap();
    assert!(first.created);

    assert!(table.reconcile(configs(config.clone())).is_empty());
    let second = acquire(&table, &config).unwrap();
    assert!(!second.created);
    assert!(Arc::ptr_eq(&first.generation, &second.generation));
}

#[test]
fn changed_config_closes_old_and_rejects_stale_acquisition() {
    let old = anytls("old-secret");
    let new = anytls("new-secret");
    let table = LinkTable::new(configs(old.clone()));
    let first = acquire(&table, &old).unwrap();

    let invalidations = table.reconcile(configs(new.clone()));
    assert_eq!(invalidations.len(), 1);
    assert_eq!(invalidations[0].reason, LinkReasonCode::ConfigChanged);
    assert_eq!(
        acquire(&table, &old).err(),
        Some(LinkAcquireError::StaleConfig)
    );
    let summary = &table.snapshot(now_ms()).items[0];
    assert_eq!(summary.state, LinkState::Closed);
    assert_eq!(
        summary.reason.as_ref().map(|reason| reason.code),
        Some(LinkReasonCode::ConfigChanged)
    );

    let replacement = acquire(&table, &new).unwrap();
    assert_eq!(
        replacement.generation.number(),
        first.generation.number() + 1
    );
}

#[test]
fn removed_and_readded_name_keeps_lineage() {
    let config = anytls("secret");
    let table = LinkTable::new(configs(config.clone()));
    let first = acquire(&table, &config).unwrap();

    let invalidations = table.reconcile(HashMap::new());
    assert_eq!(invalidations[0].reason, LinkReasonCode::ConfigRemoved);
    assert_eq!(
        acquire(&table, &config).err(),
        Some(LinkAcquireError::NotConfigured)
    );
    let removed = &table.snapshot(now_ms()).items[0];
    assert_eq!(
        removed.reason.as_ref().map(|reason| reason.code),
        Some(LinkReasonCode::ConfigRemoved)
    );

    assert!(table.reconcile(configs(config.clone())).is_empty());
    let replacement = acquire(&table, &config).unwrap();
    assert_eq!(
        replacement.generation.number(),
        first.generation.number() + 1
    );
}

#[test]
fn removed_never_used_name_stays_omitted_and_starts_at_one_after_readd() {
    let config = anytls("secret");
    let table = LinkTable::new(configs(config.clone()));
    assert!(table.reconcile(HashMap::new()).is_empty());
    assert!(table.snapshot(now_ms()).items.is_empty());

    assert!(table.reconcile(configs(config.clone())).is_empty());
    assert_eq!(acquire(&table, &config).unwrap().generation.number(), 1);
}

#[test]
fn delayed_old_generation_operation_cannot_affect_replacement() {
    let old = anytls("old-secret");
    let new = anytls("new-secret");
    let table = LinkTable::new(configs(old.clone()));
    let first = acquire(&table, &old).unwrap();
    table.reconcile(configs(new.clone()));
    let replacement = acquire(&table, &new).unwrap();

    assert!(!table.mark_terminal(
        "link",
        first.generation.number(),
        LinkState::Failed,
        LinkHealth::Unhealthy,
        LinkReason {
            code: LinkReasonCode::TaskStopped,
            detail: None,
        },
        ConnResultCode::LinkLost,
    ));
    let summary = &table.snapshot(now_ms()).items[0];
    assert_eq!(summary.generation, replacement.generation.number());
    assert_eq!(summary.state, LinkState::Initializing);
    assert!(summary.reason.is_none());
}

#[test]
fn racing_old_stop_cannot_close_reload_replacement() {
    let old = anytls("old-secret");
    let new = anytls("new-secret");
    let table = Arc::new(LinkTable::new(configs(old.clone())));
    let old_generation = acquire(&table, &old).unwrap().generation.number();
    let barrier = Arc::new(Barrier::new(3));

    std::thread::scope(|scope| {
        let reload_table = table.clone();
        let reload_barrier = barrier.clone();
        let reload_config = new.clone();
        scope.spawn(move || {
            reload_barrier.wait();
            reload_table.reconcile(configs(reload_config.clone()));
            acquire(&reload_table, &reload_config).unwrap();
        });

        let stop_table = table.clone();
        let stop_barrier = barrier.clone();
        scope.spawn(move || {
            stop_barrier.wait();
            let _ = stop_table.stop_generation("link", old_generation);
        });
        barrier.wait();
    });

    let summary = &table.snapshot(now_ms()).items[0];
    assert_eq!(summary.generation, old_generation + 1);
    assert_eq!(summary.state, LinkState::Initializing);
    assert!(summary.reason.is_none());
}

fn wireguard(private_key_byte: u8) -> WireguardConfig {
    let private_key = x25519_dalek::StaticSecret::from([private_key_byte; 32]);
    let peer_secret = x25519_dalek::StaticSecret::from([99; 32]);
    WireguardConfig {
        name: "wireguard".to_string(),
        ip_addr: Some("10.0.0.2".parse().unwrap()),
        ip_addr6: None,
        private_key,
        public_key: x25519_dalek::PublicKey::from(&peer_secret),
        endpoint: NetworkAddr::Domain {
            name: "wg.example".to_string(),
            port: 51820,
        },
        mtu: 1420,
        preshared_key: Some([7; 32]),
        keepalive: Some(25),
        dns: ResolverConfig::default(),
        dns_preference: DnsPreference::PreferIpv4,
        reserved: Some([1, 2, 3]),
        over_tcp: false,
    }
}

#[test]
fn wireguard_effective_comparison_includes_secrets_transport_and_dns() {
    let base = wireguard(1);
    assert!(
        !LinkConfig::Wireguard(base.clone())
            .same_effective_config(&LinkConfig::Wireguard(wireguard(2)))
    );

    let mut changed = base.clone();
    changed.over_tcp = true;
    assert!(
        !LinkConfig::Wireguard(base.clone()).same_effective_config(&LinkConfig::Wireguard(changed))
    );

    let mut changed = base.clone();
    changed
        .dns
        .name_servers
        .push(NameServerConfig::udp("1.1.1.1".parse().unwrap()));
    assert!(!LinkConfig::Wireguard(base).same_effective_config(&LinkConfig::Wireguard(changed)));
}

#[test]
fn ssh_effective_comparison_includes_authentication_and_key_policy() {
    let base = SshConfig {
        server: NetworkAddr::Domain {
            name: "ssh.example".to_string(),
            port: 22,
        },
        user: "operator".to_string(),
        auth: SshAuthentication::Password("first".to_string()),
        host_pubkey: None,
    };
    let mut changed = base.clone();
    changed.auth = SshAuthentication::Password("second".to_string());
    assert!(!LinkConfig::Ssh(base.clone()).same_effective_config(&LinkConfig::Ssh(changed)));

    let mut changed = base.clone();
    changed.host_pubkey = Some(Vec::new());
    assert!(!LinkConfig::Ssh(base).same_effective_config(&LinkConfig::Ssh(changed)));
}

#[test]
fn anytls_effective_comparison_includes_session_and_verification_settings() {
    let base = match anytls("secret").config {
        LinkConfig::Anytls(config) => config,
        _ => unreachable!(),
    };
    let mut changed = base.clone();
    changed.reuse_session = false;
    assert!(!LinkConfig::Anytls(base.clone()).same_effective_config(&LinkConfig::Anytls(changed)));

    let mut changed = base.clone();
    changed.cert_verify = CertVerify::SkipVerify;
    assert!(!LinkConfig::Anytls(base).same_effective_config(&LinkConfig::Anytls(changed)));
}

#[test]
fn route_change_is_an_effective_change() {
    let left = anytls("secret");
    let mut right = left.clone();
    right.routes[0].interface = Some("en1".to_string());
    assert!(!left.same_effective_config(&right));
}

#[tokio::test]
async fn initialization_is_coordinated_per_name_and_generation() {
    let initializing = LinkInitializationTable::default();
    assert!(matches!(
        initializing.begin("link", 1).await,
        InitializationDecision::Create
    ));
    let waiter = match initializing.begin("link", 1).await {
        InitializationDecision::Wait(waiter) => waiter,
        InitializationDecision::Create => panic!("same generation initialized twice"),
    };

    initializing.finish("link", 1).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        LinkInitializationTable::wait(waiter),
    )
    .await
    .expect("waiter was not released");
}

#[tokio::test]
async fn stale_initializer_cannot_finish_replacement_coordination() {
    let initializing = LinkInitializationTable::default();
    assert!(matches!(
        initializing.begin("link", 1).await,
        InitializationDecision::Create
    ));
    let old_waiter = match initializing.begin("link", 1).await {
        InitializationDecision::Wait(waiter) => waiter,
        InitializationDecision::Create => panic!("same generation initialized twice"),
    };
    assert!(matches!(
        initializing.begin("link", 2).await,
        InitializationDecision::Create
    ));

    // Starting generation 2 wakes generation 1, while a delayed generation
    // 1 completion must leave generation 2's coordination entry intact.
    LinkInitializationTable::wait(old_waiter).await;
    initializing.finish("link", 1).await;
    let replacement_waiter = match initializing.begin("link", 2).await {
        InitializationDecision::Wait(waiter) => waiter,
        InitializationDecision::Create => panic!("stale completion removed replacement"),
    };
    initializing.finish("link", 2).await;
    LinkInitializationTable::wait(replacement_waiter).await;
}

#[tokio::test]
async fn stale_lease_waits_for_replacement_initializer() {
    let initializing = LinkInitializationTable::default();
    assert!(matches!(
        initializing.begin("link", 2).await,
        InitializationDecision::Create
    ));

    // A caller that leased generation 1 before it ended must not take over.
    let stale_waiter = match initializing.begin("link", 1).await {
        InitializationDecision::Wait(waiter) => waiter,
        InitializationDecision::Create => panic!("stale lease evicted the replacement"),
    };
    let replacement_waiter = match initializing.begin("link", 2).await {
        InitializationDecision::Wait(waiter) => waiter,
        InitializationDecision::Create => panic!("replacement entry was lost"),
    };
    assert!(!*stale_waiter.borrow());
    assert!(!*replacement_waiter.borrow());

    initializing.finish("link", 2).await;
    for waiter in [stale_waiter, replacement_waiter] {
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            LinkInitializationTable::wait(waiter),
        )
        .await
        .expect("waiter was not released");
    }
}

#[test]
fn upstream_ended_follows_route_dependencies() {
    let upstream_config = named_anytls("upstream", "upstream-secret");
    let child_config = named_anytls("child", "child-secret");
    let table = LinkTable::new(HashMap::from([
        ("upstream".to_string(), upstream_config.clone()),
        ("child".to_string(), child_config.clone()),
    ]));
    let upstream = acquire_ready(
        &table,
        "upstream",
        &upstream_config,
        vec![shared("upstream")],
    );
    let child = acquire_ready(
        &table,
        "child",
        &child_config,
        vec![shared("upstream"), shared("child")],
    );
    assert!(!upstream.upstream_ended());
    assert!(!child.upstream_ended());

    table.mark_terminal(
        "upstream",
        upstream.number(),
        LinkState::Failed,
        LinkHealth::Unhealthy,
        LinkReason {
            code: LinkReasonCode::TaskStopped,
            detail: None,
        },
        ConnResultCode::LinkLost,
    );
    assert!(child.upstream_ended());
}

#[test]
fn terminal_generation_retains_endpoint_and_dns_activity() {
    let config = anytls("secret");
    let table = LinkTable::new(configs(config.clone()));
    let generation = acquire(&table, &config).unwrap().generation;
    generation.record_dns_lookup(DnsLookupDetail {
        purpose: boltapi::DnsLookupPurpose::LinkServer {
            link: "link".to_string(),
        },
        name: "link.example".to_string(),
        selection: boltapi::DnsSelection::Global,
        cache: DnsCacheStatus::Miss,
        attempts: Vec::new(),
        answers: Vec::new(),
        result: DnsOutcome::Error {
            code: boltapi::DnsErrorCode::Servfail,
            detail: Some("upstream failed".to_string()),
        },
        duration_ms: 12,
    });
    assert!(table.mark_terminal(
        "link",
        generation.number(),
        LinkState::Failed,
        LinkHealth::Unhealthy,
        LinkReason {
            code: LinkReasonCode::ProtocolFailed,
            detail: Some("session reader stopped".to_string()),
        },
        ConnResultCode::LinkLost,
    ));
    let endpoint = "192.0.2.10:443".parse().unwrap();
    generation.retain_final_snapshot(LinkHealth::Healthy, vec![endpoint]);

    let detail = table.detail_result("link", now_ms()).unwrap();
    assert_eq!(detail.summary.state, LinkState::Failed);
    // A runtime's final health cannot overwrite the terminal health/reason
    // selected by the lifecycle owner.
    assert_eq!(detail.summary.health, LinkHealth::Unhealthy);
    assert_eq!(detail.connected_endpoints, vec![endpoint]);
    assert_eq!(detail.dns.lookups, 1);
    assert_eq!(detail.dns.outcomes.error, 1);
}

#[tokio::test]
async fn dependent_link_waits_for_upstream_route() {
    let upstream_config = named_anytls("upstream", "upstream-secret");
    let child_config = named_anytls("child", "child-secret");
    let table = Arc::new(LinkTable::new(HashMap::from([
        ("upstream".to_string(), upstream_config.clone()),
        ("child".to_string(), child_config.clone()),
    ])));
    let child_route = vec![shared("upstream"), shared("child")];
    let child = acquire_named(&table, "child", &child_config, child_route.clone())
        .unwrap()
        .generation;

    // A chain creates both links at once; here the child is ready before its upstream exists.
    let waiting = tokio::spawn({
        let table = table.clone();
        async move {
            table
                .publish_creation_route_when_ready("child", child.number(), &child_route)
                .await
        }
    });
    tokio::task::yield_now().await;
    assert!(
        !waiting.is_finished(),
        "child did not wait for its upstream"
    );

    acquire_ready(
        &table,
        "upstream",
        &upstream_config,
        vec![shared("upstream")],
    );
    let published = waiting.await.unwrap().unwrap();
    let path: Vec<_> = published
        .dependency_path()
        .iter()
        .map(|generation| generation.name.clone())
        .collect();
    assert_eq!(path, ["upstream", "child"]);
}

#[test]
fn dependent_generation_reuses_upstream_route_and_freezes_connection_links() {
    let upstream_config = named_anytls("upstream", "upstream-secret");
    let child_config = named_anytls("child", "child-secret");
    let table = LinkTable::new(HashMap::from([
        ("upstream".to_string(), upstream_config.clone()),
        ("child".to_string(), child_config.clone()),
    ]));

    let upstream_route = vec![
        ordinary(Some("entry-group"), "entry", "socks5"),
        shared("upstream"),
    ];
    let upstream = acquire_ready(&table, "upstream", &upstream_config, upstream_route.clone());
    let child_route = vec![
        upstream_route[0].clone(),
        upstream_route[1].clone(),
        ordinary(None, "middle", "http"),
        shared("child"),
    ];
    let child = acquire_ready(&table, "child", &child_config, child_route);

    let detail = table.detail_result("child", now_ms()).unwrap();
    assert_eq!(
        detail
            .chain
            .iter()
            .map(|hop| (
                hop.group.as_deref(),
                hop.proxy.as_str(),
                hop.proxy_type.as_str()
            ))
            .collect::<Vec<_>>(),
        vec![
            (Some("entry-group"), "entry", "socks5"),
            (None, "upstream", "anytls"),
            (None, "middle", "http"),
            (None, "child", "anytls"),
        ]
    );
    let route_links: Vec<_> = detail
        .chain
        .iter()
        .filter_map(|hop| hop.link.as_ref())
        .map(|link| (link.name.as_str(), link.generation))
        .collect();
    assert_eq!(
        route_links,
        vec![("upstream", upstream.number()), ("child", child.number())]
    );

    let manager = ContextManager::new(10);
    let connection = begin_connection(&manager, 10_001);
    assert!(connection.consider_link_path(child.dependency_path()));
    assert_eq!(
        connection
            .snapshot()
            .state
            .links
            .iter()
            .map(|link| (link.name.as_str(), link.generation))
            .collect::<Vec<_>>(),
        vec![("upstream", upstream.number()), ("child", child.number())]
    );
    connection.more_upload(5);
    assert!(connection.set_state(ConnState::Active));
    for summary in table.snapshot(now_ms()).items {
        assert_eq!(summary.active_conn_count, 1);
        assert_eq!(summary.traffic.upload_bytes, 5);
    }
    assert!(connection.finish(ConnResultCode::Completed, None, None));
    for summary in table.snapshot(now_ms()).items {
        assert_eq!(summary.active_conn_count, 0);
        assert_eq!(summary.traffic.upload_bytes, 5);
    }
}

#[test]
fn active_traffic_is_folded_then_committed_once_and_survives_recreation() {
    let config = anytls("secret");
    let route = vec![ordinary(None, "entry", "direct"), shared("link")];
    let table = LinkTable::new(configs(config.clone()));
    let generation = acquire_ready(&table, "link", &config, route.clone());
    let manager = ContextManager::new(10);
    let connection = begin_connection(&manager, 10_001);
    assert!(connection.consider_link_path(generation.dependency_path()));

    connection.more_upload(11);
    connection.more_download(17);
    let preactive = table.snapshot(now_ms()).items.remove(0);
    assert_eq!(preactive.active_conn_count, 0);
    assert_eq!(
        (
            preactive.traffic.upload_bytes,
            preactive.traffic.download_bytes
        ),
        (0, 0)
    );

    assert!(connection.set_state(ConnState::Active));
    let active = table.snapshot(now_ms()).items.remove(0);
    assert_eq!(active.active_conn_count, 1);
    assert_eq!(
        (active.traffic.upload_bytes, active.traffic.download_bytes),
        (11, 17)
    );

    assert!(connection.finish(ConnResultCode::Completed, None, None));
    let completed = table.snapshot(now_ms()).items.remove(0);
    assert_eq!(completed.active_conn_count, 0);
    assert_eq!(
        (
            completed.traffic.upload_bytes,
            completed.traffic.download_bytes
        ),
        (11, 17)
    );
    assert!(!connection.finish(ConnResultCode::TransferError, None, None));
    let after_duplicate = table.snapshot(now_ms()).items.remove(0);
    assert_eq!(
        (
            after_duplicate.traffic.upload_bytes,
            after_duplicate.traffic.download_bytes,
        ),
        (11, 17)
    );

    table.stop("link").unwrap();
    assert_eq!(
        table.stop("link").unwrap_err().code,
        ApiErrorCode::LinkNotActive
    );
    let replacement = acquire_ready(&table, "link", &config, route);
    assert_eq!(replacement.number(), generation.number() + 1);
    let replacement_summary = table.snapshot(now_ms()).items.remove(0);
    assert_eq!(
        (
            replacement_summary.traffic.upload_bytes,
            replacement_summary.traffic.download_bytes,
        ),
        (0, 0)
    );
    assert_eq!(
        (
            replacement_summary.total_traffic.upload_bytes,
            replacement_summary.total_traffic.download_bytes,
        ),
        (11, 17)
    );
}

#[test]
fn failed_before_active_does_not_contribute_link_traffic() {
    let config = anytls("secret");
    let route = vec![shared("link")];
    let table = LinkTable::new(configs(config.clone()));
    let generation = acquire_ready(&table, "link", &config, route);
    let manager = ContextManager::new(10);
    let connection = begin_connection(&manager, 10_001);
    assert!(connection.consider_link_path(generation.dependency_path()));
    connection.more_upload(23);
    connection.more_download(29);
    assert!(connection.finish(
        ConnResultCode::ConnectError,
        Some(boltapi::ConnStage::Connecting),
        None,
    ));

    let summary = table.snapshot(now_ms()).items.remove(0);
    assert_eq!(summary.active_conn_count, 0);
    assert_eq!(
        (summary.traffic.upload_bytes, summary.traffic.download_bytes),
        (0, 0)
    );
    assert_eq!(
        (
            summary.total_traffic.upload_bytes,
            summary.total_traffic.download_bytes,
        ),
        (0, 0)
    );
}

#[test]
fn active_link_filter_uses_frozen_owned_dependencies() {
    let config = anytls("secret");
    let route = vec![shared("link")];
    let table = LinkTable::new(configs(config.clone()));
    let generation = acquire_ready(&table, "link", &config, route);
    let manager = ContextManager::new(10);
    let matching = begin_connection(&manager, 10_001);
    let unrelated = begin_connection(&manager, 10_002);
    let preactive = begin_connection(&manager, 10_003);

    assert!(matching.consider_link_path(generation.dependency_path()));
    assert!(matching.set_state(ConnState::Active));
    assert!(unrelated.set_state(ConnState::Active));
    assert!(preactive.consider_link_path(generation.dependency_path()));
    assert_eq!(
        manager
            .get_active_for_link("link")
            .iter()
            .map(ConnHandle::id)
            .collect::<Vec<_>>(),
        vec![matching.id()]
    );

    assert!(matching.finish(ConnResultCode::Completed, None, None));
    assert!(manager.get_active_for_link("link").is_empty());
}

#[derive(Clone, Copy)]
enum StopCause {
    User,
    Reconfigure,
    Remove,
    Lost,
}

#[test]
fn each_link_stop_cause_terminates_only_its_active_dependents() {
    let cases = [
        (
            StopCause::User,
            ConnResultCode::LinkStopped,
            LinkReasonCode::UserStopped,
        ),
        (
            StopCause::Reconfigure,
            ConnResultCode::LinkReconfigured,
            LinkReasonCode::ConfigChanged,
        ),
        (
            StopCause::Remove,
            ConnResultCode::LinkRemoved,
            LinkReasonCode::ConfigRemoved,
        ),
        (
            StopCause::Lost,
            ConnResultCode::LinkLost,
            LinkReasonCode::TaskStopped,
        ),
    ];

    for (index, (cause, expected_result, expected_reason)) in cases.into_iter().enumerate() {
        let config = anytls("secret");
        let table = LinkTable::new(configs(config.clone()));
        let generation = acquire_ready(&table, "link", &config, vec![shared("link")]);
        let manager = ContextManager::new(10);
        let dependent = begin_connection(&manager, 11_000 + index as u16);
        let unrelated = begin_connection(&manager, 12_000 + index as u16);
        assert!(dependent.consider_link_path(generation.dependency_path()));
        assert!(dependent.set_state(ConnState::Active));
        assert!(unrelated.set_state(ConnState::Active));

        match cause {
            StopCause::User => {
                table.stop("link").unwrap();
            }
            StopCause::Reconfigure => {
                table.reconcile(configs(anytls("changed-secret")));
            }
            StopCause::Remove => {
                table.reconcile(HashMap::new());
            }
            StopCause::Lost => {
                assert!(table.mark_terminal(
                    "link",
                    generation.number(),
                    LinkState::Failed,
                    LinkHealth::Unhealthy,
                    LinkReason {
                        code: LinkReasonCode::TaskStopped,
                        detail: None,
                    },
                    ConnResultCode::LinkLost,
                ));
            }
        }

        assert_eq!(
            dependent.snapshot().state.termination.unwrap().code,
            expected_result
        );
        assert!(!unrelated.done());
        assert_eq!(
            table
                .detail_result("link", now_ms())
                .unwrap()
                .summary
                .reason
                .unwrap()
                .code,
            expected_reason
        );
    }
}
