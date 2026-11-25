use super::*;
use crate::adapter::{ConfiguredLinkRoute, LinkConfig, LinkRouteSpec, NamedLinkConfig};
use crate::config::DnsPreference;
use crate::network::dns::NameserverPolicies;
use boltapi::LinkKind;
use hickory_resolver::config::ResolverConfig;
use tokio::net::UdpSocket;

const LINK: &str = "wg";
const UPSTREAM: &str = "outer";

fn spec(name: &str) -> LinkRouteSpec {
    LinkRouteSpec {
        group: None,
        proxy: name.to_string(),
        proxy_type: "wireguard".to_string(),
        link_kind: Some(LinkKind::Wireguard),
    }
}

/// Configures `LINK` and `UPSTREAM` and returns `LINK`'s request through `creation_route`.
fn link_table(
    config: &WireguardConfig,
    creation_route: Vec<LinkRouteSpec>,
) -> (Arc<LinkTable>, LinkRuntimeConfig<WireguardConfig>) {
    let routes = vec![ConfiguredLinkRoute {
        chain: "route".to_string(),
        hops: vec![UPSTREAM.to_string(), LINK.to_string()],
        interface: None,
    }];
    let named = NamedLinkConfig::new(LinkConfig::Wireguard(config.clone()), routes.clone());
    let table = Arc::new(LinkTable::new(HashMap::from([
        (LINK.to_string(), named.clone()),
        (UPSTREAM.to_string(), named),
    ])));
    (
        table,
        LinkRuntimeConfig::new(config.clone(), routes, creation_route),
    )
}

fn manager(table: Arc<LinkTable>) -> Arc<WireguardManager> {
    let dns = Arc::new(Dns::with_config(
        "test",
        "unused",
        DnsPreference::PreferIpv4,
        &HashMap::new(),
        NameserverPolicies::empty(),
        Vec::new(),
    ));
    Arc::new(WireguardManager::new_with_link_table(
        "unused",
        dns,
        Duration::from_secs(180),
        table,
    ))
}

async fn socket_to(peer: SocketAddr) -> AdapterOrSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(peer).await.unwrap();
    AdapterOrSocket::Socket(socket)
}

/// Returns the runtime and whether this call created it.
async fn connect(
    manager: &WireguardManager,
    requested: &LinkRuntimeConfig<WireguardConfig>,
    outbound: AdapterOrSocket,
) -> (ManagedRuntime<Endpoint>, bool) {
    let (created_tx, created_rx) = tokio::sync::oneshot::channel();
    let runtime = manager
        .get_wg_conn(LINK, requested, Some(outbound), created_tx)
        .await
        .unwrap();
    (runtime, created_rx.await.unwrap())
}

async fn publish_upstream(
    table: &LinkTable,
    requested: &LinkRuntimeConfig<WireguardConfig>,
) -> Arc<crate::adapter::LinkGeneration> {
    let generation = table.acquire(UPSTREAM, requested).unwrap().generation;
    table
        .publish_creation_route(UPSTREAM, generation.number(), &[spec(UPSTREAM)])
        .unwrap();
    generation.set_live_state(LinkState::Ready, LinkHealth::Healthy);
    generation
}

// A current-thread runtime runs the spawned caller only when the test yields, which pins
// the interleaving that reconnect bursts hit by chance.
#[tokio::test]
async fn stale_lease_reuses_the_published_replacement() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let config = config(peer_addr);
    let (table, requested) = link_table(&config, vec![spec(LINK)]);
    let manager = manager(table.clone());
    let (first, created) = connect(&manager, &requested, socket_to(peer_addr).await).await;
    assert!(created);
    assert_eq!(first.generation, 1);
    // The endpoint dies, e.g. because its upstream tunnel failed.
    first.runtime.abort_connection();

    // A reconnecting caller leases generation 1 and then stalls before reading the map.
    let map = manager.active_conn.write().await;
    let stale_outbound = socket_to(peer_addr).await;
    let stale = tokio::spawn({
        let manager = manager.clone();
        let requested = requested.clone();
        async move { connect(&manager, &requested, stale_outbound).await }
    });
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }

    // Meanwhile another caller retires generation 1 and publishes its replacement.
    let mut map = map;
    map.remove(LINK);
    drop(first);
    table.mark_terminal(
        LINK,
        1,
        LinkState::Failed,
        LinkHealth::Unhealthy,
        LinkReason {
            code: LinkReasonCode::TaskStopped,
            detail: None,
        },
        ConnResultCode::LinkLost,
    );
    let lease = table.acquire(LINK, &requested).unwrap();
    let AdapterOrSocket::Socket(socket) = socket_to(peer_addr).await else {
        unreachable!()
    };
    let replacement = Endpoint::new(
        LINK,
        AdapterOrSocket::Socket(socket),
        &config,
        peer_addr,
        Duration::from_secs(180),
    )
    .await
    .unwrap();
    map.insert(
        LINK.to_string(),
        ManagedRuntime {
            generation: lease.generation.number(),
            record: lease.generation.clone(),
            runtime: replacement.clone(),
        },
    );
    drop(map);

    let (reused, created) = stale.await.unwrap();
    assert!(!created, "a stale lease started another tunnel");
    assert!(Arc::ptr_eq(&reused.runtime, &replacement));
    assert!(
        replacement.is_active.alive(),
        "a stale lease retired the healthy replacement"
    );
}

#[tokio::test]
async fn endpoint_whose_upstream_ended_is_replaced() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let (table, requested) = link_table(&config(peer_addr), vec![spec(UPSTREAM), spec(LINK)]);
    let manager = manager(table.clone());
    let upstream = publish_upstream(&table, &requested).await;
    let (first, created) = connect(&manager, &requested, socket_to(peer_addr).await).await;
    assert!(created);

    // The upstream generation this endpoint's route went through ends and is replaced.
    table.mark_terminal(
        UPSTREAM,
        upstream.number(),
        LinkState::Failed,
        LinkHealth::Unhealthy,
        LinkReason {
            code: LinkReasonCode::TaskStopped,
            detail: None,
        },
        ConnResultCode::LinkLost,
    );
    publish_upstream(&table, &requested).await;

    let (second, created) = connect(&manager, &requested, socket_to(peer_addr).await).await;
    assert!(
        created,
        "connections were handed an endpoint on an ended upstream"
    );
    assert!(second.generation > first.generation);
    assert!(!first.runtime.is_active.alive());
    assert!(!second.record.upstream_ended());
}

#[tokio::test]
async fn dropping_the_last_reference_stops_the_endpoint() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let endpoint = Endpoint::new(
        "wireguard",
        socket_to(peer_addr).await,
        &config(peer_addr),
        peer_addr,
        Duration::from_secs(180),
    )
    .await
    .unwrap();
    let stack = Arc::downgrade(&endpoint.stack);
    let canary = endpoint.is_active.clone();

    drop(endpoint);

    tokio::time::timeout(Duration::from_secs(5), async {
        while stack.strong_count() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("an unreferenced endpoint kept running");
    assert!(!canary.alive());
}

fn config(peer: SocketAddr) -> WireguardConfig {
    let peer_secret = x25519_dalek::StaticSecret::from([2; 32]);
    WireguardConfig {
        name: "wireguard".to_string(),
        ip_addr: Some("10.0.0.2".parse().unwrap()),
        ip_addr6: None,
        private_key: x25519_dalek::StaticSecret::from([1; 32]),
        public_key: x25519_dalek::PublicKey::from(&peer_secret),
        endpoint: NetworkAddr::Socket { address: peer },
        mtu: 1420,
        preshared_key: None,
        keepalive: None,
        dns: ResolverConfig::default(),
        dns_preference: DnsPreference::PreferIpv4,
        reserved: None,
        over_tcp: false,
    }
}

#[tokio::test]
async fn aborted_endpoint_stops_stack_driver_before_any_traffic() {
    // The peer never answers, so the stack driver receives no packet wakeups.
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(peer_addr).await.unwrap();
    let endpoint = Endpoint::new(
        "wireguard",
        AdapterOrSocket::Socket(socket),
        &config(peer_addr),
        peer_addr,
        Duration::from_secs(180),
    )
    .await
    .unwrap();
    let stack = Arc::downgrade(&endpoint.stack);

    endpoint.abort_connection();
    drop(endpoint);

    tokio::time::timeout(Duration::from_secs(5), async {
        while stack.strong_count() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("stack driver thread kept the aborted endpoint alive");
}
