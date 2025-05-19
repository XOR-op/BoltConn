use crate::config::{
    default_inbound_ip_addr, safe_join_path, LinkedState, LoadedConfig, RawDnsConfig,
    RawInboundConfig, RawInboundServiceConfig, RawInstrumentConfig, RawRootCfg,
    RawWebControllerConfig, SingleOrVec,
};
use crate::dispatch::{DispatchingBuilder, RuleSet, RuleSetBuilder};
use crate::external::{
    Controller, DatabaseHandle, InstrumentServer, MmdbReader, SharedDispatching, StreamLoggerSend,
    UdsController, UnixListenerGuard, WebController,
};
use crate::instrument::bus::MessageBus;
use crate::intercept::{InterceptModifier, InterceptionManager};
use crate::network::configure::TunConfigure;
use crate::network::dns::{
    new_bootstrap_resolver, parse_dns_config, BootstrapResolver, Dns, DnsHijackController,
    NameserverPolicies,
};
use crate::network::tun_device::TunDevice;
use crate::platform::get_default_v4_route;
use crate::proxy::{
    ContextManager, Dispatcher, HttpCapturer, HttpInbound, MixedInbound, SessionManager,
    Socks5Inbound, TunTcpInbound, TunUdpInbound,
};
use crate::{external, platform};
use anyhow::anyhow;
use arc_swap::ArcSwap;
use bytes::Bytes;
use ipnet::Ipv4Net;
use rcgen::{Certificate, CertificateParams, KeyPair};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fs, io};
use tokio::select;

pub struct App {
    config_path: PathBuf,
    data_path: PathBuf,
    outbound_iface: String,
    dns: Arc<Dns>,
    dns_hijack_ctrl: Arc<DnsHijackController>,
    dispatcher: Arc<Dispatcher>,
    api_dispatching_handler: SharedDispatching,
    tun_configure: Arc<std::sync::Mutex<TunConfigure>>,
    http_capturer: Arc<HttpCapturer>,
    linked_state: Arc<std::sync::Mutex<LinkedState>>,
    speedtest_url: Arc<std::sync::RwLock<String>>,
    receiver: tokio::sync::mpsc::Receiver<()>,
    uds_socket: Arc<UnixListenerGuard>,
    msg_bus: Arc<MessageBus>,
}

impl App {
    /// Create a running App instance.
    pub async fn create(
        config_path: PathBuf,
        data_path: PathBuf,
        cert_path: PathBuf,
        enable_tun: Option<bool>,
        rootless_mode: bool,
    ) -> anyhow::Result<Self> {
        // tracing
        let stream_logger = StreamLoggerSend::new();
        external::init_tracing(&stream_logger)?;

        // setup Unix socket
        let uds_listener = Arc::new(UnixListenerGuard::new(&app_uds_addr(rootless_mode))?);

        // Read initial config
        let loaded_config = LoadedConfig::load_config(&config_path, &data_path)
            .await
            .map_err(|e| anyhow!("Load config from {:?} failed: {}", &config_path, e))?;
        let config = &loaded_config.config;
        let mmdb = load_mmdb(config.geoip_db.as_ref(), &config_path)?;

        let outbound_iface = detect_interface(config)?;

        let (ctx_manager, http_capturer) = {
            let conn_handle = if config.enable_dump {
                Some(open_database_handle(data_path.as_path())?)
            } else {
                None
            };
            let intercept_handle = conn_handle.clone();
            (
                Arc::new(ContextManager::new(
                    conn_handle,
                    loaded_config.state.log_limit.unwrap_or(50),
                )),
                Arc::new(HttpCapturer::new(intercept_handle)),
            )
        };

        // initialize resources
        let bootstrap =
            new_bootstrap_resolver(outbound_iface.as_str(), config.dns.bootstrap.as_slice());
        let dns = initialize_dns(bootstrap, &config.dns, outbound_iface.as_str()).await?;
        let manager = Arc::new(SessionManager::new());
        // initialize instrumentation
        let msg_bus = Arc::new(MessageBus::new());

        // dispatch
        let ruleset = load_rulesets(&loaded_config)?;
        let dispatching = Arc::new(
            DispatchingBuilder::new(
                config_path.as_path(),
                dns.clone(),
                mmdb.clone(),
                &loaded_config,
                &ruleset,
                msg_bus.clone(),
            )
            .and_then(|b| b.build(&loaded_config))
            .map_err(|e| anyhow!("Parse routing rules failed: {}", e))?,
        );
        let dispatcher = {
            // tls mitm
            let cert = load_cert_and_key(&cert_path)
                .map_err(|e| anyhow!("Load certs from path {:?} failed: {}", cert_path, e))?;
            let interception_mgr = Arc::new(
                InterceptionManager::new(
                    config_path.as_path(),
                    config.interception.as_slice(),
                    dns.clone(),
                    mmdb.clone(),
                    &ruleset,
                    msg_bus.clone(),
                )
                .map_err(|e| anyhow!("Load intercept rules failed: {}", e))?,
            );
            let hcap_copy = http_capturer.clone();
            Arc::new(Dispatcher::new(
                outbound_iface.as_str(),
                dns.clone(),
                config.sni_sniff,
                ctx_manager.clone(),
                dispatching.clone(),
                cert,
                Box::new(move |result, proc_info| {
                    Arc::new(InterceptModifier::new(hcap_copy.clone(), result, proc_info))
                }),
                interception_mgr,
            ))
        };

        // Create TUN
        let will_enable_tun = enable_tun.unwrap_or(config.inbound.enable_tun) && !rootless_mode;
        let (tun_udp_tx, tun_udp_rx) = flume::bounded(4096);
        let (udp_tun_tx, udp_tun_rx) = flume::bounded(4096);
        let fake_dns_server = Ipv4Addr::new(198, 18, 99, 88);
        let tun = if rootless_mode {
            None
        } else {
            let mut tun = TunDevice::open(
                manager.clone(),
                outbound_iface.as_str(),
                tun_udp_tx,
                udp_tun_rx,
                false, // TODO: load from configuration
                config.inbound.enable_icmp_proxy,
            )
            .map_err(|e| anyhow!("Fail to create TUN: {e}"))?;
            // create tun device
            tracing::info!("TUN Device {} opened.", tun.get_name());
            tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 1), 16).unwrap())
                .map_err(|e| anyhow!("TUN failed to set address: {e}"))?;
            tun.up().map_err(|e| anyhow!("TUN failed to up: {e}"))?;
            Some(tun)
        };
        assert!((tun.is_some() && !rootless_mode) || (tun.is_none() && rootless_mode));

        let tun_configure = {
            let tun_configure = Arc::new(std::sync::Mutex::new(TunConfigure::new(
                fake_dns_server,
                tun.as_ref()
                    .map(|t| t.get_name())
                    .unwrap_or("placeholder device name for rootless mode"),
                &outbound_iface,
                rootless_mode,
            )));
            if will_enable_tun && !rootless_mode {
                // tokio::time::sleep(Duration::from_secs(5)).await;
                tun_configure
                    .lock()
                    .unwrap()
                    .enable()
                    .map_err(|e| anyhow!("Failed to enable global setting: {e}"))?;
            }
            tun_configure
        };
        let dns_hijack = Arc::new(DnsHijackController::new(
            config.dns.tun_bypass_list.clone(),
            config.dns.tun_hijack_list.clone(),
            SocketAddr::new(fake_dns_server.into(), 53),
        ));

        // create controller
        let api_dispatching_handler = Arc::new(ArcSwap::new(dispatching));
        let (reload_sender, reload_receiver) = tokio::sync::mpsc::channel::<()>(1);
        let speedtest_url = Arc::new(std::sync::RwLock::new(config.speedtest_url.clone()));
        let linked_state = Arc::new(std::sync::Mutex::new(LinkedState {
            state_path: LoadedConfig::state_path(&data_path),
            state: loaded_config.state,
        }));
        let controller = Arc::new(Controller::new(
            manager.clone(),
            dns.clone(),
            ctx_manager,
            Some(http_capturer.clone()),
            dispatcher.clone(),
            api_dispatching_handler.clone(),
            tun_configure.clone(),
            reload_sender,
            linked_state.clone(),
            stream_logger,
            speedtest_url.clone(),
        ));

        // start tun & L7 inbound services
        if !rootless_mode {
            assert!(tun.is_some());
            let nat_addr = SocketAddr::new(
                platform::get_iface_address(tun.as_ref().unwrap().get_name())
                    .map_err(|e| anyhow!("Failed to get tun address: {e}"))?,
                9961,
            );
            start_tun_services(
                nat_addr,
                manager.clone(),
                dispatcher.clone(),
                dns.clone(),
                tun.unwrap(),
                tun_udp_rx,
                udp_tun_tx,
                dns_hijack.clone(),
            )
            .await?;
        }
        start_inbound_services(&config.inbound, dispatcher.clone());

        // start controller service
        start_controller_services(
            config.web_controller.as_ref(),
            controller,
            uds_listener.clone(),
        );

        start_instrument_services(msg_bus.clone(), config.instrument.as_ref());

        Ok(Self {
            config_path,
            data_path,
            outbound_iface,
            dns,
            dns_hijack_ctrl: dns_hijack,
            dispatcher,
            api_dispatching_handler,
            tun_configure,
            http_capturer,
            linked_state,
            speedtest_url,
            receiver: reload_receiver,
            uds_socket: uds_listener,
            msg_bus,
        })
    }

    /// Serve Ctrl-C and reload command from API server.
    pub async fn serve_command(mut self) {
        let tun_configure = self.tun_configure.clone();
        'outer: loop {
            select! {
                _ = tokio::signal::ctrl_c()=>break 'outer,
                restart = self.receiver.recv() => {
                    if restart.is_some(){
                        // try restarting components
                       self.reload().await;
                    } else {
                        break 'outer;
                    }
                }
            }
        }
        tun_configure.lock().unwrap().disable(false);
    }

    async fn reload(&self) {
        let start = Instant::now();
        match self.reload_inner().await {
            Ok(_) => {
                tracing::info!(
                    "Reloaded config successfully in {}ms",
                    start.elapsed().as_millis()
                );
            }
            Err(err) => {
                tracing::error!("Reloading config failed: {}", err);
            }
        }
    }

    async fn reload_inner(&self) -> anyhow::Result<()> {
        // reload parsing
        let loaded_config = LoadedConfig::load_config(&self.config_path, &self.data_path).await?;
        let config = &loaded_config.config;
        let mmdb = load_mmdb(config.geoip_db.as_ref(), &self.config_path)?;
        let ruleset = load_rulesets(&loaded_config)?;

        let bootstrap =
            new_bootstrap_resolver(&self.outbound_iface, config.dns.bootstrap.as_slice());
        let group = parse_dns_config(config.dns.nameserver.iter(), &bootstrap).await?;
        let ns_policy = NameserverPolicies::new(
            &config.dns.nameserver_policy,
            &bootstrap,
            self.outbound_iface.as_str(),
        )
        .await?;
        let dispatching = {
            let builder = DispatchingBuilder::new(
                self.config_path.as_path(),
                self.dns.clone(),
                mmdb.clone(),
                &loaded_config,
                &ruleset,
                self.msg_bus.clone(),
            )?;
            Arc::new(builder.build(&loaded_config)?)
        };

        let interception_mgr = Arc::new(
            InterceptionManager::new(
                self.config_path.as_path(),
                config.interception.as_slice(),
                self.dns.clone(),
                mmdb.clone(),
                &ruleset,
                self.msg_bus.clone(),
            )
            .map_err(|e| anyhow!("Load intercept rules failed: {}", e))?,
        );

        // start atomic replacing
        self.dns.replace_resolvers(&self.outbound_iface, group);
        self.dns.replace_ns_policy(ns_policy);
        self.dns.replace_hosts(&config.dns.hosts);
        self.dns_hijack_ctrl.update(
            config.dns.tun_hijack_list.clone(),
            config.dns.tun_bypass_list.clone(),
            SocketAddr::new(Ipv4Addr::new(198, 18, 99, 88).into(), 53),
        );

        self.linked_state.lock().unwrap().state = loaded_config.state;

        self.api_dispatching_handler.store(dispatching.clone());
        let hcap2 = self.http_capturer.clone();
        self.dispatcher.replace_dispatching(dispatching);
        self.dispatcher.replace_intercept_filter(interception_mgr);
        self.dispatcher
            .replace_modifier(Box::new(move |result, proc_info| {
                Arc::new(InterceptModifier::new(hcap2.clone(), result, proc_info))
            }));
        self.dispatcher.set_sniff_flag(config.sni_sniff);
        self.speedtest_url
            .write()
            .unwrap()
            .clone_from(&config.speedtest_url);
        Ok(())
    }
}

pub async fn validate_config(
    config_path: &Path,
    data_path: &Path,
    cert_path: &Path,
) -> anyhow::Result<()> {
    // Read initial config
    let loaded_config = LoadedConfig::load_config(config_path, data_path)
        .await
        .map_err(|e| anyhow!("Load config from {:?} failed: {}", config_path, e))?;
    let config = &loaded_config.config;
    let mmdb = load_mmdb(config.geoip_db.as_ref(), config_path)?;
    let outbound_iface = detect_interface(config)?;
    // initialize resources
    let _bootstrap =
        new_bootstrap_resolver(outbound_iface.as_str(), config.dns.bootstrap.as_slice());
    let dns = initialize_dns(
        BootstrapResolver::mocked(),
        &config.dns,
        outbound_iface.as_str(),
    )
    .await?;
    let msg_bus = Arc::new(MessageBus::new());
    let _cert = load_cert_and_key(cert_path)
        .map_err(|e| anyhow!("Load certs from path {:?} failed: {}", cert_path, e))?;
    // dispatch
    let ruleset = load_rulesets(&loaded_config)?;
    let _dispatching = DispatchingBuilder::new(
        config_path,
        dns.clone(),
        mmdb.clone(),
        &loaded_config,
        &ruleset,
        msg_bus.clone(),
    )
    .and_then(|b| b.build(&loaded_config))
    .map_err(|e| anyhow!("Parse routing rules failed: {}", e))?;
    let _interception_mgr = InterceptionManager::new(
        config_path,
        config.interception.as_slice(),
        dns,
        mmdb,
        &ruleset,
        msg_bus,
    )
    .map_err(|e| anyhow!("Load intercept rules failed: {}", e))?;
    Ok(())
}

fn load_mmdb(db_path: Option<&String>, cfg_path: &Path) -> anyhow::Result<Option<Arc<MmdbReader>>> {
    Ok(match db_path {
        None => None,
        Some(p) => {
            let path = safe_join_path(cfg_path, p)?;
            Some(Arc::new(MmdbReader::read_from_file(path)?))
        }
    })
}

fn detect_interface(config: &RawRootCfg) -> anyhow::Result<String> {
    Ok(if config.interface != "auto" {
        tracing::info!("Use pre-configured interface: {}", config.interface);
        config.interface.clone()
    } else {
        let (_, real_iface_name) =
            get_default_v4_route().map_err(|e| anyhow!("Failed to get default route: {}", e))?;
        tracing::info!("Auto detected interface: {}", real_iface_name);
        real_iface_name
    })
}

async fn initialize_dns(
    bootstrap: BootstrapResolver,
    config: &RawDnsConfig,
    outbound_iface: &str,
) -> anyhow::Result<Arc<Dns>> {
    Ok({
        let group = match parse_dns_config(config.nameserver.iter(), &bootstrap).await {
            Ok(g) => {
                if g.is_empty() {
                    return Err(anyhow!("No DNS specified"));
                }
                g
            }
            Err(e) => return Err(anyhow!("Parse dns config failed: {e}")),
        };
        let ns_policy =
            NameserverPolicies::new(&config.nameserver_policy, &bootstrap, outbound_iface)
                .await
                .map_err(|e| anyhow!("Parse nameserver policy failed: {e}"))?;
        Arc::new(Dns::with_config(
            "default",
            outbound_iface,
            config.preference,
            &config.hosts,
            ns_policy,
            group,
        ))
    })
}

fn start_instrument_services(bus: Arc<MessageBus>, config: Option<&RawInstrumentConfig>) {
    if let Some(config) = config {
        let web_server = InstrumentServer::new(config.secret.clone(), bus.clone());
        let addr = config.api_addr.as_socket_addr(default_inbound_ip_addr);
        let cors_allowed_list = config.cors_allowed_list.clone();
        tokio::spawn(async move { web_server.run(addr, cors_allowed_list.as_slice()).await });
    }
    tokio::spawn(async move { bus.run().await });
}

#[allow(clippy::too_many_arguments)]
async fn start_tun_services(
    nat_addr: SocketAddr,
    manager: Arc<SessionManager>,
    dispatcher: Arc<Dispatcher>,
    dns: Arc<Dns>,
    tun: TunDevice,
    tun_udp_rx: flume::Receiver<Bytes>,
    udp_tun_tx: flume::Sender<Bytes>,
    hijack_ctrl: Arc<DnsHijackController>,
) -> io::Result<()> {
    let tun_inbound_tcp = Arc::new(TunTcpInbound::new(
        nat_addr,
        manager.clone(),
        dispatcher.clone(),
        dns.clone(),
    ));
    let tun_inbound_udp = TunUdpInbound::new(
        tun_udp_rx,
        udp_tun_tx,
        dispatcher.clone(),
        manager.clone(),
        dns.clone(),
        hijack_ctrl,
    );
    manager.flush_with_interval(Duration::from_secs(30));
    #[cfg(unix)]
    let tcp_listener = tokio::net::TcpListener::bind(tun_inbound_tcp.nat_addr())
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to start NAT at {}: {}",
                tun_inbound_tcp.nat_addr(),
                e
            );
            e
        })?;
    #[cfg(windows)]
    let tcp_listener = {
        let start_time = Instant::now();
        tracing::info!(
            "Starting NAT at {}, requires a few seconds...",
            tun_inbound_tcp.nat_addr()
        );
        loop {
            match tokio::net::TcpListener::bind(tun_inbound_tcp.nat_addr()).await {
                Ok(l) => break l,
                Err(e) => {
                    if e.raw_os_error() == Some(10049) && start_time.elapsed().as_secs() < 15 {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    } else {
                        tracing::error!(
                            "Failed to start NAT at {}: {}",
                            tun_inbound_tcp.nat_addr(),
                            e
                        );
                        return Err(e);
                    }
                }
            }
        }
    };
    tokio::spawn(async move { tun_inbound_tcp.run(tcp_listener).await });
    tokio::spawn(async move { tun_inbound_udp.run().await });
    tokio::spawn(async move { tun.run(nat_addr).await });
    Ok(())
}

fn start_inbound_services(config: &RawInboundConfig, dispatcher: Arc<Dispatcher>) {
    for (sock_addr, http_auth, socks_auth) in
        parse_two_inbound_service(&config.http, &config.socks5)
    {
        let dispatcher = dispatcher.clone();
        match (http_auth, socks_auth) {
            (Some(http_auth), Some(socks_auth)) => {
                tokio::spawn(async move {
                    MixedInbound::new(sock_addr, http_auth, socks_auth, dispatcher)
                        .await?
                        .run()
                        .await;
                    Ok::<(), io::Error>(())
                });
            }
            (Some(auth), None) => {
                tokio::spawn(async move {
                    HttpInbound::new(sock_addr, auth, dispatcher)
                        .await?
                        .run()
                        .await;
                    Ok::<(), io::Error>(())
                });
            }
            (None, Some(auth)) => {
                tokio::spawn(async move {
                    Socks5Inbound::new(sock_addr, auth, dispatcher)
                        .await?
                        .run()
                        .await;
                    Ok::<(), io::Error>(())
                });
            }
            _ => unreachable!(),
        }
    }
}

fn start_controller_services(
    config: Option<&RawWebControllerConfig>,
    controller: Arc<Controller>,
    uds_listener: Arc<UnixListenerGuard>,
) {
    let uds_controller = UdsController::new(controller.clone());
    let uds_listener2 = uds_listener.clone();
    tokio::spawn(async move { uds_controller.run(uds_listener2).await });

    if let Some(web_cfg) = config {
        let api_addr = web_cfg.api_addr.as_socket_addr(default_inbound_ip_addr);
        let api_server = WebController::new(web_cfg.api_key.clone(), controller);
        let cors_domains = web_cfg.cors_allowed_list.clone();
        tokio::spawn(async move { api_server.run(api_addr, cors_domains.as_slice()).await });
    }
}

fn load_rulesets(loaded_config: &LoadedConfig) -> anyhow::Result<HashMap<String, Arc<RuleSet>>> {
    let mut ruleset = HashMap::new();
    for (name, schema) in &loaded_config.rule_schema {
        let Some(builder) = RuleSetBuilder::new(name.as_str(), schema) else {
            return Err(anyhow!("Filter: failed to parse provider {}", name));
        };
        ruleset.insert(name.clone(), Arc::new(builder.build()?));
    }
    Ok(ruleset)
}

fn load_cert_and_key(cert_path: &Path) -> anyhow::Result<Certificate> {
    let cert_str = fs::read_to_string(cert_path.join("crt.pem"))?;
    let key_str = fs::read_to_string(cert_path.join("key.pem"))?;
    let key_pair = KeyPair::from_pem(key_str.as_str())?;
    let params = CertificateParams::from_ca_cert_pem(cert_str.as_str(), key_pair)?;
    let cert = Certificate::from_params(params)?;
    Ok(cert)
}

fn open_database_handle(data_path: &Path) -> anyhow::Result<DatabaseHandle> {
    let path = data_path.join("data.sqlite");
    match DatabaseHandle::open(path) {
        Ok(h) => Ok(h),
        Err(e) => Err(anyhow!(
            "Open data.sqlite from {:?} failed: {}",
            data_path,
            e
        )),
    }
}

#[allow(clippy::type_complexity)]
fn parse_two_inbound_service(
    http: &Option<SingleOrVec<RawInboundServiceConfig>>,
    socks5: &Option<SingleOrVec<RawInboundServiceConfig>>,
) -> Vec<(
    SocketAddr,
    Option<HashMap<String, String>>,
    Option<HashMap<String, String>>,
)> {
    fn parse_inbound_service(
        config: &Option<SingleOrVec<RawInboundServiceConfig>>,
    ) -> HashMap<SocketAddr, HashMap<String, String>> {
        config
            .as_ref()
            .map(|v| {
                v.clone()
                    .linearize()
                    .into_iter()
                    .map(|c| match c {
                        RawInboundServiceConfig::Simple(e) => (
                            e.as_socket_addr(default_inbound_ip_addr),
                            HashMap::default(),
                        ),
                        RawInboundServiceConfig::Complex { host, port, auth } => {
                            (SocketAddr::new(host, port), auth)
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
    let http_map = parse_inbound_service(http);
    let mut socks5_map = parse_inbound_service(socks5);

    let mut result = vec![];
    http_map.into_iter().for_each(|(port, http_auth)| {
        result.push((port, Some(http_auth), socks5_map.remove(&port)))
    });
    socks5_map
        .into_iter()
        .for_each(|(port, socks5_auth)| result.push((port, None, Some(socks5_auth))));
    result
}

pub(crate) fn app_uds_addr(rootless_mode: bool) -> String {
    #[cfg(target_os = "windows")]
    {
        r"\\.\pipe\boltconn"
    }
    #[cfg(not(target_os = "windows"))]
    {
        if rootless_mode {
            let runtime_dir_env = if cfg!(target_os = "macos") {
                "TMPDIR"
            } else {
                "XDG_RUNTIME_DIR"
            };
            if let Ok(dir) = std::env::var(runtime_dir_env) {
                let mut path = PathBuf::from(dir);
                path.push("boltconn.sock");
                path.to_string_lossy().to_string()
            } else {
                String::from("/tmp/boltconn.sock")
            }
        } else {
            String::from("/var/run/boltconn.sock")
        }
    }
}
