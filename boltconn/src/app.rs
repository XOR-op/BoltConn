use crate::config::{safe_join_path, LinkedState, LoadedConfig, RawInboundServiceConfig};
use crate::dispatch::{Dispatching, DispatchingBuilder};
use crate::external::{
    Controller, DatabaseHandle, MmdbReader, SharedDispatching, StreamLoggerSend, UdsController,
    UnixListenerGuard, WebController,
};
use crate::intercept::{HeaderModManager, InterceptModifier, UrlModManager};
use crate::network::configure::TunConfigure;
use crate::network::dns::{new_bootstrap_resolver, parse_dns_config, Dns};
use crate::network::tun_device::TunDevice;
use crate::platform::get_default_route;
use crate::proxy::{
    ContextManager, Dispatcher, HttpCapturer, HttpInbound, MixedInbound, SessionManager,
    Socks5Inbound, TunTcpInbound, TunUdpInbound,
};
use crate::{external, platform};
use anyhow::anyhow;
use arc_swap::ArcSwap;
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
    dispatcher: Arc<Dispatcher>,
    api_dispatching_handler: SharedDispatching,
    tun_configure: Arc<std::sync::Mutex<TunConfigure>>,
    http_capturer: Arc<HttpCapturer>,
    speedtest_url: Arc<std::sync::RwLock<String>>,
    receiver: tokio::sync::mpsc::Receiver<()>,
    uds_socket: Arc<UnixListenerGuard>,
}

impl App {
    /// Create a running App instance.
    pub async fn create(
        config_path: PathBuf,
        data_path: PathBuf,
        cert_path: PathBuf,
    ) -> anyhow::Result<Self> {
        // tracing
        let stream_logger = StreamLoggerSend::new();
        external::init_tracing(&stream_logger);

        // interface
        let (_, real_iface_name) =
            get_default_route().map_err(|e| anyhow!("Failed to get default route: {}", e))?;
        let fake_dns_server = "198.18.99.88".parse().unwrap();

        // setup Unix socket
        let uds_listener = Arc::new(UnixListenerGuard::new("/var/run/boltconn.sock")?);

        // Read initial config
        let loaded_config = LoadedConfig::load_config(&config_path, &data_path)
            .await
            .map_err(|e| anyhow!("Load config from {:?} failed: {}", &config_path, e))?;
        let config = &loaded_config.config;
        let mmdb = match config.geoip_db.as_ref() {
            None => None,
            Some(p) => {
                let path = safe_join_path(&config_path, p)?;
                Some(Arc::new(MmdbReader::read_from_file(path)?))
            }
        };

        let outbound_iface = if config.interface != "auto" {
            config.interface.clone()
        } else {
            tracing::info!("Auto detected interface: {}", real_iface_name);
            real_iface_name
        };

        let manager = Arc::new(SessionManager::new());
        let (stat_center, http_capturer) = {
            let conn_handle = if config.enable_dump {
                Some(open_database_handle(data_path.as_path())?)
            } else {
                None
            };
            let intercept_handle = conn_handle.clone();
            (
                Arc::new(ContextManager::new(conn_handle)),
                Arc::new(HttpCapturer::new(intercept_handle)),
            )
        };

        // initialize resources
        let dns = {
            let bootstrap =
                new_bootstrap_resolver(outbound_iface.as_str(), config.dns.bootstrap.as_slice())
                    .unwrap();
            let group = match parse_dns_config(&config.dns.nameserver, Some(bootstrap)).await {
                Ok(g) => {
                    if g.is_empty() {
                        return Err(anyhow!("No DNS specified"));
                    }
                    g
                }
                Err(e) => return Err(anyhow!("Parse dns config failed: {e}")),
            };
            Arc::new(
                Dns::with_config(outbound_iface.as_str(), group)
                    .map_err(|e| anyhow!("DNS failed to initialize: {e}"))?,
            )
        };

        // Create TUN
        let (tun_udp_tx, tun_udp_rx) = flume::unbounded();
        let (udp_tun_tx, udp_tun_rx) = flume::unbounded();
        let tun = {
            let mut tun = TunDevice::open(
                manager.clone(),
                outbound_iface.as_str(),
                dns.clone(),
                fake_dns_server,
                tun_udp_tx,
                udp_tun_rx,
            )
            .map_err(|e| anyhow!("Fail to create TUN: {e}"))?;
            // create tun device
            tracing::info!("TUN Device {} opened.", tun.get_name());
            tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 1), 16).unwrap())
                .map_err(|e| anyhow!("TUN failed to set address: {e}"))?;
            tun.up().map_err(|e| anyhow!("TUN failed to up: {e}"))?;
            tun
        };
        let tun_configure = {
            let tun_configure = Arc::new(std::sync::Mutex::new(TunConfigure::new(
                fake_dns_server,
                tun.get_name(),
            )));
            if config.inbound.enable_tun {
                tun_configure
                    .lock()
                    .unwrap()
                    .enable()
                    .map_err(|e| anyhow!("Failed to enable global setting: {e}"))?;
            }
            tun_configure
        };

        let nat_addr = SocketAddr::new(
            platform::get_iface_address(tun.get_name())
                .map_err(|e| anyhow!("Failed to get tun address: {e}"))?,
            9961,
        );

        // dispatch
        let dispatching = Arc::new(
            DispatchingBuilder::new(dns.clone(), mmdb.clone())
                .build(&loaded_config)
                .map_err(|e| anyhow!("Parse routing rules failed: {}", e))?,
        );
        let dispatcher = {
            // tls mitm
            let cert = load_cert_and_key(&cert_path)
                .map_err(|e| anyhow!("Load certs from path {:?} failed: {}", cert_path, e))?;
            let rule_schema = &loaded_config.rule_schema;
            let intercept_filter = DispatchingBuilder::new(dns.clone(), mmdb.clone())
                .build_filter(config.intercept_rule.as_slice(), rule_schema)
                .map_err(|e| anyhow!("Load intercept rules failed: {}", e))?;
            let (url_modifier, hdr_modifier) = {
                let (url_mod, hdr_mod) = mapping_rewrite(config.rewrite.as_slice())
                    .map_err(|e| anyhow!("Parse url modifier rules, syntax failed: {}", e))?;
                (
                    Arc::new(UrlModManager::new(url_mod.as_slice()).map_err(|e| {
                        anyhow!("Parse url modifier rules, invalid regexes: {}", e)
                    })?),
                    Arc::new(HeaderModManager::new(hdr_mod.as_slice()).map_err(|e| {
                        anyhow!("Parse header modifier rules, invalid regexes: {}", e)
                    })?),
                )
            };
            let hcap_copy = http_capturer.clone();
            Arc::new(Dispatcher::new(
                outbound_iface.as_str(),
                dns.clone(),
                stat_center.clone(),
                dispatching.clone(),
                cert,
                Box::new(move |pi| {
                    Arc::new(InterceptModifier::new(
                        hcap_copy.clone(),
                        url_modifier.clone(),
                        hdr_modifier.clone(),
                        pi,
                    ))
                }),
                Arc::new(intercept_filter),
            ))
        };

        // create controller
        let api_dispatching_handler = Arc::new(ArcSwap::new(dispatching));
        let (reload_sender, reload_receiver) = tokio::sync::mpsc::channel::<()>(1);
        let speedtest_url = Arc::new(std::sync::RwLock::new(config.speedtest_url.clone()));
        let controller = Arc::new(Controller::new(
            manager.clone(),
            stat_center,
            Some(http_capturer.clone()),
            dispatcher.clone(),
            api_dispatching_handler.clone(),
            tun_configure.clone(),
            reload_sender,
            LinkedState {
                state_path: LoadedConfig::state_path(&data_path),
                state: loaded_config.state,
            },
            stream_logger,
            speedtest_url.clone(),
        ));

        // start tun
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
        );
        manager.flush_with_interval(Duration::from_secs(30));
        tokio::spawn(async move { tun_inbound_tcp.run().await });
        tokio::spawn(async move { tun_inbound_udp.run().await });
        tokio::spawn(async move { tun.run(nat_addr).await });

        // start http/socks5 inbound
        for (port, http_auth, socks_auth) in
            parse_two_inbound_service(&config.inbound.http, &config.inbound.socks5)
        {
            let dispatcher = dispatcher.clone();
            match (http_auth, socks_auth) {
                (Some(http_auth), Some(socks_auth)) => {
                    tokio::spawn(async move {
                        MixedInbound::new(port, http_auth, socks_auth, dispatcher)
                            .await?
                            .run()
                            .await;
                        Ok::<(), io::Error>(())
                    });
                }
                (Some(auth), None) => {
                    tokio::spawn(async move {
                        HttpInbound::new(port, auth, dispatcher).await?.run().await;
                        Ok::<(), io::Error>(())
                    });
                }
                (None, Some(auth)) => {
                    tokio::spawn(async move {
                        Socks5Inbound::new(port, auth, dispatcher)
                            .await?
                            .run()
                            .await;
                        Ok::<(), io::Error>(())
                    });
                }
                _ => unreachable!(),
            }
        }

        let uds_contoller = UdsController::new(controller.clone());
        let uds_listener2 = uds_listener.clone();
        tokio::spawn(async move { uds_contoller.run(uds_listener2).await });

        // start web controller
        if let Some(web_cfg) = &config.web_controller {
            let api_port = web_cfg.api_port;
            let api_server = WebController::new(web_cfg.api_key.clone(), controller);
            let cors_domains = web_cfg.cors_allowed_list.clone();
            tokio::spawn(async move { api_server.run(api_port, cors_domains.as_slice()).await });
        }

        Ok(Self {
            config_path,
            data_path,
            outbound_iface,
            dns,
            dispatcher,
            api_dispatching_handler,
            tun_configure,
            http_capturer,
            speedtest_url,
            receiver: reload_receiver,
            uds_socket: uds_listener,
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
        match reload(
            &self.config_path,
            &self.data_path,
            self.outbound_iface.as_str(),
            self.dns.clone(),
        )
        .await
        {
            Ok((
                dispatching,
                intercept_filter,
                url_rewriter,
                header_rewriter,
                new_speedtest_url,
            )) => {
                self.api_dispatching_handler.store(dispatching.clone());
                let hcap2 = self.http_capturer.clone();
                self.dispatcher.replace_dispatching(dispatching);
                self.dispatcher.replace_intercept_filter(intercept_filter);
                self.dispatcher.replace_modifier(Box::new(move |pi| {
                    Arc::new(InterceptModifier::new(
                        hcap2.clone(),
                        url_rewriter.clone(),
                        header_rewriter.clone(),
                        pi,
                    ))
                }));
                *self.speedtest_url.write().unwrap() = new_speedtest_url;
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
}

fn load_cert_and_key(cert_path: &Path) -> anyhow::Result<Certificate> {
    let cert_str = fs::read_to_string(cert_path.join("crt.pem"))?;
    let key_str = fs::read_to_string(cert_path.join("key.pem"))?;
    let key_pair = KeyPair::from_pem(key_str.as_str())?;
    let params = CertificateParams::from_ca_cert_pem(cert_str.as_str(), key_pair)?;
    let cert = Certificate::from_params(params)?;
    Ok(cert)
}

fn mapping_rewrite(list: &[String]) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let mut url_list = vec![];
    let mut header_list = vec![];
    for s in list.iter() {
        if s.starts_with("url,") {
            url_list.push(s.clone());
        } else if s.starts_with("header-req,") || s.starts_with("header-resp,") {
            header_list.push(s.clone());
        } else {
            return Err(anyhow::anyhow!("Unexpected: {}", s));
        }
    }
    Ok((url_list, header_list))
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

async fn reload(
    config_path: &Path,
    data_path: &Path,
    iface_name: &str,
    dns: Arc<Dns>,
) -> anyhow::Result<(
    Arc<Dispatching>,
    Arc<Dispatching>,
    Arc<UrlModManager>,
    Arc<HeaderModManager>,
    String,
)> {
    let loaded_config = LoadedConfig::load_config(config_path, data_path).await?;
    let config = &loaded_config.config;
    let mmdb = match config.geoip_db.as_ref() {
        None => None,
        Some(p) => {
            let path = safe_join_path(config_path, p)?;
            Some(Arc::new(MmdbReader::read_from_file(path)?))
        }
    };
    let (url_mod, hdr_mod) = {
        let (url, hdr) = mapping_rewrite(config.rewrite.as_slice())?;
        (
            Arc::new(UrlModManager::new(url.as_slice())?),
            Arc::new(HeaderModManager::new(hdr.as_slice())?),
        )
    };
    let bootstrap = new_bootstrap_resolver(iface_name, config.dns.bootstrap.as_slice())?;
    let group = parse_dns_config(&config.dns.nameserver, Some(bootstrap)).await?;
    let dispatching = {
        let builder = DispatchingBuilder::new(dns.clone(), mmdb.clone());
        Arc::new(builder.build(&loaded_config)?)
    };
    let intercept_filter = {
        let builder = DispatchingBuilder::new(dns.clone(), mmdb);
        let rule_schema = &loaded_config.rule_schema;
        Arc::new(builder.build_filter(config.intercept_rule.as_slice(), rule_schema)?)
    };
    dns.replace_resolvers(iface_name, group).await?;
    Ok((
        dispatching,
        intercept_filter,
        url_mod,
        hdr_mod,
        config.speedtest_url.clone(),
    ))
}

#[allow(clippy::type_complexity)]
fn parse_two_inbound_service(
    http: &Option<RawInboundServiceConfig>,
    socks5: &Option<RawInboundServiceConfig>,
) -> Vec<(
    u16,
    Option<HashMap<String, String>>,
    Option<HashMap<String, String>>,
)> {
    fn parse_inbound_service(
        auths: &Option<RawInboundServiceConfig>,
    ) -> Option<(u16, HashMap<String, String>)> {
        let Some(config) = auths.as_ref() else {
            return None
        };
        match config {
            RawInboundServiceConfig::Simple(p) => Some((*p, Default::default())),
            RawInboundServiceConfig::Complex { port, auth } => {
                let authmap = auth
                    .iter()
                    .map(|a| (a.username.clone(), a.password.clone()))
                    .collect();
                Some((*port, authmap))
            }
        }
    }

    match (parse_inbound_service(http), parse_inbound_service(socks5)) {
        (Some(h), Some(s)) => {
            if h.0 == s.0 {
                vec![(h.0, Some(h.1), Some(s.1))]
            } else {
                vec![(h.0, Some(h.1), None), (s.0, None, Some(s.1))]
            }
        }
        (Some(h), None) => vec![(h.0, Some(h.1), None)],
        (None, Some(s)) => vec![(s.0, None, Some(s.1))],
        (None, None) => vec![],
    }
}
