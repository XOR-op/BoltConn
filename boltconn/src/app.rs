use crate::config::{LinkedState, LoadedConfig};
use crate::dispatch::{Dispatching, DispatchingBuilder};
use crate::external::{ApiServer, Controller, DatabaseHandle, SharedDispatching, StreamLoggerSend};
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
use ipnet::Ipv4Net;
use rcgen::{Certificate, CertificateParams, KeyPair};
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
    speedtest_url: Arc<std::sync::Mutex<String>>,
    receiver: tokio::sync::mpsc::Receiver<()>,
}

impl App {
    /// Create a running App instance.
    pub async fn create(
        config_path: PathBuf,
        data_path: PathBuf,
        cert_path: PathBuf,
    ) -> anyhow::Result<Self> {
        // tokio and tracing

        let stream_logger = StreamLoggerSend::new();
        external::init_tracing(&stream_logger);

        // interface
        let (_, real_iface_name) =
            get_default_route().map_err(|e| anyhow!("Failed to get default route: {}", e))?;

        let fake_dns_server = "198.18.99.88".parse().unwrap();

        // database handle
        let conn_handle = open_database_handle(data_path.as_path())?;
        let intercept_handle = conn_handle.clone();

        // config-independent components
        let manager = Arc::new(SessionManager::new());
        let stat_center = Arc::new(ContextManager::new(conn_handle));
        let http_capturer = Arc::new(HttpCapturer::new(intercept_handle));
        let hcap_copy = http_capturer.clone();
        let (tun_udp_tx, tun_udp_rx) = flume::unbounded();
        let (udp_tun_tx, udp_tun_rx) = flume::unbounded();

        // Read initial config
        let loaded_config = LoadedConfig::load_config(&config_path, &data_path)
            .await
            .map_err(|e| anyhow!("Load config from {:?} failed: {}", &config_path, e))?;
        let config = &loaded_config.config;

        let outbound_iface = if config.interface != "auto" {
            config.interface.clone()
        } else {
            tracing::info!("Auto detected interface: {}", real_iface_name);
            real_iface_name
        };
        let cors_domains = config.restful.cors_allowed_list.clone();

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

        let tun_configure = Arc::new(std::sync::Mutex::new(TunConfigure::new(
            fake_dns_server,
            tun.get_name(),
        )));
        tun_configure
            .lock()
            .unwrap()
            .enable()
            .map_err(|e| anyhow!("Failed to enable global setting: {e}"))?;

        let nat_addr = SocketAddr::new(
            platform::get_iface_address(tun.get_name())
                .map_err(|e| anyhow!("Failed to get tun address: {e}"))?,
            9961,
        );

        let dispatching = Arc::new(
            DispatchingBuilder::new()
                .build(&loaded_config)
                .map_err(|e| anyhow!("Parse routing rules failed: {}", e))?,
        );

        // external controller
        let api_dispatching_handler = Arc::new(tokio::sync::RwLock::new(dispatching.clone()));
        let api_port = config.restful.api_port;
        let (sender, receiver) = tokio::sync::mpsc::channel::<()>(1);

        let dispatcher = {
            // tls mitm
            let cert = load_cert_and_key(&cert_path)
                .map_err(|e| anyhow!("Load certs from path {:?} failed: {}", cert_path, e))?;
            let rule_schema = &loaded_config.rule_schema;
            let intercept_filter = DispatchingBuilder::new()
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
            Arc::new(Dispatcher::new(
                outbound_iface.as_str(),
                dns.clone(),
                stat_center.clone(),
                dispatching,
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

        let speedtest_url = Arc::new(std::sync::Mutex::new(config.restful.speedtest_url.clone()));

        let controller = Arc::new(Controller::new(
            manager.clone(),
            stat_center,
            Some(http_capturer.clone()),
            dispatcher.clone(),
            api_dispatching_handler.clone(),
            tun_configure.clone(),
            sender,
            LinkedState {
                state_path: LoadedConfig::state_path(&data_path),
                state: loaded_config.state,
            },
            stream_logger,
            speedtest_url.clone(),
        ));
        let api_server = ApiServer::new(config.restful.api_key.clone(), controller);

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

        // run
        manager.flush_with_interval(Duration::from_secs(30));
        tokio::spawn(async move { tun_inbound_tcp.run().await });
        tokio::spawn(async move { tun_inbound_udp.run().await });
        tokio::spawn(async move { tun.run(nat_addr).await });
        tokio::spawn(async move { api_server.run(api_port, cors_domains.as_slice()).await });
        if config.http_port == config.socks5_port && config.http_port.is_some() {
            // Mixed inbound
            let port = config.http_port.unwrap();
            let dispatcher = dispatcher.clone();
            tokio::spawn(async move {
                let mixed_proxy = MixedInbound::new(port, None, None, dispatcher).await?;
                mixed_proxy.run().await;
                Ok::<(), io::Error>(())
            });
        } else {
            if let Some(http_port) = config.http_port {
                let dispatcher = dispatcher.clone();
                tokio::spawn(async move {
                    let http_proxy = HttpInbound::new(http_port, None, dispatcher).await?;
                    http_proxy.run().await;
                    Ok::<(), io::Error>(())
                });
            }
            if let Some(socks5_port) = config.socks5_port {
                let dispatcher = dispatcher.clone();
                tokio::spawn(async move {
                    let socks_proxy = Socks5Inbound::new(socks5_port, None, dispatcher).await?;
                    socks_proxy.run().await;
                    Ok::<(), io::Error>(())
                });
            }
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
            receiver,
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
                *self.api_dispatching_handler.write().await = dispatching.clone();
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
                *self.speedtest_url.lock().unwrap() = new_speedtest_url;
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
        let builder = DispatchingBuilder::new();
        Arc::new(builder.build(&loaded_config)?)
    };
    let intercept_filter = {
        let builder = DispatchingBuilder::new();
        let rule_schema = &loaded_config.rule_schema;
        Arc::new(builder.build_filter(config.intercept_rule.as_slice(), rule_schema)?)
    };
    dns.replace_resolvers(iface_name, group).await?;
    Ok((
        dispatching,
        intercept_filter,
        url_mod,
        hdr_mod,
        config.restful.speedtest_url.clone(),
    ))
}
