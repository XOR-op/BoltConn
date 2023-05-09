#![allow(dead_code)]

extern crate core;

use crate::config::{LinkedState, LoadedConfig};
use crate::dispatch::{Dispatching, DispatchingBuilder};
use crate::external::{ApiServer, StreamLoggerHandle};
use crate::intercept::{HeaderModManager, InterceptModifier, UrlModManager};
use crate::network::configure::TunConfigure;
use crate::network::dns::{new_bootstrap_resolver, parse_dns_config};
use crate::proxy::{
    AgentCenter, HttpCapturer, HttpInbound, MixedInbound, Socks5Inbound, TunUdpInbound,
};
use ipnet::Ipv4Net;
use is_root::is_root;
use network::tun_device::TunDevice;
use network::{
    dns::Dns,
    packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt},
};
use platform::get_default_route;
use proxy::Dispatcher;
use proxy::{SessionManager, TunTcpInbound};
use rcgen::{Certificate, CertificateParams, KeyPair};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, io};
use structopt::StructOpt;
use tokio::select;
use tracing::{event, Level};

mod adapter;
mod common;
mod config;
mod dispatch;
mod external;
mod intercept;
mod network;
mod platform;
mod proxy;
mod transport;

#[derive(Debug, StructOpt)]
#[structopt(name = "boltconn", about = "BoltConn core binary")]
struct Args {
    /// Path of configutation. Default to $HOME/.config/boltconn
    #[structopt(short, long)]
    pub config: Option<PathBuf>,
    /// Path of certificate. Default to ${config}/cert
    #[structopt(long)]
    pub cert: Option<PathBuf>,
}

fn parse_config_path(
    config: &Option<PathBuf>,
    cert: &Option<PathBuf>,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let config_path = match config {
        None => {
            let home = PathBuf::from(std::env::var("HOME")?);
            home.join(".config").join("boltconn")
        }
        Some(p) => p.clone(),
    };
    let cert_path = match cert {
        None => config_path.join("cert"),
        Some(p) => p.clone(),
    };
    Ok((config_path, cert_path))
}

fn load_cert_and_key(cert_path: &Path) -> anyhow::Result<Certificate> {
    let cert_str = fs::read_to_string(cert_path.join("crt.pem"))?;
    let key_str = fs::read_to_string(cert_path.join("key.pem"))?;
    let key_pair = KeyPair::from_pem(key_str.as_str())?;
    let params = CertificateParams::from_ca_cert_pem(cert_str.as_str(), key_pair)?;
    let cert = Certificate::from_params(params)?;
    Ok(cert)
}

fn state_path(config_path: &Path) -> PathBuf {
    config_path.join("state.yml")
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

fn main() -> ExitCode {
    if !is_root() {
        eprintln!("BoltConn must be run with root privilege.");
        return ExitCode::from(1);
    }
    let args: Args = Args::from_args();
    let (config_path, cert_path) =
        parse_config_path(&args.config, &args.cert).expect("Invalid config path");

    // tokio and tracing
    let rt = tokio::runtime::Runtime::new().expect("Tokio failed to initialize");

    let stream_logger = StreamLoggerHandle::new();
    external::init_tracing(&stream_logger);

    // interface
    let (_, real_iface_name) = get_default_route().expect("failed to get default route");

    // guards
    let _guard = rt.enter();
    let fake_dns_server = "198.18.99.88".parse().unwrap();

    // config-independent components
    let manager = Arc::new(SessionManager::new());
    let stat_center = Arc::new(AgentCenter::new());
    let http_capturer = Arc::new(HttpCapturer::new());
    let hcap_copy = http_capturer.clone();
    let (tun_udp_tx, tun_udp_rx) = flume::unbounded();
    let (udp_tun_tx, udp_tun_rx) = flume::unbounded();

    // Read initial config
    let loaded_config = match rt.block_on(LoadedConfig::load_config(&config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Load config from {:?} failed: {}", &config_path, e);
            return ExitCode::from(1);
        }
    };
    let config = &loaded_config.config;

    let outbound_iface = if config.interface != "auto" {
        config.interface.clone()
    } else {
        tracing::info!("Auto detected interface: {}", real_iface_name);
        real_iface_name
    };

    // initialize resources
    let dns = {
        let bootstrap = new_bootstrap_resolver(config.dns.bootstrap.as_slice()).unwrap();
        let group = match rt.block_on(parse_dns_config(&config.dns.nameserver, Some(bootstrap))) {
            Ok(g) => {
                if g.is_empty() {
                    eprintln!("No DNS specified");
                    return ExitCode::from(1);
                } else {
                    g
                }
            }
            Err(e) => {
                eprintln!("Parse dns config failed: {}", e);
                return ExitCode::from(1);
            }
        };
        Arc::new(
            Dns::with_config(outbound_iface.as_str(), group).expect("DNS failed to initialize"),
        )
    };

    let tun = rt.block_on(async {
        let mut tun = TunDevice::open(
            manager.clone(),
            outbound_iface.as_str(),
            dns.clone(),
            fake_dns_server,
            tun_udp_tx,
            udp_tun_rx,
        )
        .expect("fail to create TUN");
        // create tun device
        event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
        tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 1), 16).unwrap())
            .expect("TUN failed to set address");
        tun.up().expect("TUN failed to up");
        tun
    });

    let tun_configure = Arc::new(std::sync::Mutex::new(TunConfigure::new(
        fake_dns_server,
        tun.get_name(),
    )));
    tun_configure
        .lock()
        .unwrap()
        .enable()
        .expect("Failed to enable global setting");

    let nat_addr = SocketAddr::new(
        platform::get_iface_address(tun.get_name()).expect("failed to get tun address"),
        9961,
    );

    let dispatching = {
        let builder = DispatchingBuilder::new();
        let result = match builder.build(&loaded_config) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Parse routing rules failed: {}", e);
                return ExitCode::from(1);
            }
        };
        Arc::new(result)
    };

    // external controller
    let api_dispatching_handler = Arc::new(tokio::sync::RwLock::new(dispatching.clone()));
    let api_port = config.api_port;
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<()>(1);

    let dispatcher = {
        // tls mitm
        let cert = match load_cert_and_key(&cert_path) {
            Ok(cert) => cert,
            Err(e) => {
                eprintln!("Load certs from path {:?} failed: {}", cert_path, e);
                return ExitCode::from(1);
            }
        };
        let rule_schema = &loaded_config.rule_schema;
        let intercept_filter = match {
            let builder = DispatchingBuilder::new();
            builder.build_filter(config.intercept_rule.as_slice(), rule_schema)
        } {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Load intercept rules failed: {}", e);
                return ExitCode::from(1);
            }
        };
        let (url_modifier, hdr_modifier) = {
            let (url_mod, hdr_mod) = match mapping_rewrite(config.rewrite.as_slice()) {
                Ok((url_mod, hdr_mod)) => (url_mod, hdr_mod),
                Err(e) => {
                    eprintln!("Parse url modifier rules, syntax failed: {}", e);
                    return ExitCode::from(1);
                }
            };
            (
                Arc::new(match UrlModManager::new(url_mod.as_slice()) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("Parse url modifier rules, invalid regexes: {}", e);
                        return ExitCode::from(1);
                    }
                }),
                Arc::new(match HeaderModManager::new(hdr_mod.as_slice()) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("Parse header modifier rules, invalid regexes: {}", e);
                        return ExitCode::from(1);
                    }
                }),
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

    let speedtest_url = Arc::new(std::sync::Mutex::new(config.speedtest_url.clone()));

    let api_server = ApiServer::new(
        config.api_key.clone(),
        manager.clone(),
        stat_center,
        Some(http_capturer.clone()),
        dispatcher.clone(),
        api_dispatching_handler.clone(),
        tun_configure.clone(),
        sender,
        LinkedState {
            state_path: state_path(&config_path),
            state: loaded_config.state,
        },
        stream_logger,
        speedtest_url.clone(),
    );

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
    let _mgr_flush_handle = manager.flush_with_interval(Duration::from_secs(30));
    let _tun_inbound_tcp_handle = rt.spawn(async move { tun_inbound_tcp.run().await });
    let _tun_inbound_udp_handle = rt.spawn(async move { tun_inbound_udp.run().await });
    let _tun_handle = rt.spawn(async move { tun.run(nat_addr).await });
    let _api_handle = rt.spawn(async move { api_server.run(api_port).await });
    if config.http_port == config.socks5_port && config.http_port.is_some() {
        // Mixed inbound
        let port = config.http_port.unwrap();
        let dispatcher = dispatcher.clone();
        rt.spawn(async move {
            let mixed_proxy = MixedInbound::new(port, None, None, dispatcher).await?;
            mixed_proxy.run().await;
            Ok::<(), io::Error>(())
        });
    } else {
        if let Some(http_port) = config.http_port {
            let dispatcher = dispatcher.clone();
            rt.spawn(async move {
                let http_proxy = HttpInbound::new(http_port, None, dispatcher).await?;
                http_proxy.run().await;
                Ok::<(), io::Error>(())
            });
        }
        if let Some(socks5_port) = config.socks5_port {
            let dispatcher = dispatcher.clone();
            rt.spawn(async move {
                let socks_proxy = Socks5Inbound::new(socks5_port, None, dispatcher).await?;
                socks_proxy.run().await;
                Ok::<(), io::Error>(())
            });
        }
    }

    rt.block_on(async move {
        loop {
            select! {
                _ = tokio::signal::ctrl_c()=>return,
                restart = receiver.recv() => {
                    if restart.is_some(){
                        // try restarting components
                        match reload(&config_path, outbound_iface.as_str(), dns.clone()).await{
                            Ok((dispatching, intercept_filter,url_rewriter,header_rewriter,new_speedtest_url)) => {
                                *api_dispatching_handler.write().await = dispatching.clone();
                                let hcap2 = http_capturer.clone();
                                dispatcher.replace_dispatching(dispatching);
                                dispatcher.replace_intercept_filter(intercept_filter);
                                dispatcher.replace_modifier(Box::new(move |pi| Arc::new(InterceptModifier::new(hcap2.clone(),url_rewriter.clone(),header_rewriter.clone(),pi))));
                                *speedtest_url.lock().unwrap() = new_speedtest_url;
                                tracing::info!("Reloaded config successfully");
                            }
                            Err(err)=>{
                                tracing::error!("Reloading config failed: {}",err);
                            }
                        }
                    } else {
                        return;
                    }
                }
            }
        }
    });
    tracing::info!("Exiting...");
    tun_configure.lock().unwrap().disable();
    rt.shutdown_background();
    ExitCode::from(0)
}

async fn reload(
    config_path: &Path,
    iface_name: &str,
    dns: Arc<Dns>,
) -> anyhow::Result<(
    Arc<Dispatching>,
    Arc<Dispatching>,
    Arc<UrlModManager>,
    Arc<HeaderModManager>,
    String,
)> {
    let loaded_config = LoadedConfig::load_config(config_path).await?;
    let config = &loaded_config.config;
    let (url_mod, hdr_mod) = {
        let (url, hdr) = mapping_rewrite(config.rewrite.as_slice())?;
        (
            Arc::new(UrlModManager::new(url.as_slice())?),
            Arc::new(HeaderModManager::new(hdr.as_slice())?),
        )
    };
    let bootstrap = new_bootstrap_resolver(config.dns.bootstrap.as_slice())?;
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
        config.speedtest_url.clone(),
    ))
}
