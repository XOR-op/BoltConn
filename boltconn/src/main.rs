#![allow(unused_imports)]
#![allow(dead_code)]

extern crate core;

use crate::common::host_matcher::{HostMatcher, HostMatcherBuilder};
use crate::config::{LinkedState, RawRootCfg, RawState, RuleSchema};
use crate::dispatch::{Dispatching, DispatchingBuilder};
use crate::external::ApiServer;
use crate::mitm::{MitmModifier, Recorder, UrlModManager};
use crate::network::dns::{extract_address, new_bootstrap_resolver, parse_dns_config};
use crate::proxy::{AgentCenter, HttpCapturer, UdpOutboundManager};
use chrono::Timelike;
use common::buf_pool::PktBufPool;
use ipnet::Ipv4Net;
use is_root::is_root;
use network::tun_device::TunDevice;
use network::{
    dns::Dns,
    packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt},
};
use platform::get_default_route;
use proxy::Dispatcher;
use proxy::{Nat, SessionManager};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, io};
use tokio::select;
use tokio_rustls::rustls::{Certificate, PrivateKey};
use tracing::{event, Level};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod adapter;
mod common;
mod config;
mod dispatch;
mod external;
mod mitm;
mod network;
mod platform;
mod proxy;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct SystemTime;

impl FormatTime for SystemTime {
    fn format_time(&self, w: &mut Writer<'_>) -> core::fmt::Result {
        let time = chrono::prelude::Local::now();
        write!(
            w,
            "{:02}:{:02}:{:02}.{:03}",
            (time.hour() + 8) % 24,
            time.minute(),
            time.second(),
            time.timestamp_subsec_millis()
        )
    }
}

fn load_cert_and_key(
    cert_path: &str,
    key_path: &str,
) -> io::Result<(Vec<Certificate>, PrivateKey)> {
    let cert_raw = fs::read(cert_path)?;
    let mut cert_bytes = cert_raw.as_slice();
    let key_raw = fs::read(key_path)?;
    let mut key_bytes = key_raw.as_slice();
    let cert = Certificate(rustls_pemfile::certs(&mut cert_bytes)?.remove(0));
    let key = PrivateKey(rustls_pemfile::pkcs8_private_keys(&mut key_bytes)?.remove(0));
    Ok((vec![cert], key))
}

async fn load_config(
    config_path: &str,
    state_path: &str,
) -> anyhow::Result<(RawRootCfg, RawState, HashMap<String, RuleSchema>)> {
    let config_text = fs::read_to_string(config_path)?;
    let raw_config: RawRootCfg = serde_yaml::from_str(&config_text).unwrap();
    let state_text = fs::read_to_string(state_path)?;
    let raw_state: RawState = serde_yaml::from_str(&state_text).unwrap();
    let config_folder = PathBuf::from_str(config_path)
        .unwrap()
        .parent()
        .unwrap()
        .display()
        .to_string();
    let schema = tokio::join!(config::read_schema(
        config_folder.as_str(),
        &raw_config.rule_provider,
        false
    ))
    .0?;
    Ok((raw_config, raw_state, schema))
}

fn mapping_rewrite(list: &[String]) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let mut url_list = vec![];
    let mut header_list = vec![];
    for s in list.iter() {
        if s.starts_with("url,") {
            url_list.push(s.clone());
        } else if s.starts_with("header,") {
            header_list.push(s.clone());
        } else {
            return Err(anyhow::anyhow!("Unexpected: {}", s));
        }
    }
    Ok((url_list, header_list))
}

fn initialize_dispatching(
    raw_config: &RawRootCfg,
    raw_state: &RawState,
    schema: HashMap<String, RuleSchema>,
) -> anyhow::Result<Arc<Dispatching>> {
    let builder = DispatchingBuilder::new_from_config(&raw_config, &raw_state, schema)?;
    Ok(Arc::new(builder.build()))
}

fn read_mitm_hosts(arr: &Option<Vec<String>>) -> HostMatcher {
    let mut builder = HostMatcherBuilder::new();
    if let Some(arr) = arr.as_ref() {
        for s in arr {
            if s.starts_with("*") {
                let st: String = s.chars().skip(1).collect();
                builder.add_suffix(st.as_str());
            } else {
                builder.add_exact(s.as_str())
            }
        }
    }
    builder.build()
}

fn main() {
    let config_path = "./_private/config/config.yml";
    let state_path = "./_private/config/state.yml";
    let crt_path = "_private/ca/crt.pem";
    let privkey_path = "_private/ca/key.pem";

    if !is_root() {
        println!("BoltConn must be run with root privilege.");
        exit(-1);
    }

    // tokio and tracing
    let rt = tokio::runtime::Runtime::new().expect("Tokio failed to initialize");
    let formatting_layer = fmt::layer()
        .compact()
        .with_writer(std::io::stdout)
        .with_timer(SystemTime::default());
    tracing_subscriber::registry()
        .with(formatting_layer)
        .with(EnvFilter::new("boltconn=trace"))
        .init();

    // interface
    let (_, real_iface_name) = get_default_route().expect("failed to get default route");

    // guards
    let _guard = rt.enter();
    let fake_dns_server = "198.18.99.88".parse().unwrap();
    let _dns_guard =
        platform::SystemDnsHandle::new(fake_dns_server).expect("fail to replace /etc/resolv.conf");

    // config-independent components
    let manager = Arc::new(SessionManager::new());
    let stat_center = Arc::new(AgentCenter::new());
    let http_capturer = Arc::new(HttpCapturer::new());
    let hcap_copy = http_capturer.clone();
    let proxy_allocator = PktBufPool::new(512, 4096);
    let udp_manager = Arc::new(UdpOutboundManager::new());

    // Read initial config
    let (config, state, schema) = rt.block_on(load_config(config_path, state_path)).unwrap();

    // initialize resources
    let (dns, dns_ips) = {
        let bootstrap = new_bootstrap_resolver(config.dns.bootstrap.as_slice()).unwrap();
        let group = rt
            .block_on(parse_dns_config(&config.dns.nameserver, Some(bootstrap)))
            .unwrap();
        let dns_ips = if config.dns.force_direct_dns {
            Some(extract_address(&group))
        } else {
            None
        };
        (
            Arc::new(Dns::with_config(group).expect("DNS failed to initialize")),
            dns_ips,
        )
    };

    let outbound_iface = if config.interface != "auto" {
        config.interface.clone()
    } else {
        tracing::info!("Auto detected interface: {}", real_iface_name);
        real_iface_name
    };

    let tun = rt.block_on(async {
        let pool = PktBufPool::new(512, 4096);
        let mut tun = TunDevice::open(
            manager.clone(),
            pool,
            outbound_iface.as_str(),
            dns.clone(),
            fake_dns_server,
        )
        .expect("fail to create TUN");
        // create tun device
        event!(Level::INFO, "TUN Device {} opened.", tun.get_name());
        tun.set_network_address(Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 1), 16).unwrap())
            .expect("TUN failed to set address");
        tun.up().expect("TUN failed to up");
        tun
    });
    let nat_addr = SocketAddr::new(
        platform::get_iface_address(tun.get_name()).expect("failed to get tun address"),
        9961,
    );

    let dispatching = {
        let mut builder = DispatchingBuilder::new_from_config(&config, &state, schema).unwrap();
        if let Some(list) = dns_ips {
            builder.direct_prioritize(list);
        }
        Arc::new(builder.build())
    };

    // external controller
    let api_dispatching_handler = Arc::new(tokio::sync::RwLock::new(dispatching.clone()));
    let api_port = config.api_port;
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<()>(1);
    let api_server = ApiServer::new(
        manager.clone(),
        stat_center.clone(),
        Some(http_capturer.clone()),
        api_dispatching_handler.clone(),
        sender,
        LinkedState {
            state_path: state_path.to_string(),
            state,
        },
    );

    let dispatcher = {
        // tls mitm
        let (cert, priv_key) = load_cert_and_key(crt_path, privkey_path).unwrap();
        let url_modifier = if let Some(rewrite_cfg) = &config.rewrite {
            let (url_mod, _hdr_mod) = mapping_rewrite(rewrite_cfg.as_slice()).unwrap();
            Arc::new(UrlModManager::new(url_mod.as_slice()).unwrap())
        } else {
            Arc::new(UrlModManager::empty())
        };
        Arc::new(Dispatcher::new(
            outbound_iface.as_str(),
            proxy_allocator.clone(),
            dns.clone(),
            stat_center.clone(),
            dispatching.clone(),
            cert,
            priv_key,
            Box::new(move |pi| {
                Arc::new(MitmModifier::new(
                    hcap_copy.clone(),
                    url_modifier.clone(),
                    pi,
                ))
            }),
            read_mitm_hosts(&config.mitm_host),
        ))
    };
    let nat = Arc::new(Nat::new(
        nat_addr,
        manager.clone(),
        dispatcher.clone(),
        dns.clone(),
        proxy_allocator.clone(),
        udp_manager.clone(),
    ));
    let nat_tcp = nat.clone();
    let nat_udp = nat.clone();

    // run
    let _mgr_flush_handle = manager.flush_with_interval(Duration::from_secs(30));
    let _nat_tcp_handle = rt.spawn(async move { nat_tcp.run_tcp().await });
    let _nat_udp_handle = rt.spawn(async move { nat_udp.run_udp().await });
    let _tun_handle = rt.spawn(async move { tun.run(nat_addr).await });
    let _api_handle = rt.spawn(async move { api_server.run(api_port).await });

    rt.block_on(async move {
        loop {
            select! {
                _ = tokio::signal::ctrl_c()=>return,
                restart = receiver.recv() => {
                    if restart.is_some(){
                        // try restarting components
                        match reload(config_path,state_path,dns.clone()).await{
                            Ok((dispatching, mitm_hosts,url_rewriter)) => {
                                *api_dispatching_handler.write().await = dispatching.clone();
                                let hcap2 = http_capturer.clone();
                                dispatcher.replace_dispatching(dispatching);
                                dispatcher.replace_mitm_list(mitm_hosts);
                                dispatcher.replace_modifier(Box::new(move |pi| Arc::new(MitmModifier::new(hcap2.clone(),url_rewriter.clone(),pi))));
                                tracing::info!("Reloaded config successfully");
                            }
                            Err(err)=>{
                                tracing::warn!("Reloading config failed: {}",err);
                            }
                        }
                    }else {
                        return;
                    }
                }
            }
        }
    });
    tracing::info!("Exiting...");
    drop(_dns_guard);
    rt.shutdown_background();
}

async fn reload(
    config_path: &str,
    state_path: &str,
    dns: Arc<Dns>,
) -> anyhow::Result<(Arc<Dispatching>, HostMatcher, Arc<UrlModManager>)> {
    let (config, state, schema) = load_config(config_path, state_path).await?;
    let url_mod = if let Some(rewrite) = &config.rewrite {
        let (url, _hdr) = mapping_rewrite(rewrite.as_slice())?;
        Arc::new(UrlModManager::new(url.as_slice())?)
    } else {
        Arc::new(UrlModManager::empty())
    };
    let bootstrap = new_bootstrap_resolver(config.dns.bootstrap.as_slice())?;
    let group = parse_dns_config(&config.dns.nameserver, Some(bootstrap)).await?;
    let dispatching = {
        let mut builder = DispatchingBuilder::new_from_config(&config, &state, schema)?;
        if config.dns.force_direct_dns {
            builder.direct_prioritize(extract_address(&group));
        }
        Arc::new(builder.build())
    };
    dns.replace_resolvers(group).await?;
    Ok((dispatching, read_mitm_hosts(&config.mitm_host), url_mod))
}
