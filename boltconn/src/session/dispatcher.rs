use crate::adapter::{Connector, DirectOutbound, OutBound, Socks5Outbound, TunAdapter};
use crate::common::duplex_chan::DuplexChan;
use crate::dispatch::{ConnInfo, Dispatching, ProxyImpl};
use crate::network::dns::Dns;
use crate::platform::process;
use crate::session::{NetworkAddr, SessionInfo};
use crate::sniff::{HttpSniffer, HttpsSniffer};
use crate::PktBufPool;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{Certificate, PrivateKey};
use crate::platform::process::NetworkType;

pub struct Dispatcher {
    iface_name: String,
    allocator: PktBufPool,
    dns: Arc<Dns>,
    dispatching: Arc<Dispatching>,
    certificate: Vec<Certificate>,
    priv_key: PrivateKey,
}

impl Dispatcher {
    pub fn new(
        iface_name: &str,
        allocator: PktBufPool,
        dns: Arc<Dns>,
        dispatching: Arc<Dispatching>,
        certificate: Vec<Certificate>,
        priv_key: PrivateKey,
    ) -> Self {
        Self {
            iface_name: iface_name.into(),
            allocator,
            dns,
            dispatching,
            certificate,
            priv_key,
        }
    }

    pub fn submit_tun_tcp(
        &self,
        src_addr: SocketAddr,
        dst_addr: NetworkAddr,
        indicator: Arc<AtomicU8>,
        stream: TcpStream,
    ) {
        let process_info = process::get_pid(src_addr, process::NetworkType::TCP)
            .map_or(None, |pid| process::get_process_info(pid));
        let conn_info = ConnInfo {
            src: src_addr,
            dst: dst_addr.clone(),
            connection_type: NetworkType::TCP,
            process_info,
        };

        let outbounding: Box<dyn OutBound> = match self.dispatching.matches(conn_info) {
            ProxyImpl::Direct => Box::new(DirectOutbound::new(
                &self.iface_name, dst_addr.clone(), self.allocator.clone(), self.dns.clone())),
            ProxyImpl::Socks5(cfg) => Box::new(Socks5Outbound::new(
                &self.iface_name, dst_addr.clone(), self.allocator.clone(), self.dns.clone(), cfg,
            ))
        };

        let info = SessionInfo::new(dst_addr.clone(), "direct");

        let (tun_conn, tun_next) = Connector::new_pair(10);
        let tun_alloc = self.allocator.clone();
        let out_dst_addr = dst_addr.clone();
        tokio::spawn(async move {
            let tun = TunAdapter::new(
                src_addr,
                out_dst_addr,
                info,
                stream,
                indicator,
                tun_alloc,
                tun_conn,
            );
            if let Err(err) = tun.run().await {
                tracing::error!("[Dispatcher] run TunAdapter failed: {}", err)
            }
        });
        match dst_addr.port() {
            80 => {
                // hijack
                tracing::debug!("HTTP sniff");
                let http_alloc = self.allocator.clone();
                tokio::spawn(async move {
                    let mocker = HttpSniffer::new(DuplexChan::new(http_alloc, tun_next), outbounding);
                    if let Err(err) = mocker.run().await {
                        tracing::error!("[Dispatcher] mock HTTP failed: {}", err)
                    }
                });
            }
            443 if matches!(dst_addr, NetworkAddr::DomainName { .. }) => {
                tracing::debug!("HTTP sniff");
                let http_alloc = self.allocator.clone();
                let cert = self.certificate.clone();
                let key = self.priv_key.clone();
                let domain_name = match dst_addr.clone() {
                    NetworkAddr::Raw(_) => unreachable!(),
                    NetworkAddr::DomainName { domain_name, .. } => domain_name,
                };
                tokio::spawn(async move {
                    let mocker = HttpsSniffer::new(
                        cert,
                        key,
                        domain_name,
                        DuplexChan::new(http_alloc, tun_next),
                        outbounding,
                    );
                    if let Err(err) = mocker.run().await {
                        tracing::error!("[Dispatcher] mock HTTPS failed: {}", err)
                    }
                });
            }
            _ => {
                tokio::spawn(async move {
                    if let Err(err) = outbounding.spawn(tun_next).await {
                        tracing::error!("[Dispatcher] create failed: {}", err)
                    }
                });
            }
        }
    }
}
