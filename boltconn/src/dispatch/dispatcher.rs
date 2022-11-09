use crate::adapter::{Connector, DirectOutbound, TunAdapter};
use crate::common::duplex_chan::DuplexChan;
use crate::platform::process;
use crate::session::{NetworkAddr, SessionInfo};
use crate::sniff::{HttpSniffer, HttpsSniffer};
use crate::PktBufPool;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{Certificate, PrivateKey};

pub struct Dispatcher {
    iface_name: String,
    allocator: PktBufPool,
    certificate: Vec<Certificate>,
    priv_key: PrivateKey,
}

impl Dispatcher {
    pub fn new(
        iface_name: &str,
        allocator: PktBufPool,
        certificate: Vec<Certificate>,
        priv_key: PrivateKey,
    ) -> Self {
        Self {
            iface_name: iface_name.into(),
            allocator,
            certificate,
            priv_key,
        }
    }

    pub fn submit_tun_tcp(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        dst_domain: Option<String>,
        indicator: Arc<AtomicU8>,
        stream: TcpStream,
    ) {
        let info = {
            let r = process::get_pid(src_addr, process::NetworkType::TCP);
            if let Ok(pid) = r {
                process::get_process_info(pid)
            } else {
                tracing::info!(
                    "[Dispatcher] ({} -> {}) get_pid() failed: {:?}",
                    src_addr,
                    dst_addr,
                    r
                );
                None
            }
        };
        if let Some(info) = info {
            tracing::trace!(
                "[Dispatcher] ({} -> {}) Name:{}, Path:{}",
                src_addr,
                dst_addr,
                info.name,
                info.path
            )
        } else {
            tracing::info!(
                "[Dispatcher] ({} -> {}) get_process_info() failed",
                src_addr,
                dst_addr
            );
        }
        let info = SessionInfo::new(
            match dst_domain.clone() {
                Some(dn) => NetworkAddr::DomainName {
                    domain_name: dn,
                    port: dst_addr.port(),
                },
                None => NetworkAddr::Raw(dst_addr),
            },
            "direct",
        );

        let (tun_conn, tun_next) = Connector::new_pair(10);
        let (tun_alloc, out_alloc) = (self.allocator.clone(), self.allocator.clone());
        let name = self.iface_name.clone();
        let out_dst_addr = dst_addr.clone();
        tokio::spawn(async move {
            let tun = TunAdapter::new(
                src_addr, dst_addr, info, stream, indicator, tun_alloc, tun_conn,
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
                    let mocker =
                        HttpSniffer::new(DuplexChan::new(http_alloc, tun_next), move || {
                            let direct =
                                DirectOutbound::new(name.as_str(), out_dst_addr, out_alloc.clone());
                            direct.as_async().0
                        });
                    if let Err(err) = mocker.run().await {
                        tracing::error!("[Dispatcher] mock HTTP failed: {}", err)
                    }
                });
            }
            443 if dst_domain.is_some() => {
                tracing::debug!("HTTP sniff");
                let http_alloc = self.allocator.clone();
                let cert = self.certificate.clone();
                let key = self.priv_key.clone();
                tokio::spawn(async move {
                    let mocker = HttpsSniffer::new(
                        cert,
                        key,
                        dst_domain.unwrap(),
                        DuplexChan::new(http_alloc, tun_next),
                        move || {
                            let direct =
                                DirectOutbound::new(name.as_str(), out_dst_addr, out_alloc.clone());
                            direct.as_async().0
                        },
                    );
                    if let Err(err) = mocker.run().await {
                        tracing::error!("[Dispatcher] mock HTTP failed: {}", err)
                    }
                });
            }
            _ => {
                tokio::spawn(async move {
                    let direct = DirectOutbound::new(name.as_str(), out_dst_addr, out_alloc);
                    if let Err(err) = direct.run(tun_next).await {
                        tracing::error!("[Dispatcher] create Direct failed: {}", err)
                    }
                });
            }
        }
    }
}
