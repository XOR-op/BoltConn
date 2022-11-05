use crate::adapter::{Connector, DirectOutbound, TunAdapter};
use crate::platform::process;
use crate::session::{NetworkAddr, SessionInfo};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::net::TcpStream;
use crate::PktBufPool;

pub struct Dispatcher {
    iface_name: String,
    allocator: PktBufPool,
}

impl Dispatcher {
    pub fn new(iface_name: &str, allocator: PktBufPool) -> Self {
        Self {
            iface_name: iface_name.into(),
            allocator,
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
            match dst_domain {
                Some(dn) => NetworkAddr::DomainName {
                    domain_name: dn,
                    port: dst_addr.port(),
                },
                None => NetworkAddr::Raw(dst_addr),
            },
            "direct",
        );
        let (utx, urx) = tokio::sync::mpsc::channel(10);
        let (dtx, drx) = tokio::sync::mpsc::channel(10);
        let (tun_conn, tun_alloc) = (Connector::new(utx, drx), self.allocator.clone());
        let (out_conn, out_alloc) = (Connector::new(dtx, urx), self.allocator.clone());
        let out_dst_addr = dst_addr.clone();
        tokio::spawn(async move {
            let mut tun = TunAdapter::new(src_addr, dst_addr, info, stream, indicator, tun_alloc, tun_conn);
            if let Err(err) = tun.run().await {
                tracing::error!("[Dispatcher] run TunAdapter failed: {}", err)
            }
        });
        let name = self.iface_name.clone();
        tokio::spawn(async move {
            let mut direct = DirectOutbound::new(name.as_str(), out_dst_addr, out_alloc, out_conn);
            if let Err(err) = direct.run().await {
                tracing::error!("[Dispatcher] create Direct failed: {}", err)
            }
        });
    }
}
