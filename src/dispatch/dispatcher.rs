use crate::outbound::DirectOutbound;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::net::TcpStream;
use crate::process;

pub struct Dispatcher {
    iface_name: String,
}

impl Dispatcher {
    pub fn new(iface_name: &str) -> Self {
        Self {
            iface_name: iface_name.into(),
        }
    }

    pub fn submit_tcp(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        indicator: Arc<AtomicU8>,
        stream: TcpStream,
    ) {
        let name = self.iface_name.clone();
        let info = {
            let r = process::get_pid(src_addr, process::NetworkType::TCP);
            if let Ok(pid) = r {
                process::get_process_info(pid)
            } else {
                tracing::info!("[Dispatcher] ({} -> {}) get_pid() failed: {:?}",src_addr,dst_addr,r);
                None
            }
        };
        if let Some(info) = info {
            tracing::trace!("[Dispatcher] ({} -> {}) Name:{}, Path:{}",src_addr,dst_addr,info.name,info.path)
        }else {
            tracing::info!("[Dispatcher] ({} -> {}) get_process_info() failed",src_addr,dst_addr);
        }
        tokio::spawn(async move {
            let mut direct = DirectOutbound::new(name.as_str(), src_addr, dst_addr, indicator);
            if let Err(err) = direct.run(stream).await {
                tracing::error!("[Dispatcher] create Direct failed: {}", err)
            }
        });
    }
}
