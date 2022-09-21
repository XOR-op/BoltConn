use crate::outbound::DirectOutbound;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::net::TcpStream;

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
        tokio::spawn(async move {
            let mut direct = DirectOutbound::new(name.as_str(), src_addr, dst_addr, indicator);
            if let Err(err) = direct.run(stream).await {
                tracing::error!("[Dispatcher] create Direct failed: {}", err)
            }
        });
    }
}
