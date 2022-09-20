use crate::outbound::DirectOutbound;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
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
        indicator: Arc<AtomicBool>,
        stream: TcpStream,
    ) {
        let mut direct =
            DirectOutbound::new(self.iface_name.as_str(), src_addr, dst_addr, indicator);
        tokio::spawn(async move { direct.run(stream) });
    }
}
