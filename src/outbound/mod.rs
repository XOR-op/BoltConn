use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

mod direct;

pub use direct::*;

pub struct TcpConnection {
    src: SocketAddr,
    dst: SocketAddr,
    available: Arc<AtomicBool>,
}

impl TcpConnection {
    pub fn new(src: SocketAddr, dst: SocketAddr, available: Arc<AtomicBool>) -> Self {
        Self {
            src,
            dst,
            available,
        }
    }
}

pub enum Outbound {
    Direct(DirectOutbound),
}
