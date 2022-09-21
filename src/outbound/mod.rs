use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::Arc;

mod direct;

pub use direct::*;

pub struct TcpConnection {
    src: SocketAddr,
    dst: SocketAddr,
    available: Arc<AtomicU8>,
}

impl TcpConnection {
    pub fn new(src: SocketAddr, dst: SocketAddr, available: Arc<AtomicU8>) -> Self {
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
