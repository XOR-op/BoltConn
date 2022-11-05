use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::sync::mpsc;

mod direct;
mod tun_adapter;

pub use direct::*;
pub use tun_adapter::*;
use crate::common::buf_slab::PktBufHandle;

pub struct TcpStatus {
    src: SocketAddr,
    dst: SocketAddr,
    available: Arc<AtomicU8>,
}

impl TcpStatus {
    pub fn new(src: SocketAddr, dst: SocketAddr, available: Arc<AtomicU8>) -> Self {
        Self {
            src,
            dst,
            available,
        }
    }
}

pub struct Connector {
    pub tx: mpsc::Sender<PktBufHandle>,
    pub rx: mpsc::Receiver<PktBufHandle>,
}

impl Connector {
    pub fn new(tx: mpsc::Sender<PktBufHandle>,rx: mpsc::Receiver<PktBufHandle>)->Self{
        Self{
            tx,
            rx
        }
    }
}

pub enum Outbound {
    Direct(DirectOutbound),
}
