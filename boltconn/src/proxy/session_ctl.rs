use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum SessionCtl {
    Tcp(TcpSessionCtl),
    Udp(UdpSessionCtl),
}

#[derive(Debug, Clone)]
pub struct TcpSessionCtl {
    pub source_addr: SocketAddr,
    pub dest_addr: SocketAddr,
    pub available: Arc<AtomicU8>,
    pub last_time: Instant,
}

impl TcpSessionCtl {
    pub fn new(source_addr: SocketAddr, dest_addr: SocketAddr) -> Self {
        Self {
            source_addr,
            dest_addr,
            available: Arc::new(AtomicU8::new(2)), // inbound and outbound
            last_time: Instant::now(),
        }
    }

    pub fn is_expired(&self, threshold: time::Duration) -> bool {
        Instant::now() - self.last_time > threshold
    }

    pub fn update_time(&mut self) {
        self.last_time = Instant::now();
    }
}

#[derive(Debug, Clone)]
pub struct UdpSessionCtl {
    pub source_addr: SocketAddr,
    pub available: Arc<AtomicBool>,
    pub last_time: Instant,
}

impl UdpSessionCtl {
    pub fn new(source_addr: SocketAddr) -> Self {
        Self {
            source_addr,
            available: Arc::new(AtomicBool::new(true)),
            last_time: Instant::now(),
        }
    }

    pub fn is_expired(&self, threshold: time::Duration) -> bool {
        Instant::now() - self.last_time > threshold
    }

    pub fn invalidate(&self) {
        self.available.store(false, Ordering::Relaxed);
    }

    pub fn update_time(&mut self) {
        self.last_time = Instant::now();
    }
}
