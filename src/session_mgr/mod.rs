use std::net::IpAddr;
use std::time;
use std::time::Instant;

mod session;
mod manager;

#[derive(Debug, Clone)]
pub enum Session {
    TCP(TcpSession),
    UDP(UdpSession),
}

#[derive(Debug, Clone)]
pub struct TcpSession {
    source_addr: IpAddr,
    source_port: u16,
    dest_addr: IpAddr,
    dest_port: u16,
    last_time: Instant,
    // todo add some statistics
}

impl TcpSession {
    pub fn new(source_addr: IpAddr, source_port: u16, dest_addr: IpAddr, dest_port: u16) -> Self {
        Self {
            source_addr,
            source_port,
            dest_addr,
            dest_port,
            last_time: Instant::now(),
        }
    }

    pub fn is_expired(&self, threshold: time::Duration) -> bool {
        Instant.now() - self.last_time < threshold
    }

    pub fn update_time(&mut self) {
        self.last_time = Instant::now();
    }
}

#[derive(Debug, Clone)]
pub struct UdpSession {
    internal_port: u16,
    iface_port: u16,
    last_time: Instant,
    // todo add some statistics
}

impl UdpSession {
    pub fn new(internal_port: u16, iface_port: u16) -> Self {
        Self {
            internal_port,
            iface_port,
            last_time: Instant::now(),
        }
    }

    pub fn is_expired(&self, threshold: time::Duration) -> bool {
        Instant.now() - self.last_time < threshold
    }

    pub fn update_time(&mut self) {
        self.last_time = Instant::now();
    }
}


