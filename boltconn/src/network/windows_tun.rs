use crate::common::{async_session::AsyncSession, io_err};

use super::packet::ip::IPPkt;
use ipnet::Ipv4Net;
use std::io;

pub(super) struct TunInstance {
    session: Option<AsyncSession>,
}

impl TunInstance {
    pub fn new() -> io::Result<(Self, String)> {
        let name = "utun13";
        let module = match unsafe { wintun::load() } {
            Ok(module) => module,
            Err(_) => {
                tracing::error!("Failed to load wintun. Check if wintun.dll exists");
                return Err(io_err("Failed to load wintun.dll"));
            }
        };
        let device = wintun::Adapter::create(&module, name, "utun", None)
            .map_err(|e| io_err(format!("Failed to create wintun adapter: {}", e).as_str()))?;
        let session = device
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|_| io_err("Failed to initialize WinTun session"))?;
        Ok((
            Self {
                session: Some(AsyncSession::new(session)),
            },
            name.to_string(),
        ))
    }

    pub fn take_fd(&mut self) -> Option<AsyncSession> {
        self.session.take()
    }

    pub fn interface_up(&self, name: &str) -> io::Result<()> {
        todo!()
    }

    pub fn set_address(&self, name: &str, addr: Ipv4Net) -> io::Result<()> {
        todo!()
    }

    pub async fn send_outbound(pkt: &IPPkt, gw_name: &str, ipv6_enabled: bool) -> io::Result<()> {
        todo!()
    }
}
