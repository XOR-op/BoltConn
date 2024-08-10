use super::packet::ip::IPPkt;
use ipnet::Ipv4Net;
use std::io;

pub(super) struct TunInstance {}

impl TunInstance {
    pub fn new() -> io::Result<(Self, String)> {
        todo!()
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
