use crate::adapter::Connector;
use crate::common::buf_pool::{PktBufHandle, PktBufPool};
use crate::network::dns::Dns;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use sha2::{Digest, Sha224};
use std::io::Result;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

#[derive(Clone, Debug)]
struct TrojanConfig {
    dest_addr: NetworkAddr,
    password: String,
    sni: String,
    skip_cert_verify: bool,
    websocket_path: Option<String>,
}

#[derive(Clone)]
pub struct TrojanOutbound {
    iface_name: String,
    dst: NetworkAddr,
    allocator: PktBufPool,
    dns: Arc<Dns>,
    config: TrojanConfig,
}

impl TrojanOutbound {
    pub fn new() -> Self {
        todo!()
    }

    async fn run_tcp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        todo!()
    }

    async fn run_udp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        todo!()
    }
}

#[derive(Copy, Clone, Debug)]
enum TrojanCmd {
    Connect,
    Associate,
}

#[derive(Clone, Debug)]
enum TrojanAddr {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

impl TrojanAddr {
    pub fn extend_data(&self, data: &mut Vec<u8>) {
        match &self {
            TrojanAddr::Ipv4(v4) => {
                data.push(0x01);
                data.extend(v4.octets().iter());
            }
            TrojanAddr::Domain(s) => {
                data.push(0x03);
                data.push(s.as_bytes().len() as u8);
                data.extend(s.as_bytes().iter());
            }
            TrojanAddr::Ipv6(v6) => {
                data.push(0x04);
                data.extend(v6.octets().iter());
            }
        }
    }

    pub fn len(&self) -> usize {
        1 + match self {
            TrojanAddr::Ipv4(_) => 4,
            TrojanAddr::Domain(ref s) => s.len() + 1, // 1 byte ahead
            TrojanAddr::Ipv6(_) => 16,
        }
    }
}

struct TrojanReqInner {
    cmd: TrojanCmd,
    addr: TrojanAddr,
    port: u16,
}

impl TrojanReqInner {
    pub fn extend_data(&self, data: &mut Vec<u8>) {
        data.push(match self.cmd {
            TrojanCmd::Connect => 0x01,
            TrojanCmd::Associate => 0x03,
        });
        self.addr.extend_data(data);
        data.extend(self.port.to_be_bytes().iter());
    }

    pub fn len(&self) -> usize {
        1 + self.addr.len() + 2
    }
}

struct TrojanRequest {
    password: String,
    request: TrojanReqInner,
    payload: PktBufHandle,
}

const CRLF: u16 = 0x0D0A;
impl TrojanRequest {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(56 + 2 + self.request.len() + 2 + self.payload.len);
        data.extend(
            Sha224::digest(self.password.as_bytes())
                .iter()
                .map(|x| format!("{:02x}", x))
                .collect::<String>()
                .as_bytes()
                .iter(),
        );
        data.extend(CRLF.to_ne_bytes());
        self.request.extend_data(&mut data);
        data.extend(CRLF.to_ne_bytes());
        data.extend(self.payload.as_ready().iter());
        data
    }
}

struct TrojanUdpPacket {
    addr: TrojanAddr,
    port: u16,
    payload: PktBufHandle,
}

impl TrojanUdpPacket {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.addr.len() + 2 + 2 + 2 + self.payload.len);
        self.addr.extend_data(&mut data);
        data.extend(self.port.to_be_bytes().iter());
        data.extend((self.payload.len as u16).to_be_bytes());
        data.extend(CRLF.to_ne_bytes());
        data.extend(self.payload.as_ready().iter());
        data
    }
}
