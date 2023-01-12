use crate::adapter::{established_tcp, established_udp, Connector, UdpSocketWrapper};
use crate::common::buf_pool::{PktBufHandle, PktBufPool};
use crate::common::io_err;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use anyhow::Result;
use sha2::{Digest, Sha224};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio_rustls::TlsConnector;

#[derive(Clone, Debug)]
pub struct TrojanConfig {
    server_addr: NetworkAddr,
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
    tls_config: Arc<ClientConfig>,
}

impl TrojanOutbound {
    pub fn new(
        iface_name: String,
        dst: NetworkAddr,
        allocator: PktBufPool,
        dns: Arc<Dns>,
        config: TrojanConfig,
    ) -> Self {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
            |ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            },
        ));
        let tls_config = Arc::new(
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth(),
        );
        Self {
            iface_name,
            dst,
            allocator,
            dns,
            config,
            tls_config,
        }
    }

    async fn run_tcp(self, mut inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        let stream = self.first_packet(&mut inbound).await?;
        established_tcp(inbound, stream, self.allocator, abort_handle).await;
        Ok(())
    }

    async fn run_udp(self, mut inbound: Connector, abort_handle: ConnAbortHandle) -> Result<()> {
        // let stream = self.first_packet(&mut inbound).await?;
        todo!();
        // established_udp(inbound, udp_socket, self.allocator, abort_handle).await;
        Ok(())
    }

    async fn first_packet(&self, inbound: &mut Connector) -> Result<TlsStream<TcpStream>> {
        let mut stream = self.connect_proxy().await?;
        let first_packet = inbound.rx.recv().await.ok_or(anyhow::anyhow!("No resp"))?;
        let trojan_req = TrojanRequest {
            password: self.config.password.clone(),
            request: TrojanReqInner {
                cmd: TrojanCmd::Connect,
                addr: TrojanAddr::from(self.dst.clone()),
            },
            payload: first_packet,
        };
        let res = stream.write_all(trojan_req.serialize().as_slice()).await;
        self.allocator.release(trojan_req.payload);
        res?;
        Ok(stream)
    }

    async fn connect_proxy(&self) -> Result<TlsStream<TcpStream>> {
        let server_addr = match self.config.server_addr {
            NetworkAddr::Raw(addr) => addr,
            NetworkAddr::DomainName {
                ref domain_name,
                port,
            } => {
                let resp = self
                    .dns
                    .genuine_lookup(domain_name.as_str())
                    .await
                    .ok_or(io_err("dns not found"))?;
                SocketAddr::new(resp, port)
            }
        };
        let server_name = ServerName::try_from(self.config.sni.as_str())?;
        let tcp_conn = match server_addr {
            SocketAddr::V4(_) => {
                Egress::new(&self.iface_name)
                    .tcpv4_stream(server_addr)
                    .await?
            }
            SocketAddr::V6(_) => {
                Egress::new(&self.iface_name)
                    .tcpv6_stream(server_addr)
                    .await?
            }
        };
        let tls_conn = TlsConnector::from(self.tls_config.clone());
        let stream = tls_conn.connect(server_name, tcp_conn).await?;
        Ok(stream)
    }
}

#[derive(Copy, Clone, Debug)]
enum TrojanCmd {
    Connect,
    Associate,
}

#[derive(Clone, Debug)]
enum TrojanAddr {
    Ipv4(SocketAddrV4),
    Domain((String, u16)),
    Ipv6(SocketAddrV6),
}

impl From<NetworkAddr> for TrojanAddr {
    fn from(addr: NetworkAddr) -> Self {
        match addr {
            NetworkAddr::Raw(addr) => match addr {
                SocketAddr::V4(v4) => Self::Ipv4(v4),
                SocketAddr::V6(v6) => Self::Ipv6(v6),
            },
            NetworkAddr::DomainName { domain_name, port } => Self::Domain((domain_name, port)),
        }
    }
}

impl Into<NetworkAddr> for TrojanAddr {
    fn into(self) -> NetworkAddr {
        match self {
            TrojanAddr::Ipv4(v4) => NetworkAddr::Raw(SocketAddr::from(v4)),
            TrojanAddr::Domain((domain_name, port)) => {
                NetworkAddr::DomainName { domain_name, port }
            }
            TrojanAddr::Ipv6(v6) => NetworkAddr::Raw(SocketAddr::from(v6)),
        }
    }
}

impl TrojanAddr {
    pub fn extend_data(&self, data: &mut Vec<u8>) {
        match &self {
            TrojanAddr::Ipv4(v4) => {
                data.push(0x01);
                data.extend(v4.ip().octets().iter());
                data.extend(v4.port().to_be_bytes().iter())
            }
            TrojanAddr::Domain((dn, port)) => {
                data.push(0x03);
                data.push(dn.as_bytes().len() as u8);
                data.extend(dn.as_bytes().iter());
                data.extend(port.to_be_bytes().iter())
            }
            TrojanAddr::Ipv6(v6) => {
                data.push(0x04);
                data.extend(v6.ip().octets().iter());
                data.extend(v6.port().to_be_bytes().iter())
            }
        }
    }

    pub fn len(&self) -> usize {
        1 + match self {
            TrojanAddr::Ipv4(_) => 4,
            TrojanAddr::Domain((dn, _)) => dn.len() + 1, // 1 byte ahead
            TrojanAddr::Ipv6(_) => 16,
        } + 2
    }
}

#[derive(Clone, Debug)]
struct TrojanReqInner {
    cmd: TrojanCmd,
    addr: TrojanAddr,
}

impl TrojanReqInner {
    pub fn extend_data(&self, data: &mut Vec<u8>) {
        data.push(match self.cmd {
            TrojanCmd::Connect => 0x01,
            TrojanCmd::Associate => 0x03,
        });
        self.addr.extend_data(data);
    }

    pub fn len(&self) -> usize {
        1 + self.addr.len()
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
    payload: PktBufHandle,
}

impl TrojanUdpPacket {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.addr.len() + 2 + 2 + self.payload.len);
        self.addr.extend_data(&mut data);
        data.extend((self.payload.len as u16).to_be_bytes());
        data.extend(CRLF.to_ne_bytes());
        data.extend(self.payload.as_ready().iter());
        data
    }
}

pub(crate) struct TrojanUdpSocket<S>
where
    S: AsyncRead + AsyncWrite,
{
    read_half: Mutex<ReadHalf<S>>,
    write_half: Mutex<WriteHalf<S>>,
}

impl<S> TrojanUdpSocket<S>
where
    S: AsyncRead + AsyncWrite,
{
    pub fn bind(stream: S) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            read_half: Mutex::new(read_half),
            write_half: Mutex::new(write_half),
        }
    }

    pub async fn send_to(&self, data: &[u8], dest: NetworkAddr) -> Result<()> {
        let dest = TrojanAddr::from(dest);
        let mut buf = Vec::with_capacity(dest.len() + 4 + data.len());
        dest.extend_data(&mut buf);
        buf.extend((data.len() as u16).to_be_bytes().iter());
        buf.extend(CRLF.to_ne_bytes());
        buf.extend(data);
        self.write_half.lock().await.write_all(data).await?;
        Ok(())
    }

    pub async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, NetworkAddr)> {
        let mut header_buf = [0u8; 256];
        let mut reader = self.read_half.lock().await;
        reader.read_exact(&mut header_buf[..1]).await?;
        // read source address
        let src_addr = match header_buf[0] {
            0x01 => {
                const IP_LEN: usize = 4;
                reader.read_exact(&mut header_buf[..IP_LEN + 2]).await?;
                let mut ip = [0u8; IP_LEN];
                ip.copy_from_slice(&header_buf[..IP_LEN]);
                let mut port = [0u8; 2];
                port.copy_from_slice(&header_buf[IP_LEN..IP_LEN + 2]);
                NetworkAddr::Raw(SocketAddr::new(
                    Ipv4Addr::from(ip).into(),
                    u16::from_be_bytes(port),
                ))
            }
            0x03 => {
                reader.read_exact(&mut header_buf[..1]).await?;
                let len = header_buf[0] as usize;
                reader.read_exact(&mut header_buf[..len]).await?;
                let domain_name = String::from_utf8_lossy(&header_buf[..len]).to_string();
                reader.read_exact(&mut header_buf[..2]).await?;
                let mut port = [0u8; 2];
                port.copy_from_slice(&header_buf[..2]);
                NetworkAddr::DomainName {
                    domain_name,
                    port: u16::from_be_bytes(port),
                }
            }
            0x04 => {
                const IP_LEN: usize = 16;
                reader.read_exact(&mut header_buf[..IP_LEN + 2]).await?;
                let mut ip = [0u8; IP_LEN];
                ip.copy_from_slice(&header_buf[..IP_LEN]);
                let mut port = [0u8; 2];
                port.copy_from_slice(&header_buf[IP_LEN..IP_LEN + 2]);
                NetworkAddr::Raw(SocketAddr::new(
                    Ipv6Addr::from(ip).into(),
                    u16::from_be_bytes(port),
                ))
            }
            _ => return Err(anyhow::anyhow!("Bad trojan udp format")),
        };

        // read payload length and skip CRLF
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        let len = u16::from_be_bytes(buf) as usize;
        reader.read_exact(&mut header_buf[..2]).await?;
        if len > buffer.len() {
            return Err(anyhow::anyhow!("Buffer too small"));
        }

        // read payload
        reader.read_exact(&mut buffer[..len]).await?;
        Ok((len, src_addr))
    }
}

#[tokio::test]
async fn test_trojan_packets() {
    let inner = TrojanReqInner {
        cmd: TrojanCmd::Connect,
        addr: TrojanAddr::Domain(("google.com".to_string(), 443)),
    };
    let pool = PktBufPool::new(10, 20);
    let mut payload = pool.obtain().await;
    payload.len = 10;
    let packet = TrojanRequest {
        password: "test".to_string(),
        request: inner.clone(),
        payload,
    };
    assert_eq!(packet.serialize().len(), (56 + 2 + 2 + 11 + 2 + 2 + 10));
    let udp_packet = TrojanUdpPacket {
        addr: inner.addr,
        payload: packet.payload,
    };
    assert_eq!(udp_packet.serialize().len(), (1 + 11 + 6 + 10));
}
