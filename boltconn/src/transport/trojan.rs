use crate::proxy::NetworkAddr;
use anyhow::anyhow;
use bytes::Bytes;
use sha2::{Digest, Sha224};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tokio_rustls::rustls::client::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, DigitallySignedStruct, Error, OwnedTrustAnchor, RootCertStore,
    ServerName, SignatureScheme,
};

#[derive(Clone, Debug)]
pub struct TrojanConfig {
    pub(crate) server_addr: NetworkAddr,
    pub(crate) password: String,
    pub(crate) sni: String,
    pub(crate) skip_cert_verify: bool,
    pub(crate) websocket_path: Option<String>,
    pub(crate) udp: bool,
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum TrojanCmd {
    Connect,
    Associate,
}

#[derive(Clone, Debug)]
pub(crate) enum TrojanAddr {
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

impl From<TrojanAddr> for NetworkAddr {
    fn from(t: TrojanAddr) -> Self {
        match t {
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
pub(crate) struct TrojanReqInner {
    pub(crate) cmd: TrojanCmd,
    pub(crate) addr: TrojanAddr,
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

pub(crate) struct TrojanRequest {
    pub(crate) password: String,
    pub(crate) request: TrojanReqInner,
    pub(crate) payload: Bytes,
}

const CRLF: u16 = 0x0D0A;

impl TrojanRequest {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(56 + 2 + self.request.len() + 2 + self.payload.len());
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
        data.extend(self.payload.as_ref().iter());
        data
    }
}

pub(crate) struct TrojanUdpPacket {
    addr: TrojanAddr,
    payload: Bytes,
}

impl TrojanUdpPacket {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.addr.len() + 2 + 2 + self.payload.len());
        self.addr.extend_data(&mut data);
        data.extend((self.payload.len() as u16).to_be_bytes());
        data.extend(CRLF.to_ne_bytes());
        data.extend(self.payload.as_ref().iter());
        data
    }
}

pub fn encapsule_udp_packet(data: &[u8], dest: NetworkAddr) -> Vec<u8> {
    let dest = TrojanAddr::from(dest);
    let mut buf = Vec::with_capacity(dest.len() + 4 + data.len());
    dest.extend_data(buf.as_mut());
    buf.extend((data.len() as u16).to_be_bytes().iter());
    buf.extend(CRLF.to_ne_bytes());
    buf.extend(data);
    buf
}

pub(crate) struct TrojanUdpSocket<S>
where
    S: AsyncRead + AsyncWrite + Sized,
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

    pub async fn send_to(&self, data: &[u8], dest: NetworkAddr) -> anyhow::Result<()> {
        let data = encapsule_udp_packet(data, dest);
        self.write_half
            .lock()
            .await
            .write_all(data.as_ref())
            .await?;
        Ok(())
    }

    pub async fn recv_from(&self, buffer: &mut [u8]) -> anyhow::Result<(usize, NetworkAddr)> {
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
            _ => return Err(anyhow!("Bad trojan udp format")),
        };

        // read payload length and skip CRLF
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        let len = u16::from_be_bytes(buf) as usize;
        reader.read_exact(&mut header_buf[..2]).await?;
        if len > buffer.len() {
            return Err(anyhow!("Buffer too small"));
        }

        // read payload
        reader.read_exact(&mut buffer[..len]).await?;
        Ok((len, src_addr))
    }
}

struct NoCertVerification {}

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA1,
        ]
    }

    fn request_scts(&self) -> bool {
        false
    }
}

pub(crate) fn make_tls_config(skip_cert_verify: bool) -> Arc<ClientConfig> {
    if skip_cert_verify {
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertVerification {}));
        Arc::new(config)
    } else {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        Arc::new(
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth(),
        )
    }
}

#[tokio::test]
async fn test_trojan_packets() {
    let inner = TrojanReqInner {
        cmd: TrojanCmd::Connect,
        addr: TrojanAddr::Domain(("google.com".to_string(), 443)),
    };
    let payload = Bytes::from("OKokokokok");
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
