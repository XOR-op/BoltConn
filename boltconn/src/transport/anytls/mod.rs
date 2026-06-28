use crate::proxy::NetworkAddr;
use crate::proxy::error::TransportError;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

mod client;
mod padding;
mod session;
mod stream;

#[allow(unused_imports)]
pub use client::AnytlsClient;
pub use padding::PaddingScheme;
pub use session::AnytlsSession;
pub use stream::AnytlsStream;

pub const UDP_OVER_TCP_DOMAIN: &str = "sp.v2.udp-over-tcp.arpa";
pub(super) const DEFAULT_IDLE_SESSION_CHECK_INTERVAL: Duration = Duration::from_secs(30);
pub(super) const DEFAULT_IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
pub(super) const DEFAULT_MIN_IDLE_SESSION: usize = 0;
pub(super) const DEFAULT_SYNACK_TIMEOUT: Duration = Duration::from_secs(3);

const DEFAULT_CLIENT_NAME: &str = "sing-anytls/0.0.11";

pub(super) const HEADER_LEN: usize = 1 + 4 + 2;
pub(super) const MAX_FRAME_DATA_LEN: usize = u16::MAX as usize;
pub(super) const PROTOCOL_VERSION: u8 = 2;

#[derive(Clone, Debug)]
pub struct AnytlsConfig {
    pub(crate) server_addr: NetworkAddr,
    pub(crate) password: String,
    pub(crate) sni: String,
    pub(crate) skip_cert_verify: bool,
    pub(crate) idle_session_check_interval: Duration,
    pub(crate) idle_session_timeout: Duration,
    pub(crate) min_idle_session: usize,
    pub(crate) client_name: String,
}

impl AnytlsConfig {
    pub fn new(
        server_addr: NetworkAddr,
        password: impl Into<String>,
        sni: impl Into<String>,
        skip_cert_verify: bool,
    ) -> Self {
        Self {
            server_addr,
            password: password.into(),
            sni: sni.into(),
            skip_cert_verify,
            idle_session_check_interval: DEFAULT_IDLE_SESSION_CHECK_INTERVAL,
            idle_session_timeout: DEFAULT_IDLE_SESSION_TIMEOUT,
            min_idle_session: DEFAULT_MIN_IDLE_SESSION,
            client_name: DEFAULT_CLIENT_NAME.to_string(),
        }
    }

    pub fn session_options(&self) -> AnytlsSessionOptions {
        AnytlsSessionOptions::with_client_name(&self.password, &self.client_name)
    }
}

#[derive(Clone, Debug)]
pub struct AnytlsSessionOptions {
    pub(super) password: String,
    pub(super) client_name: String,
    padding_scheme: Arc<Mutex<PaddingScheme>>,
}

impl AnytlsSessionOptions {
    pub fn new(password: impl Into<String>) -> Self {
        Self::with_client_name(password, DEFAULT_CLIENT_NAME)
    }

    pub fn with_client_name(password: impl Into<String>, client_name: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            client_name: client_name.into(),
            padding_scheme: Arc::new(Mutex::new(PaddingScheme::default())),
        }
    }

    pub fn current_padding_scheme(&self) -> PaddingScheme {
        lock_mutex(&self.padding_scheme).clone()
    }

    pub fn update_padding_scheme(&self, raw_scheme: &[u8]) -> Result<(), TransportError> {
        let scheme = PaddingScheme::parse(raw_scheme)?;
        *lock_mutex(&self.padding_scheme) = scheme;
        Ok(())
    }

    pub(super) fn padding_store(&self) -> Arc<Mutex<PaddingScheme>> {
        Arc::clone(&self.padding_scheme)
    }
}

impl From<&AnytlsConfig> for AnytlsSessionOptions {
    fn from(value: &AnytlsConfig) -> Self {
        value.session_options()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Command {
    Waste,
    Syn,
    Psh,
    Fin,
    Settings,
    Alert,
    UpdatePaddingScheme,
    SynAck,
    HeartRequest,
    HeartResponse,
    ServerSettings,
    Unknown(u8),
}

impl Command {
    fn from_wire(value: u8) -> Self {
        match value {
            0 => Self::Waste,
            1 => Self::Syn,
            2 => Self::Psh,
            3 => Self::Fin,
            4 => Self::Settings,
            5 => Self::Alert,
            6 => Self::UpdatePaddingScheme,
            7 => Self::SynAck,
            8 => Self::HeartRequest,
            9 => Self::HeartResponse,
            10 => Self::ServerSettings,
            value => Self::Unknown(value),
        }
    }

    pub(super) fn wire_value(self) -> u8 {
        match self {
            Self::Waste => 0,
            Self::Syn => 1,
            Self::Psh => 2,
            Self::Fin => 3,
            Self::Settings => 4,
            Self::Alert => 5,
            Self::UpdatePaddingScheme => 6,
            Self::SynAck => 7,
            Self::HeartRequest => 8,
            Self::HeartResponse => 9,
            Self::ServerSettings => 10,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct FrameWrite {
    pub(super) command: Command,
    pub(super) stream_id: u32,
    pub(super) data: Bytes,
}

#[derive(Debug)]
pub(super) struct FrameRead {
    pub(super) command: Command,
    pub(super) stream_id: u32,
    pub(super) data: Bytes,
}

pub(super) async fn read_frame<R>(reader: &mut R) -> Result<FrameRead, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let command = Command::from_wire(header[0]);
    let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let data_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0u8; data_len];
    if data_len > 0 {
        reader.read_exact(&mut data).await?;
    }
    Ok(FrameRead {
        command,
        stream_id,
        data: Bytes::from(data),
    })
}

pub(super) fn append_frame(
    packet: &mut Vec<u8>,
    command: Command,
    stream_id: u32,
    data: &[u8],
) -> Result<(), TransportError> {
    let data_len = u16::try_from(data.len())
        .map_err(|_| TransportError::Internal("AnyTLS frame exceeded u16::MAX"))?;
    packet.push(command.wire_value());
    packet.extend(stream_id.to_be_bytes());
    packet.extend(data_len.to_be_bytes());
    packet.extend(data);
    Ok(())
}

pub(super) fn settings_payload(client_name: &str, padding_md5: &str) -> Bytes {
    Bytes::from(format!(
        "v={PROTOCOL_VERSION}\nclient={client_name}\npadding-md5={padding_md5}"
    ))
}

pub(super) fn parse_settings(data: &[u8]) -> HashMap<String, String> {
    let Ok(text) = std::str::from_utf8(data) else {
        return HashMap::new();
    };
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

pub fn encode_socks_addr(addr: &NetworkAddr) -> Result<Vec<u8>, TransportError> {
    let mut data = Vec::new();
    match addr {
        NetworkAddr::Raw(socket_addr) => match socket_addr {
            std::net::SocketAddr::V4(v4) => {
                data.reserve(1 + 4 + 2);
                data.push(0x01);
                data.extend(v4.ip().octets());
                data.extend(v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                data.reserve(1 + 16 + 2);
                data.push(0x04);
                data.extend(v6.ip().octets());
                data.extend(v6.port().to_be_bytes());
            }
        },
        NetworkAddr::DomainName { domain_name, port } => {
            let domain_len = u8::try_from(domain_name.len())
                .map_err(|_| TransportError::Internal("AnyTLS domain name too long"))?;
            data.reserve(1 + 1 + domain_name.len() + 2);
            data.push(0x03);
            data.push(domain_len);
            data.extend(domain_name.as_bytes());
            data.extend(port.to_be_bytes());
        }
    }
    Ok(data)
}

pub(super) fn lock_mutex<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use tokio::io::AsyncWriteExt;

    #[test]
    fn encodes_socks_addr() {
        let addr = NetworkAddr::Raw(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            443,
        )));
        assert_eq!(
            encode_socks_addr(&addr).unwrap(),
            vec![0x01, 127, 0, 0, 1, 0x01, 0xbb]
        );

        let addr = NetworkAddr::DomainName {
            domain_name: "example.com".to_string(),
            port: 80,
        };
        assert_eq!(
            encode_socks_addr(&addr).unwrap(),
            b"\x03\x0bexample.com\x00\x50".to_vec()
        );
    }

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let mut packet = Vec::new();
        append_frame(&mut packet, Command::Psh, 7, b"hello").unwrap();
        client.write_all(&packet).await.unwrap();

        let frame = read_frame(&mut server).await.unwrap();
        assert_eq!(frame.command, Command::Psh);
        assert_eq!(frame.stream_id, 7);
        assert_eq!(&frame.data[..], b"hello");
    }
}
