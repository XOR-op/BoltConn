use bytes::{BufMut, BytesMut};
use std::convert::Infallible;
use std::error::Error;
use std::io;
use std::mem::transmute;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadHalf};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

#[cfg(not(target_os = "windows"))]
pub mod async_raw_fd;
#[cfg(target_os = "windows")]
pub mod async_session;
#[cfg(not(target_os = "windows"))]
pub mod async_socket;
pub mod async_ws_stream;
pub mod client_hello;
pub mod duplex_chan;
pub mod evictable_vec;
pub mod host_matcher;
mod hostname_parse;
mod sync;
pub mod utils;

pub(crate) use hostname_parse::{parse_http_host, parse_tls_sni};

pub use sync::{local_async_run, AbortCanary};

pub fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::other(msg)
}

pub fn as_io_err<E>(err: E) -> std::io::Error
where
    E: Error,
{
    std::io::Error::other(err.to_string())
}

pub trait StreamOutboundTrait: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static {}

impl StreamOutboundTrait for tokio::net::TcpStream {}

#[cfg(target_os = "windows")]
impl StreamOutboundTrait for tokio::net::windows::named_pipe::NamedPipeServer {}
#[cfg(not(target_os = "windows"))]
impl StreamOutboundTrait for tokio::net::UnixStream {}

pub const MAX_PKT_SIZE: usize = 65576;
pub const MAX_UDP_PKT_SIZE: usize = 1518;

pub async fn read_to_bytes_mut(
    buf: &mut BytesMut,
    read: &mut ReadHalf<impl AsyncRead>,
) -> io::Result<usize> {
    let raw_buffer = buf.spare_capacity_mut();
    let len = read
        .read(unsafe { transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(raw_buffer) })
        .await?;
    unsafe { buf.advance_mut(len) };
    Ok(len)
}

pub(crate) unsafe fn mut_buf(buf: &mut BytesMut) -> &mut [u8] {
    unsafe { transmute(buf.spare_capacity_mut()) }
}

use tokio_rustls::rustls::client::client_hello::ClientHelloOverride;
pub fn create_tls_connector(hello_override: Option<Arc<dyn ClientHelloOverride>>) -> TlsConnector {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
    let mut client_cfg = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    if let Some(hello_override) = hello_override {
        let mut dangerous_cfg = client_cfg.dangerous();
        dangerous_cfg.set_hello_override(hello_override);
    }
    TlsConnector::from(Arc::new(client_cfg))
}

pub trait UnwrapInfallible {
    type Ok;
    fn infallible(self) -> Self::Ok;
}
impl<T> UnwrapInfallible for Result<T, Infallible> {
    type Ok = T;
    fn infallible(self) -> T {
        match self {
            Ok(val) => val,
            Err(never) => match never {},
        }
    }
}
