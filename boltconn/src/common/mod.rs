use bytes::{BufMut, BytesMut};
use std::error::Error;
use std::intrinsics::transmute;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadHalf};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

pub mod async_raw_fd;
pub mod async_socket;
pub mod async_ws_stream;
pub mod client_hello;
pub mod duplex_chan;
pub mod evictable_vec;
pub mod host_matcher;
pub mod id_gen;
mod sync;

pub use sync::{local_async_run, AbortCanary};

pub fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

pub fn as_io_err<E>(err: E) -> std::io::Error
where
    E: Error,
{
    std::io::Error::new(std::io::ErrorKind::Other, err.to_string())
}

pub trait StreamOutboundTrait: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static {}

pub const MAX_PKT_SIZE: usize = 65576;

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
