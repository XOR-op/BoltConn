use bytes::{BufMut, BytesMut};
use std::error::Error;
use std::intrinsics::transmute;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadHalf};
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use tokio_rustls::TlsConnector;

pub mod async_raw_fd;
pub mod async_socket;
pub mod async_ws_stream;
pub mod duplex_chan;
pub mod host_matcher;
pub mod id_gen;

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
    let len = read.read(unsafe { transmute(raw_buffer) }).await?;
    unsafe { buf.advance_mut(len) };
    Ok(len)
}

pub(crate) unsafe fn mut_buf(buf: &mut BytesMut) -> &mut [u8] {
    unsafe { transmute(buf.spare_capacity_mut()) }
}

pub fn create_tls_connector() -> TlsConnector {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let client_cfg = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(client_cfg))
}
