use std::error::Error;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod async_raw_fd;
pub mod async_socket;
pub mod async_ws_stream;
pub mod buf_pool;
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

pub trait OutboundTrait: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static {}
