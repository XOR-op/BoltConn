use std::error::Error;

pub mod async_raw_fd;
pub mod async_socket;
pub mod buf_pool;
pub mod duplex_chan;

pub fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

pub fn as_io_err<E>(err: E) -> std::io::Error
where
    E: Error,
{
    std::io::Error::new(std::io::ErrorKind::Other, err.to_string())
}
