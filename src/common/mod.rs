pub mod async_raw_fd;
pub mod async_socket;
pub mod buf_pool;
mod duplex_chan;

pub fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}
