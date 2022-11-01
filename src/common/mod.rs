pub mod async_raw_fd;
pub mod async_socket;
pub mod buf_slab;

pub fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}
