use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuntimeError {}

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Internal error: {0}")]
    Internal(&'static str),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ShadowSocks error: {0}")]
    ShadowSocks(&'static str),
    #[error("Socks5 error: {0}")]
    Socks5(#[from] fast_socks5::SocksError),
    #[error("Trojan error: {0}")]
    Trojan(&'static str),
    #[error("Unsupported SOCKS5 UDP fragment")]
    UnsupportedSocks5UdpFragment,
}
