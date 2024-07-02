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
    #[error("HTTP proxy error: {0}")]
    Http(&'static str),
    #[error("Socks5 error: {0}")]
    Socks5(#[from] fast_socks5::SocksError),
    #[error("Socks5 error: {0}")]
    Socks5Extra(&'static str),
    #[error("Trojan error: {0}")]
    Trojan(&'static str),
    #[error("WireGuard error: {0}")]
    WireGuard(#[from] WireGuardError),
}

#[derive(Error, Debug)]
pub enum WireGuardError {
    #[error("WireGuard BoringTun error: {0}")]
    BoringTun(&'static str),
    #[error("WireGuard error: {0}")]
    Others(&'static str),
}
