use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("Intercept error: {0}")]
    Intercept(#[from] InterceptError),
}

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Internal error: {0}")]
    Internal(&'static str),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),
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
pub enum DnsError {
    #[error("Missing bootstrap DNS server for {0}")]
    MissingBootstrap(String),
    #[error("Failed to resolve dns server: {0}")]
    ResolveServer(String),
}

#[derive(Error, Debug)]
pub enum WireGuardError {
    #[error("WireGuard BoringTun error: {0}")]
    BoringTun(&'static str),
    #[error("WireGuard error: {0}")]
    Others(&'static str),
}

#[derive(Error, Debug)]
pub enum InterceptError {
    #[error("No corresponding id: {0}")]
    NoCorrespondingId(u64),
    #[error("Wait response: {0}")]
    WaitResponse(hyper::Error),
    #[error("Invalid data")]
    InvalidData,
    #[error("Tls connect error: {0}")]
    TlsConnect(std::io::Error),
    #[error("Handshake error: {0}")]
    Handshake(hyper::Error),
    #[error("Send request error: {0}")]
    SendRequest(hyper::Error),
    #[error("Certificate error: {0}")]
    Certificate(#[from] CertificateError),
}

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("No generated private key available")]
    NoPrivateKey,
    #[error("No generated certificate available")]
    NoCert,
    #[error("RcGen error: {0}")]
    RcGen(#[from] rcgen::RcgenError),
    #[error("PemFile error: {0}")]
    PemFile(std::io::Error),
}
