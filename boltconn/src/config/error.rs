use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("File error: {0}")]
    File(#[from] FileError),
    #[error("DNS")]
    Dns,
    #[error("Rule error: {0}")]
    Rule(#[from] RuleError),
    #[error("Proxy error: {0}")]
    Proxy(#[from] ProxyError),
    #[error("Provider error: {0}")]
    Provider(#[from] ProviderError),
    #[error("Runtime task join error: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),
    #[error("Script error: {0}")]
    Script(#[from] ScriptError),
}

#[derive(Error, Debug)]
pub enum FileError {
    #[error("{0} io error: {1}")]
    Io(String, std::io::Error),
    #[error("{0} deserialization error: {1}")]
    Serde(String, serde_yaml::Error),
    #[error("{0} serialization error: {1}")]
    Http(String, reqwest::Error),
}

#[derive(Error, Debug)]
pub enum ScriptError {
    #[error("Script {0}: invalid type {1}")]
    InvalidType(String, String),
    #[error("Script {0} invalid filter {1}")]
    InvalidFilter(String, String),
}

#[derive(Error, Debug)]
pub enum RuleError {
    #[error("Missing fallback rule")]
    MissingFallback,
    #[error("Invalid rule: {0}")]
    Invalid(String),
    #[error("Ruleset {0} exceeded limit")]
    RulesetExceededLimit(String),
}

#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("Missing provider: {0}")]
    Missing(String),
    #[error("Invalid provider: {0}")]
    Invalid(String),
    #[error("Provider {0} has bad filter: {1}")]
    BadFilter(String, String),
}

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Duplicate group name: {0}")]
    DuplicateGroup(String),
    #[error("Duplicate proxy name: {0}")]
    DuplicateProxy(String),
    #[error("Missing group: {0}")]
    MissingGroup(String),
    #[error("Missing proxy: {0}")]
    MissingProxy(String),
    #[error("Invalid proxy: {0}")]
    Invalid(String),
    #[error("Invalid Shadowsocks cipher {0} in proxy {1}")]
    ShadowsocksCipher(String, String),
    #[error("Proxy {0} error: {1}")]
    ProxyFieldError(String, &'static str),
    #[error("Unknown proxy {proxy} in group {group}")]
    UnknownProxyInGroup { proxy: String, group: String },
}
