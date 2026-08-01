use crate::config::SourceLocation;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("File error: {0}")]
    File(#[from] FileError),
    #[error("DNS error: {0}")]
    Dns(#[from] DnsConfigError),
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
    #[error("Instrument error: {0}")]
    Instrument(#[from] InstrumentConfigError),
    #[error("Interception error: {0}")]
    Intercept(#[from] InterceptConfigError),
    #[error("Configuration composition error: {0}")]
    Composition(#[source] Box<CompositionError>),
    #[error("{location}: {error}")]
    AtSource {
        location: SourceLocation,
        error: Box<ConfigError>,
    },
    #[error("Internal error: {0}")]
    Internal(&'static str),
}

impl ConfigError {
    pub fn at(self, location: SourceLocation) -> Self {
        Self::AtSource {
            location,
            error: Box::new(self),
        }
    }
}

impl From<CompositionError> for ConfigError {
    fn from(error: CompositionError) -> Self {
        Self::Composition(Box::new(error))
    }
}

#[derive(Error, Debug)]
pub enum CompositionError {
    #[error("Unknown module {name:?} referenced from {location}")]
    MissingModule {
        name: String,
        location: SourceLocation,
    },
    #[error("Module {name:?} is referenced more than once in {section}")]
    DuplicateModuleReference { name: String, section: &'static str },
    #[error("Duplicate {kind} {name:?}: first defined at {first}, then at {second}")]
    DuplicateDefinition {
        kind: &'static str,
        name: String,
        first: SourceLocation,
        second: SourceLocation,
    },
    #[error("Include cycle: {0}")]
    IncludeCycle(String),
    #[error("Include path {path:?} from {location} is outside the configuration root")]
    PathEscape {
        path: String,
        location: SourceLocation,
    },
    #[error("Top-level FALLBACK is only allowed directly in root rules ({0})")]
    FallbackOutsideRoot(SourceLocation),
}

#[derive(Error, Debug)]
pub enum InstrumentConfigError {
    #[error("Bad template {0}: {1}")]
    BadTemplate(String, String),
    #[error("Invalid request route: {0}")]
    BadRequestRoute(String),
}

#[derive(Error, Debug)]
pub enum InterceptConfigError {
    #[error("Unknown rule: {0}")]
    UnknownRule(String),
    #[error("Bad url rule: {0}")]
    BadUrl(String),
    #[error("Bad header rule: {0}")]
    BadHeader(String),
}

#[derive(Error, Debug)]
pub enum DnsConfigError {
    #[error("Invalid DNS: {0}")]
    Invalid(String),
    #[error("Invalid DNS type: {0}")]
    InvalidType(String),
    #[error("Invalid DNS preset for {0}: {1}")]
    InvalidPreset(&'static str, String),
    #[error("Runtime error for configuration: {0}")]
    ResolveRuntimeInfo(#[from] crate::proxy::error::DnsError),
}

#[derive(Error, Debug)]
pub enum FileError {
    #[error("{0} io error: {1}")]
    Io(String, std::io::Error),
    #[error("{0} deserialization error: {1}")]
    Serde(String, serde_yaml::Error),
    #[error("{0} serialization error: {1}")]
    Http(String, reqwest::Error),
    #[error("Env variable error: {0}")]
    Env(#[from] std::env::VarError),
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
    #[error("Provider {0} has unsupported format: {1}")]
    UnsupportedFormat(String, &'static str),
    #[error("Provider {0} has bad filter: {1}")]
    BadFilter(String, String),
}

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Duplicate group name: {0}")]
    DuplicateGroup(String),
    #[error("Duplicate proxy name: {0}")]
    DuplicateProxy(String),
    #[error("Duplicate chain name: {0}")]
    DuplicateChain(String),
    #[error("Missing group: {0}")]
    MissingGroup(String),
    #[error("Missing proxy: {0}")]
    MissingProxy(String),
    #[error("Invalid proxy: {0}")]
    Invalid(String),
    #[error("Invalid chain: {0}")]
    InvalidChain(String),
    #[error("Invalid Shadowsocks cipher {0} in proxy {1}")]
    ShadowsocksCipher(String, String),
    #[error("Proxy {0} error: {1}")]
    ProxyFieldError(String, &'static str),
    #[error("Unknown proxy {proxy} in group {group}")]
    UnknownProxyInGroup { proxy: String, group: String },
    #[error("Duplicate proxy {proxy} in group {group}")]
    DuplicateProxyInGroup { proxy: String, group: String },
}
