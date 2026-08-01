#[allow(clippy::module_inception)]
mod config;
mod error;
mod file_path;
mod inbound;
mod interception;
mod module;
mod proxy_chain;
mod proxy_group;
mod proxy_provider;
mod rule;
mod rule_provider;
mod source;
mod state;

use crate::platform::get_user_info;
pub use config::*;
pub use error::*;
pub(crate) use file_path::*;
pub use inbound::*;
pub use interception::*;
pub use module::*;
pub use proxy_chain::*;
pub use proxy_group::*;
pub use proxy_provider::*;
pub use rule::*;
pub use rule_provider::*;
use serde::{Deserialize, Serialize};
pub use source::*;
pub use state::*;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, io};

pub fn safe_join_path(root: &Path, file_path: &str) -> io::Result<PathBuf> {
    let file_path = if file_path.starts_with('/') {
        PathBuf::from_str(file_path).unwrap()
    } else {
        root.join(file_path)
    };
    // we use parent path in order to ensure fs::canonicalize does not return Err
    let file_folder_path = file_path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?
        .canonicalize()?;
    if file_folder_path.starts_with(root.canonicalize()?) {
        Ok(file_path)
    } else {
        Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
    }
}

#[derive(Debug)]
pub struct LoadedConfig {
    pub config: ResolvedRootCfg,
    pub state: RawState,
    pub rule_schema: HashMap<String, RuleSchema>,
    pub proxy_schema: HashMap<String, ProxySchema>,
    pub rule_provider_sources: HashMap<String, SourceLocation>,
}

impl LoadedConfig {
    pub fn state_path(app_data_path: &Path) -> PathBuf {
        app_data_path.join("state.yml")
    }

    pub async fn load_config(config_path: &Path, data_path: &Path) -> Result<Self, ConfigError> {
        let state_text = fs::read_to_string(Self::state_path(data_path))
            .map_err(|e| FileError::Io("state.yml".to_string(), e))?;
        let raw_state: RawState = serde_yaml::from_str(&state_text)
            .map_err(|e| FileError::Serde("state.yml".to_string(), e))?;
        Self::load_with_state(config_path, raw_state).await
    }

    /// Load configuration without requiring runtime state or certificates.
    pub async fn load_config_only(config_path: &Path) -> Result<Self, ConfigError> {
        Self::load_with_state(config_path, RawState::default()).await
    }

    async fn load_with_state(config_path: &Path, state: RawState) -> Result<Self, ConfigError> {
        // Normalize once at the loading boundary. All source paths below share
        // this base, avoiding a filesystem canonicalization for every rule.
        let config_path = config_path
            .canonicalize()
            .map_err(|error| FileError::Io(config_path.display().to_string(), error))?;
        let config_file = config_path.join("config.yml");
        let config_text = fs::read_to_string(&config_file)
            .map_err(|error| FileError::Io("config.yml".to_string(), error))?;
        let raw_config: RawRootCfg = serde_yaml::from_str(&config_text)
            .map_err(|error| FileError::Serde("config.yml".to_string(), error))?;

        let (config, rule_provider_sources) =
            resolve_config(&config_path, &config_file, raw_config).await?;

        let (rule_schema, proxy_schema) = tokio::try_join!(
            read_rule_schema(
                &config_path,
                &config.rule_providers,
                &rule_provider_sources,
                false
            ),
            read_proxy_schema(&config_path, &config.proxy_provider, false),
        )?;
        Ok(Self {
            config,
            state,
            rule_schema,
            proxy_schema,
            rule_provider_sources,
        })
    }

    pub fn explain(&self) -> String {
        let mut output = String::from("Rules:\n");
        for (index, rule) in self.config.rules.iter().enumerate() {
            output.push_str(&format!(
                "  {index:>4}  {:<36} {}\n",
                rule.source_chain(),
                format_rule_line(&rule.value)
            ));
        }

        output.push_str("Interception:\n");
        for (index, entry) in self.config.interception.iter().enumerate() {
            let name = entry.value.name.as_deref().unwrap_or("<unnamed>");
            output.push_str(&format!(
                "  {index:>4}  {:<36} {name}\n",
                entry.source_chain()
            ));
        }

        output.push_str("Rule providers:\n");
        let mut names: Vec<&String> = self.rule_provider_sources.keys().collect();
        names.sort();
        for name in names {
            output.push_str(&format!(
                "        {:<36} {}\n",
                self.rule_provider_sources
                    .get(name)
                    .expect("provider name came from the same map"),
                name
            ));
        }
        output
    }
}

#[derive(Debug, Clone)]
struct ResolvedModule {
    rules: Vec<Sourced<RuleConfigLine>>,
    interception: Vec<Sourced<InterceptionConfig>>,
    rule_providers: HashMap<String, Sourced<RuleProvider>>,
}

async fn resolve_config(
    config_path: &Path,
    config_file: &Path,
    mut raw_config: RawRootCfg,
) -> Result<(ResolvedRootCfg, HashMap<String, SourceLocation>), ConfigError> {
    let loaded_modules = read_module_documents(config_path, &raw_config.modules, false).await?;
    let resolved_modules = resolve_modules(config_path, loaded_modules)?;

    let mut providers = HashMap::new();
    let mut provider_sources = HashMap::new();
    let root_providers = std::mem::take(&mut raw_config.rule_providers);
    insert_rule_providers(
        config_path,
        config_file,
        root_providers,
        &mut providers,
        &mut provider_sources,
    )?;

    let mut module_names: Vec<&String> = resolved_modules.keys().collect();
    module_names.sort();
    for module_name in module_names {
        let module = resolved_modules
            .get(module_name)
            .expect("module name came from the same map");
        for (name, sourced_provider) in &module.rule_providers {
            if let Some(first) = provider_sources.get(name) {
                return Err(CompositionError::DuplicateDefinition {
                    kind: "rule provider",
                    name: name.clone(),
                    first: first.clone(),
                    second: sourced_provider.source.clone(),
                }
                .into());
            }
            providers.insert(name.clone(), sourced_provider.value.clone());
            provider_sources.insert(name.clone(), sourced_provider.source.clone());
        }
    }

    let root_rules = std::mem::take(&mut raw_config.rules);
    let root_interception = std::mem::take(&mut raw_config.interception);
    let rules = expand_root_rules(config_path, config_file, root_rules, &resolved_modules)?;
    validate_root_fallback(&rules)?;
    let interception = expand_root_interception(
        config_path,
        config_file,
        root_interception,
        &resolved_modules,
    )?;

    Ok((
        raw_config.into_resolved(rules, providers, interception),
        provider_sources,
    ))
}

fn resolve_modules(
    config_path: &Path,
    loaded_modules: HashMap<String, LoadedModuleDocument>,
) -> Result<HashMap<String, ResolvedModule>, ConfigError> {
    let mut resolved = HashMap::with_capacity(loaded_modules.len());
    for (name, loaded) in loaded_modules {
        let source_path = loaded.source_path;
        let mut include_stack = vec![canonicalize_source(&source_path)?];
        let rules = expand_fragment_entries(
            config_path,
            &source_path,
            "rules",
            loaded.document.rules,
            &mut include_stack,
            reject_fragment_fallback,
        )?;
        let interception = expand_fragment_entries(
            config_path,
            &source_path,
            "interception",
            loaded.document.interception,
            &mut include_stack,
            allow_fragment_item,
        )?;

        let mut rule_providers = HashMap::new();
        for (provider_name, provider) in loaded.document.rule_providers {
            let source = SourceLocation::new(
                config_path,
                &source_path,
                format!("rule-providers.{provider_name}"),
            );
            let provider = rebase_rule_provider(config_path, &source_path, provider, &source)?;
            rule_providers.insert(provider_name, Sourced::new(provider, source));
        }
        resolved.insert(
            name,
            ResolvedModule {
                rules,
                interception,
                rule_providers,
            },
        );
    }
    Ok(resolved)
}

fn insert_rule_providers(
    config_path: &Path,
    source_path: &Path,
    raw_providers: HashMap<String, RuleProvider>,
    providers: &mut HashMap<String, RuleProvider>,
    sources: &mut HashMap<String, SourceLocation>,
) -> Result<(), ConfigError> {
    for (name, provider) in raw_providers {
        let source =
            SourceLocation::new(config_path, source_path, format!("rule-providers.{name}"));
        let provider = rebase_rule_provider(config_path, source_path, provider, &source)?;
        if let Some(first) = sources.get(&name) {
            return Err(CompositionError::DuplicateDefinition {
                kind: "rule provider",
                name,
                first: first.clone(),
                second: source,
            }
            .into());
        }
        providers.insert(name.clone(), provider);
        sources.insert(name, source);
    }
    Ok(())
}

fn expand_root_rules(
    config_path: &Path,
    source_path: &Path,
    entries: Vec<RootSequenceEntry<RuleConfigLine>>,
    modules: &HashMap<String, ResolvedModule>,
) -> Result<Vec<Sourced<RuleConfigLine>>, ConfigError> {
    let mut expanded = Vec::new();
    let mut referenced_modules = HashSet::new();
    let mut include_stack = vec![canonicalize_source(source_path)?];

    for (index, entry) in entries.into_iter().enumerate() {
        let source = SourceLocation::new(config_path, source_path, format!("rules[{index}]"));
        match entry {
            RootSequenceEntry::Item(rule) => expanded.push(Sourced::new(rule, source)),
            RootSequenceEntry::Include(include) => expanded.extend(expand_include(
                config_path,
                source_path,
                "rules",
                include,
                source,
                &mut include_stack,
                reject_fragment_fallback,
            )?),
            RootSequenceEntry::Module(module) => {
                if !referenced_modules.insert(module.module.clone()) {
                    return Err(CompositionError::DuplicateModuleReference {
                        name: module.module,
                        section: "rules",
                    }
                    .into());
                }
                let content =
                    modules
                        .get(&module.module)
                        .ok_or_else(|| CompositionError::MissingModule {
                            name: module.module.clone(),
                            location: source.clone(),
                        })?;
                let mut module_rules = content.rules.clone();
                for rule in &mut module_rules {
                    rule.prepend_expansion(source.clone());
                }
                expanded.extend(module_rules);
            }
        }
    }
    Ok(expanded)
}

fn expand_root_interception(
    config_path: &Path,
    source_path: &Path,
    entries: Vec<RootSequenceEntry<InterceptionConfig>>,
    modules: &HashMap<String, ResolvedModule>,
) -> Result<Vec<Sourced<InterceptionConfig>>, ConfigError> {
    let mut expanded = Vec::new();
    let mut referenced_modules = HashSet::new();
    let mut include_stack = vec![canonicalize_source(source_path)?];

    for (index, entry) in entries.into_iter().enumerate() {
        let source =
            SourceLocation::new(config_path, source_path, format!("interception[{index}]"));
        match entry {
            RootSequenceEntry::Item(item) => expanded.push(Sourced::new(item, source)),
            RootSequenceEntry::Include(include) => expanded.extend(expand_include(
                config_path,
                source_path,
                "interception",
                include,
                source,
                &mut include_stack,
                allow_fragment_item,
            )?),
            RootSequenceEntry::Module(module) => {
                if !referenced_modules.insert(module.module.clone()) {
                    return Err(CompositionError::DuplicateModuleReference {
                        name: module.module,
                        section: "interception",
                    }
                    .into());
                }
                let content =
                    modules
                        .get(&module.module)
                        .ok_or_else(|| CompositionError::MissingModule {
                            name: module.module.clone(),
                            location: source.clone(),
                        })?;
                let mut module_entries = content.interception.clone();
                for entry in &mut module_entries {
                    entry.prepend_expansion(source.clone());
                }
                expanded.extend(module_entries);
            }
        }
    }
    Ok(expanded)
}

fn expand_fragment_entries<T, V>(
    config_path: &Path,
    source_path: &Path,
    section: &'static str,
    entries: Vec<FragmentSequenceEntry<T>>,
    include_stack: &mut Vec<PathBuf>,
    validate: V,
) -> Result<Vec<Sourced<T>>, ConfigError>
where
    T: serde::de::DeserializeOwned,
    V: Fn(&T, &SourceLocation) -> Result<(), ConfigError> + Copy,
{
    let mut expanded = Vec::new();
    for (index, entry) in entries.into_iter().enumerate() {
        let source = SourceLocation::new(config_path, source_path, format!("{section}[{index}]"));
        match entry {
            FragmentSequenceEntry::Item(item) => {
                validate(&item, &source)?;
                expanded.push(Sourced::new(item, source));
            }
            FragmentSequenceEntry::Include(include) => expanded.extend(expand_include(
                config_path,
                source_path,
                section,
                include,
                source,
                include_stack,
                validate,
            )?),
        }
    }
    Ok(expanded)
}

fn expand_include<T, V>(
    config_path: &Path,
    including_path: &Path,
    section: &'static str,
    include: IncludeEntry,
    include_source: SourceLocation,
    include_stack: &mut Vec<PathBuf>,
    validate: V,
) -> Result<Vec<Sourced<T>>, ConfigError>
where
    T: serde::de::DeserializeOwned,
    V: Fn(&T, &SourceLocation) -> Result<(), ConfigError> + Copy,
{
    let include_path = resolve_include_path(
        config_path,
        including_path,
        &include.include,
        &include_source,
    )?;
    if let Some(cycle_start) = include_stack.iter().position(|path| path == &include_path) {
        let canonical_root = config_path.canonicalize().ok();
        let chain = include_stack[cycle_start..]
            .iter()
            .chain(std::iter::once(&include_path))
            .map(|path| {
                canonical_root
                    .as_deref()
                    .and_then(|root| path.strip_prefix(root).ok())
                    .unwrap_or(path)
                    .display()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(" -> ");
        return Err(CompositionError::IncludeCycle(chain).into());
    }

    let display_path = include_path
        .strip_prefix(config_path)
        .unwrap_or(&include_path)
        .display()
        .to_string();
    let text = fs::read_to_string(&include_path)
        .map_err(|error| FileError::Io(display_path.clone(), error))?;
    let entries: Vec<FragmentSequenceEntry<T>> =
        serde_yaml::from_str(&text).map_err(|error| FileError::Serde(display_path, error))?;

    include_stack.push(include_path.clone());
    let result = expand_fragment_entries(
        config_path,
        &include_path,
        section,
        entries,
        include_stack,
        validate,
    );
    include_stack.pop();
    result.map(|mut entries| {
        for entry in &mut entries {
            entry.prepend_expansion(include_source.clone());
        }
        entries
    })
}

fn resolve_include_path(
    config_path: &Path,
    including_path: &Path,
    include: &Path,
    source: &SourceLocation,
) -> Result<PathBuf, ConfigError> {
    if include.is_absolute() {
        return Err(CompositionError::PathEscape {
            path: include.display().to_string(),
            location: source.clone(),
        }
        .into());
    }
    let base = including_path.parent().ok_or_else(|| {
        FileError::Io(
            including_path.display().to_string(),
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;
    let target = base
        .join(include)
        .canonicalize()
        .map_err(|error| FileError::Io(base.join(include).display().to_string(), error))?;
    let root = config_path
        .canonicalize()
        .map_err(|error| FileError::Io(config_path.display().to_string(), error))?;
    if !target.starts_with(root) {
        return Err(CompositionError::PathEscape {
            path: include.display().to_string(),
            location: source.clone(),
        }
        .into());
    }
    Ok(target)
}

fn canonicalize_source(path: &Path) -> Result<PathBuf, ConfigError> {
    path.canonicalize()
        .map_err(|error| FileError::Io(path.display().to_string(), error).into())
}

fn rebase_rule_provider(
    config_path: &Path,
    source_path: &Path,
    mut provider: RuleProvider,
    source: &SourceLocation,
) -> Result<RuleProvider, ConfigError> {
    let path = match &mut provider.location {
        RuleLocation::File { path } | RuleLocation::Http { path, .. } => path,
    };
    let declared = Path::new(path);
    if declared.is_absolute() {
        return Err(CompositionError::PathEscape {
            path: path.clone(),
            location: source.clone(),
        }
        .into());
    }
    let base = source_path.parent().unwrap_or(config_path);
    let rebased = base.join(declared);
    let parent = rebased.parent().ok_or_else(|| {
        FileError::Io(
            rebased.display().to_string(),
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|error| FileError::Io(parent.display().to_string(), error))?;
    let canonical_root = config_path
        .canonicalize()
        .map_err(|error| FileError::Io(config_path.display().to_string(), error))?;
    if !canonical_parent.starts_with(canonical_root) {
        return Err(CompositionError::PathEscape {
            path: path.clone(),
            location: source.clone(),
        }
        .into());
    }
    let file_name = rebased.file_name().ok_or_else(|| {
        FileError::Io(
            rebased.display().to_string(),
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;
    // Store a canonical absolute parent so callers work the same way whether
    // the user supplied an absolute or relative configuration directory.
    *path = canonical_parent
        .join(file_name)
        .to_string_lossy()
        .into_owned();
    Ok(provider)
}

fn allow_fragment_item<T>(_: &T, _: &SourceLocation) -> Result<(), ConfigError> {
    Ok(())
}

fn reject_fragment_fallback(
    rule: &RuleConfigLine,
    source: &SourceLocation,
) -> Result<(), ConfigError> {
    if is_fallback(rule) {
        Err(CompositionError::FallbackOutsideRoot(source.clone()).into())
    } else {
        Ok(())
    }
}

fn validate_root_fallback(rules: &[Sourced<RuleConfigLine>]) -> Result<(), ConfigError> {
    let fallback_indices: Vec<usize> = rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| is_fallback(&rule.value).then_some(index))
        .collect();
    if fallback_indices.len() != 1 {
        return Err(RuleError::Invalid(format!(
            "expected exactly one root FALLBACK, found {}",
            fallback_indices.len()
        ))
        .into());
    }
    let fallback_index = fallback_indices[0];
    if fallback_index + 1 != rules.len() {
        return Err(ConfigError::Rule(RuleError::Invalid(
            "root FALLBACK must be the final expanded rule".to_string(),
        ))
        .at(rules[fallback_index].source.clone()));
    }
    Ok(())
}

fn is_fallback(rule: &RuleConfigLine) -> bool {
    let RuleConfigLine::Simple(line) = rule else {
        return false;
    };
    line.split(',')
        .next()
        .is_some_and(|prefix| prefix.trim() == "FALLBACK")
}

fn format_rule_line(rule: &RuleConfigLine) -> String {
    match rule {
        RuleConfigLine::Simple(line) => line.clone(),
        RuleConfigLine::Complex(_) => serde_yaml::to_string(rule)
            .unwrap_or_else(|_| format!("{rule:?}"))
            .trim()
            .to_string(),
    }
}

async fn load_remote_config<T>(
    url: &str,
    path: &str,
    root_path: impl AsRef<Path>,
    force_update: bool,
) -> Result<T, FileError>
where
    T: serde::de::DeserializeOwned,
{
    let serde_error = |e| FileError::Serde(path.to_string(), e);
    let text = load_remote_text(url, path, root_path, force_update).await?;
    serde_yaml::from_str(text.as_str()).map_err(serde_error)
}

pub(crate) async fn load_remote_text(
    url: &str,
    path: &str,
    root_path: impl AsRef<Path>,
    force_update: bool,
) -> Result<String, FileError> {
    let io_error = |e| FileError::Io(path.to_string(), e);
    let http_error = |e| FileError::Http(url.to_string(), e);
    let full_path = safe_join_path(root_path.as_ref(), path).map_err(io_error)?;
    if !force_update && full_path.as_path().exists() {
        fs::read_to_string(full_path.as_path()).map_err(io_error)
    } else {
        tracing::debug!("Downloading external resource from {}", url);
        let resp = reqwest::get(url).await.map_err(http_error)?;
        let text = resp.text().await.map_err(http_error)?;
        // security: `full_path` should be (layers of) subdir of `root_path`,
        //           so arbitrary write should not happen
        fs::write(full_path.as_path(), text.as_str()).map_err(io_error)?;
        set_real_ownership(&full_path).map_err(io_error)?;
        Ok(text)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AuthData {
    pub username: String,
    pub password: String,
}

pub(super) fn set_real_ownership(path: &Path) -> io::Result<()> {
    if let Some(user_info) = get_user_info() {
        user_info.chown(path)?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum SingleOrVec<T>
where
    T: Debug + Clone,
{
    Single(T),
    List(Vec<T>),
}

impl<T> SingleOrVec<T>
where
    T: Debug + Clone,
{
    pub fn linearize(self) -> Vec<T> {
        match self {
            SingleOrVec::Single(v) => vec![v],
            SingleOrVec::List(v) => v,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(untagged)]
pub enum PortOrSocketAddr {
    Port(u16),
    SocketAddr(SocketAddr),
}

impl PortOrSocketAddr {
    pub fn as_socket_addr<F>(&self, default_fn: F) -> SocketAddr
    where
        F: FnOnce() -> IpAddr,
    {
        match self {
            PortOrSocketAddr::Port(port) => SocketAddr::from((default_fn(), *port)),
            PortOrSocketAddr::SocketAddr(addr) => *addr,
        }
    }
}

pub(in crate::config) fn default_true() -> bool {
    true
}

#[cfg(test)]
mod composition_tests {
    use super::{CompositionError, ConfigError, LoadedConfig, RawRootCfg, RuleConfigLine};
    use std::fs;
    use std::path::{Path, PathBuf};

    struct TempConfig {
        base: PathBuf,
        root: PathBuf,
    }

    impl TempConfig {
        fn new() -> Self {
            let base = std::env::temp_dir().join(format!(
                "boltconn-config-test-{}-{}",
                std::process::id(),
                fastrand::u64(..)
            ));
            let root = base.join("config");
            fs::create_dir_all(&root).expect("create temporary config directory");
            Self { base, root }
        }

        fn write(&self, relative_path: impl AsRef<Path>, content: &str) {
            let path = self.root.join(relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create fixture parent directory");
            }
            fs::write(path, content).expect("write config fixture");
        }

        fn write_root(&self, composition: &str) {
            self.write(
                "config.yml",
                &format!(
                    r#"interface: auto
dns:
  bootstrap: [1.1.1.1]
  nameserver: ["udp, 1.1.1.1"]
proxy-group:
  Default:
    proxies: [DIRECT]
{composition}"#
                ),
            );
        }
    }

    impl Drop for TempConfig {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn simple_rules(config: &LoadedConfig) -> Vec<&str> {
        config
            .config
            .rules
            .iter()
            .map(|rule| match &rule.value {
                RuleConfigLine::Simple(line) => line.as_str(),
                RuleConfigLine::Complex(_) => panic!("fixture only uses simple rules"),
            })
            .collect()
    }

    #[tokio::test]
    async fn expands_modules_and_nested_includes_at_the_reference_position() {
        let fixture = TempConfig::new();
        fixture.write_root(
            r#"modules:
  topic:
    type: file
    path: modules/topic.yaml
rules:
  - DOMAIN, root-before.example, DIRECT
  - module: topic
  - include: fragments/root.yaml
  - FALLBACK, Default
interception:
  - module: topic
"#,
        );
        fixture.write(
            "modules/topic.yaml",
            r#"rules:
  - DOMAIN, module.example, DIRECT
  - include: nested.yaml
interception:
  - name: module-capture
    filters: ["DOMAIN, module.example"]
    actions: [capture]
"#,
        );
        fixture.write("modules/nested.yaml", "- DOMAIN, nested.example, DIRECT\n");
        fixture.write(
            "fragments/root.yaml",
            "- DOMAIN, root-after.example, DIRECT\n",
        );

        let loaded = LoadedConfig::load_config_only(&fixture.root)
            .await
            .expect("composition should load");
        assert_eq!(
            simple_rules(&loaded),
            vec![
                "DOMAIN, root-before.example, DIRECT",
                "DOMAIN, module.example, DIRECT",
                "DOMAIN, nested.example, DIRECT",
                "DOMAIN, root-after.example, DIRECT",
                "FALLBACK, Default",
            ]
        );
        assert_eq!(
            loaded.config.rules[2].source_chain(),
            "config.yml:rules[1] -> modules/topic.yaml:rules[1] -> modules/nested.yaml:rules[0]"
        );
        assert_eq!(loaded.config.interception.len(), 1);
        assert_eq!(
            loaded.config.interception[0].source.path,
            PathBuf::from("modules/topic.yaml")
        );
    }

    #[tokio::test]
    async fn declaring_a_module_does_not_insert_its_ordered_exports() {
        let fixture = TempConfig::new();
        fixture.write_root(
            r#"modules:
  topic:
    type: file
    path: topic.yaml
rules:
  - FALLBACK, Default
"#,
        );
        fixture.write("topic.yaml", "rules:\n  - DOMAIN, unused.example, DIRECT\n");

        let loaded = LoadedConfig::load_config_only(&fixture.root)
            .await
            .expect("unused module should still validate");
        assert_eq!(simple_rules(&loaded), vec!["FALLBACK, Default"]);
    }

    #[tokio::test]
    async fn rejects_duplicate_module_references_per_section() {
        let fixture = TempConfig::new();
        fixture.write_root(
            r#"modules:
  topic:
    type: file
    path: topic.yaml
rules:
  - module: topic
  - module: topic
  - FALLBACK, Default
"#,
        );
        fixture.write("topic.yaml", "rules: []\n");

        let error = LoadedConfig::load_config_only(&fixture.root)
            .await
            .expect_err("duplicate references must fail");
        assert!(matches!(
            error,
            ConfigError::Composition(error)
                if matches!(*error, CompositionError::DuplicateModuleReference { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_include_cycles_with_the_complete_chain() {
        let fixture = TempConfig::new();
        fixture.write_root("rules:\n  - include: fragments/a.yaml\n  - FALLBACK, Default\n");
        fixture.write("fragments/a.yaml", "- include: b.yaml\n");
        fixture.write("fragments/b.yaml", "- include: a.yaml\n");

        let error = LoadedConfig::load_config_only(&fixture.root)
            .await
            .expect_err("include cycles must fail");
        let ConfigError::Composition(error) = error else {
            panic!("unexpected error: {error}");
        };
        let CompositionError::IncludeCycle(chain) = *error else {
            panic!("unexpected composition error: {error}");
        };
        assert_eq!(
            chain,
            "fragments/a.yaml -> fragments/b.yaml -> fragments/a.yaml"
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_provider_names_across_root_and_modules() {
        let fixture = TempConfig::new();
        fixture.write_root(
            r#"modules:
  topic:
    type: file
    path: modules/topic.yaml
rule-providers:
  shared:
    type: file
    path: root-provider.yaml
rules:
  - FALLBACK, Default
"#,
        );
        fixture.write(
            "modules/topic.yaml",
            r#"rule-providers:
  shared:
    type: file
    path: module-provider.yaml
"#,
        );

        let error = LoadedConfig::load_config_only(&fixture.root)
            .await
            .expect_err("duplicate providers must fail");
        assert!(matches!(
            &error,
            ConfigError::Composition(error)
                if matches!(error.as_ref(), CompositionError::DuplicateDefinition { .. })
        ));
        let message = error.to_string();
        assert!(message.contains("config.yml:rule-providers.shared"));
        assert!(message.contains("modules/topic.yaml:rule-providers.shared"));
    }

    #[tokio::test]
    async fn rejects_fallback_in_module_exports() {
        let fixture = TempConfig::new();
        fixture.write_root(
            r#"modules:
  topic:
    type: file
    path: topic.yaml
rules:
  - module: topic
  - FALLBACK, Default
"#,
        );
        fixture.write("topic.yaml", "rules:\n  - FALLBACK, Default\n");

        let error = LoadedConfig::load_config_only(&fixture.root)
            .await
            .expect_err("module fallback must fail");
        assert!(matches!(
            error,
            ConfigError::Composition(error)
                if matches!(*error, CompositionError::FallbackOutsideRoot(_))
        ));
    }

    #[tokio::test]
    async fn rejects_includes_that_escape_the_configuration_root() {
        let fixture = TempConfig::new();
        fixture.write_root("rules:\n  - include: ../outside.yaml\n  - FALLBACK, Default\n");
        fs::write(fixture.base.join("outside.yaml"), "- NEVER, DIRECT\n")
            .expect("write escaped include fixture");

        let error = LoadedConfig::load_config_only(&fixture.root)
            .await
            .expect_err("escaping include must fail");
        assert!(matches!(
            error,
            ConfigError::Composition(error)
                if matches!(*error, CompositionError::PathEscape { .. })
        ));
    }

    #[test]
    fn rejects_non_kebab_case_root_fields() {
        let yaml = r#"interface: auto
dns:
  bootstrap: [1.1.1.1]
  nameserver: ["udp, 1.1.1.1"]
proxy-group:
  Default:
    proxies: [DIRECT]
rule_providers: {}
rules:
  - FALLBACK, Default
"#;
        let error = serde_yaml::from_str::<RawRootCfg>(yaml)
            .expect_err("non-canonical keys must be rejected");
        assert!(error.to_string().contains("unknown field `rule_providers`"));
    }
}
