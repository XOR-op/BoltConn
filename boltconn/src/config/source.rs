use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

/// An entry accepted directly in an ordered root configuration section.
///
/// Module references are deliberately root-only so every topic insertion remains
/// visible in `config.yml`. Included fragments use [`FragmentSequenceEntry`].
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RootSequenceEntry<T> {
    Module(ModuleEntry),
    Include(IncludeEntry),
    Item(T),
}

/// An entry accepted in module exports and included fragment files.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum FragmentSequenceEntry<T> {
    Include(IncludeEntry),
    Item(T),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ModuleEntry {
    pub module: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct IncludeEntry {
    pub include: PathBuf,
}

/// Location retained after composition so semantic errors can identify their source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    pub path: PathBuf,
    pub document_path: String,
}

impl SourceLocation {
    pub fn new(config_root: &Path, source_path: &Path, document_path: String) -> Self {
        let path = source_path
            .strip_prefix(config_root)
            .unwrap_or(source_path)
            .to_path_buf();
        Self {
            path,
            document_path,
        }
    }
}

impl Display for SourceLocation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        if self.document_path.is_empty() {
            write!(formatter, "{}", self.path.display())
        } else {
            write!(formatter, "{}:{}", self.path.display(), self.document_path)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Sourced<T> {
    pub value: T,
    pub source: SourceLocation,
    /// Composition directives traversed from the root document to `source`.
    pub expansion: Vec<SourceLocation>,
}

impl<T> Sourced<T> {
    pub fn new(value: T, source: SourceLocation) -> Self {
        Self {
            value,
            source,
            expansion: Vec::new(),
        }
    }

    pub fn prepend_expansion(&mut self, location: SourceLocation) {
        self.expansion.insert(0, location);
    }

    pub fn source_chain(&self) -> String {
        self.expansion
            .iter()
            .chain(std::iter::once(&self.source))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}
