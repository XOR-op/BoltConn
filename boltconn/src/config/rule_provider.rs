use crate::common::is_valid_domain_name;
use crate::config;
use crate::config::{ConfigError, FileError, ProviderError, load_remote_text};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::task::JoinHandle;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
// not deny_unknown_fields, in order to achieve compatibility
pub enum RuleLocation {
    #[serde(alias = "file")]
    File { path: String },
    #[serde(alias = "http")]
    Http {
        url: String,
        path: String,
        interval: u32,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub struct RuleProvider {
    #[serde(default = "default_rule_provider_format")]
    pub format: RuleProviderFormat,
    #[serde(default = "default_classical")]
    pub behavior: ProviderBehavior,
    #[serde(flatten)]
    pub location: RuleLocation,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProviderFormat {
    #[serde(alias = "yaml")]
    Yaml,
    #[serde(alias = "adblock")]
    Adblock,
}

fn default_rule_provider_format() -> RuleProviderFormat {
    RuleProviderFormat::Yaml
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderBehavior {
    #[serde(alias = "domain")]
    Domain,
    #[serde(alias = "ipcidr")]
    IpCidr,
    #[serde(alias = "classical")]
    Classical,
}

fn default_classical() -> ProviderBehavior {
    ProviderBehavior::Classical
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RawRuleSchema {
    pub payload: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuleSchema {
    pub behavior: ProviderBehavior,
    pub payload: Vec<String>,
}

fn validate_rule_provider(name: &str, provider: &RuleProvider) -> Result<(), ConfigError> {
    if provider.format == RuleProviderFormat::Adblock
        && provider.behavior != ProviderBehavior::Domain
    {
        return Err(ProviderError::UnsupportedFormat(
            name.to_string(),
            "adblock format requires behavior: domain",
        )
        .into());
    }
    Ok(())
}

fn load_local_rule_text(root_path: &Path, path: &str) -> Result<String, FileError> {
    let io_error = |e| FileError::Io(path.to_string(), e);
    fs::read_to_string(config::safe_join_path(root_path, path).map_err(io_error)?).map_err(io_error)
}

fn parse_yaml_rule_schema(
    path: &str,
    content: &str,
    behavior: ProviderBehavior,
) -> Result<RuleSchema, ConfigError> {
    let serde_error = |e| FileError::Serde(path.to_string(), e);
    let content: RawRuleSchema = serde_yaml::from_str(content).map_err(serde_error)?;
    Ok(RuleSchema {
        behavior,
        payload: content.payload,
    })
}

fn parse_adblock_schema(name: &str, behavior: ProviderBehavior, content: &str) -> RuleSchema {
    let (payload, skipped) = parse_adblock_rule_schema(content);
    if skipped > 0 {
        tracing::warn!(
            "Rule provider {} skipped {} unsupported adblock line(s)",
            name,
            skipped
        );
    }
    RuleSchema { behavior, payload }
}

fn parse_adblock_rule_schema(content: &str) -> (Vec<String>, usize) {
    let mut payload = Vec::new();
    let mut skipped = 0usize;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('!')
            || line.starts_with('#')
            || line.starts_with('[')
        {
            continue;
        }

        // Only accept exact domains and `||domain^` suffix rules. Everything else
        // stays out of the generated ruleset so third-party lists remain usable.
        if line.starts_with("@@") || line.contains('$') || is_regex_rule(line) {
            skipped += 1;
            continue;
        }

        match parse_adblock_rule_line(line) {
            Some(rule) => payload.push(rule),
            None => skipped += 1,
        }
    }

    (payload, skipped)
}

fn parse_adblock_rule_line(line: &str) -> Option<String> {
    if let Some(domain) = line.strip_prefix("||").and_then(|s| s.strip_suffix('^')) {
        return is_valid_domain_name(domain).then(|| format!("*.{}", domain));
    }
    is_valid_domain_name(line).then(|| line.to_string())
}

fn is_regex_rule(line: &str) -> bool {
    line.len() >= 2 && line.starts_with('/') && line.ends_with('/')
}

pub async fn read_rule_schema(
    config_path: &Path,
    providers: &HashMap<String, RuleProvider>,
    force_update: bool,
) -> Result<HashMap<String, RuleSchema>, ConfigError> {
    let mut table = HashMap::new();
    // concurrently download rules
    let tasks: HashMap<String, JoinHandle<Result<RuleSchema, ConfigError>>> = providers
        .clone()
        .into_iter()
        .map(|(name, item)| {
            let root_path = config_path.to_path_buf();
            let provider_name = name.clone();
            (
                name,
                tokio::spawn(async move {
                    validate_rule_provider(&provider_name, &item)?;

                    match item.location {
                        RuleLocation::File { path } => {
                            let text = load_local_rule_text(&root_path, &path)?;
                            match item.format {
                                RuleProviderFormat::Yaml => {
                                    parse_yaml_rule_schema(&path, &text, item.behavior)
                                }
                                RuleProviderFormat::Adblock => {
                                    Ok(parse_adblock_schema(&provider_name, item.behavior, &text))
                                }
                            }
                        }
                        RuleLocation::Http { url, path, .. } => {
                            let text =
                                load_remote_text(&url, &path, &root_path, force_update).await?;
                            match item.format {
                                RuleProviderFormat::Yaml => {
                                    parse_yaml_rule_schema(&path, &text, item.behavior)
                                }
                                RuleProviderFormat::Adblock => {
                                    Ok(parse_adblock_schema(&provider_name, item.behavior, &text))
                                }
                            }
                        }
                    }
                }),
            )
        })
        .collect();
    for (name, task) in tasks {
        let content = match task.await? {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        table.insert(name, content);
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::{
        ProviderBehavior, RuleLocation, RuleProvider, RuleProviderFormat,
        parse_adblock_rule_schema, validate_rule_provider,
    };

    #[test]
    fn test_parse_adblock_rule_schema_accepts_exact_and_suffix_entries() {
        let (payload, skipped) = parse_adblock_rule_schema(
            r#"
            example.com
            ||example.org^
            "#,
        );
        assert_eq!(
            payload,
            vec!["example.com".to_string(), "*.example.org".to_string()]
        );
        assert_eq!(skipped, 0);
    }

    #[test]
    fn test_parse_adblock_rule_schema_skips_comments_headers_and_unsupported_lines() {
        let (payload, skipped) = parse_adblock_rule_schema(
            r#"
            ! comment
            # comment
            [Adblock Plus 2.0]
            @@||allow.example^
            ||mod.example^$important
            /exa.*/
            ||exa*mple.com^
            |example.net
            127.0.0.1 host.example
            example.com
            ||example.org^
            "#,
        );
        assert_eq!(
            payload,
            vec!["example.com".to_string(), "*.example.org".to_string()]
        );
        assert_eq!(skipped, 6);
    }

    #[test]
    fn test_validate_rule_provider_rejects_adblock_for_non_domain_behavior() {
        let provider = RuleProvider {
            format: RuleProviderFormat::Adblock,
            behavior: ProviderBehavior::Classical,
            location: RuleLocation::File {
                path: "./rules/adblock.txt".to_string(),
            },
        };
        assert!(validate_rule_provider("ads", &provider).is_err());
    }

    #[test]
    fn test_validate_rule_provider_accepts_adblock_for_domain_behavior() {
        let provider = RuleProvider {
            format: RuleProviderFormat::Adblock,
            behavior: ProviderBehavior::Domain,
            location: RuleLocation::File {
                path: "./rules/adblock.txt".to_string(),
            },
        };
        assert!(validate_rule_provider("ads", &provider).is_ok());
    }
}
