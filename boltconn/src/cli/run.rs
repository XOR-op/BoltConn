use crate::cli::request_uds::UdsConnector;
use crate::platform::process::validate_and_encode_tag;
use clap::Args;
use ipnet::IpNet;
use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Debug, Args)]
pub(crate) struct RunOptions {
    /// Tag string to assign to the launched process (must be non-empty and
    /// base64-encode to at most 21 characters to satisfy the macOS shm name limit)
    #[arg(short = 't', long = "tag")]
    pub tag: String,
    /// Semicolon-separated domain/IP/CIDR allowlist for this tag
    #[arg(short = 'a', long = "allowlist")]
    pub allowlist: Option<String>,
    /// Keep the generated allowlist rule after the subprocess exits
    #[arg(short = 'p', long = "persistent")]
    pub persistent: bool,
    /// Overwrite an existing generated allowlist rule when persistent mode is used
    #[arg(short = 'f', long = "force")]
    pub force: bool,
    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

const ALLOWLIST_RULE_MARKER_TEMPORARY: &str = "__BOLTCONN_RUN_ALLOWLIST_TEMPORARY_V1__";
const ALLOWLIST_RULE_MARKER_PERSISTENT: &str = "__BOLTCONN_RUN_ALLOWLIST_PERSISTENT_V1__";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllowlistRulePersistence {
    Temporary,
    Persistent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowlistAtom {
    Domain(String),
    DomainSuffix(String),
    IpCidr(IpNet),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeneratedAllowlistRule {
    literal: String,
    persistence: AllowlistRulePersistence,
    normalized_allowlist: Vec<String>,
}

/// Set up the tag and exec the command. Returns the child's exit code (or -1 on error).
pub(crate) async fn run_with_tag(opts: RunOptions, uds_path: Option<&str>) -> i32 {
    let RunOptions {
        tag,
        allowlist,
        persistent,
        force,
        command,
    } = opts;

    if let Err(e) = validate_allowlist_flags(allowlist.as_deref(), persistent, force) {
        eprintln!("boltconn run: {}", e);
        return 1;
    }

    let encoded = match validate_and_encode_tag(&tag) {
        Ok(e) => e,
        Err(msg) => {
            eprintln!("boltconn run: invalid tag: {}", msg);
            return 1;
        }
    };

    let mut iter = command.into_iter();
    let program = match iter.next() {
        Some(p) => p,
        None => {
            eprintln!("boltconn run: no command specified");
            return 1;
        }
    };
    let args: Vec<String> = iter.collect();

    let mut cleanup_allowlist_rule: Option<String> = None;
    if let Some(allowlist) = &allowlist {
        let Some(uds_path) = uds_path else {
            eprintln!("boltconn run: --allowlist requires a local controller socket");
            return 1;
        };
        match upsert_allowlist_rule_for_tag(&tag, allowlist, persistent, force, uds_path).await {
            Ok(rule_to_cleanup) => cleanup_allowlist_rule = rule_to_cleanup,
            Err(e) => {
                eprintln!("boltconn run: failed to configure allowlist: {}", e);
                return 1;
            }
        }
    }

    let exit_code = {
        #[cfg(unix)]
        {
            match crate::platform::process::setup_tag_fd(&encoded) {
                Ok(_) => execute_command(program.as_str(), &args),
                Err(e) => {
                    eprintln!("boltconn run: failed to set up tag fd: {}", e);
                    1
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            crate::platform::process::setup_tag_env(&encoded);
            execute_command(program.as_str(), &args)
        }
        #[cfg(all(not(unix), not(target_os = "windows")))]
        {
            execute_command(program.as_str(), &args)
        }
    };

    if let Some(rule_literal) = cleanup_allowlist_rule {
        let Some(uds_path) = uds_path else {
            eprintln!("boltconn run: internal error: missing socket path for allowlist cleanup");
            return 1;
        };
        if let Err(e) = delete_allowlist_rule_literal(uds_path, rule_literal.as_str()).await {
            eprintln!(
                "boltconn run: failed to clean up temporary allowlist rule: {}",
                e
            );
            return 1;
        }
    }

    exit_code
}

async fn upsert_allowlist_rule_for_tag(
    tag: &str,
    allowlist: &str,
    persistent: bool,
    force: bool,
    uds_path: &str,
) -> anyhow::Result<Option<String>> {
    let atoms = parse_allowlist(allowlist)?;
    let requested_persistence = if persistent {
        AllowlistRulePersistence::Persistent
    } else {
        AllowlistRulePersistence::Temporary
    };
    let generated_rule = build_generated_allowlist_rule_literal(tag, &atoms, requested_persistence);
    let normalized_allowlist = normalize_allowlist_atoms(&atoms);

    let (conn, _streaming_server) = UdsConnector::new(uds_path).await?;
    let existing_rules = conn.list_temporary_rule().await?;
    let mut existing_generated_rules = existing_rules
        .into_iter()
        .filter_map(|rule| parse_generated_allowlist_rule_for_tag(&rule, tag))
        .collect::<Vec<_>>();

    if existing_generated_rules.len() > 1 {
        if requested_persistence != AllowlistRulePersistence::Persistent || !force {
            anyhow::bail!(
                "multiple generated allowlist rules exist for tag '{}'; rerun with --persistent --force to replace",
                tag
            );
        }

        for rule in existing_generated_rules {
            if !conn.delete_temporary_rule(rule.literal).await? {
                anyhow::bail!("failed to delete existing generated allowlist rule");
            }
        }

        if !conn.add_temporary_rule(generated_rule).await? {
            anyhow::bail!("failed to add generated allowlist rule");
        }
        return Ok(None);
    }

    if let Some(existing_rule) = existing_generated_rules.pop() {
        let should_replace = evaluate_rewrite_policy(
            &existing_rule,
            normalized_allowlist.as_slice(),
            requested_persistence,
            force,
        )?;

        if should_replace {
            if !conn.delete_temporary_rule(existing_rule.literal).await? {
                anyhow::bail!("failed to delete existing generated allowlist rule");
            }
            if !conn.add_temporary_rule(generated_rule).await? {
                anyhow::bail!("failed to add generated allowlist rule");
            }
        }

        return Ok(None);
    }

    // The server prepends new temporary rules; adding last ensures this generated rule is on top.
    if !conn.add_temporary_rule(generated_rule.clone()).await? {
        anyhow::bail!("failed to add generated allowlist rule");
    }

    if requested_persistence == AllowlistRulePersistence::Temporary {
        Ok(Some(generated_rule))
    } else {
        Ok(None)
    }
}

fn evaluate_rewrite_policy(
    existing: &GeneratedAllowlistRule,
    requested_allowlist: &[String],
    requested_persistence: AllowlistRulePersistence,
    force: bool,
) -> anyhow::Result<bool> {
    let is_equivalent = existing.normalized_allowlist == requested_allowlist;
    let same_persistence = existing.persistence == requested_persistence;

    if is_equivalent && same_persistence {
        return Ok(false);
    }

    if requested_persistence == AllowlistRulePersistence::Temporary {
        anyhow::bail!(
            "temporary allowlist cannot replace an existing generated allowlist rule; use --persistent"
        );
    }

    if !force {
        anyhow::bail!(
            "generated allowlist rule already exists for this tag; rerun with --persistent --force to replace"
        );
    }

    Ok(true)
}

fn parse_generated_allowlist_rule_for_tag(
    rule_literal: &str,
    tag: &str,
) -> Option<GeneratedAllowlistRule> {
    let list = parse_rule_literal_sequence(rule_literal)?;
    if list.len() < 4 {
        return None;
    }
    if list
        .first()
        .and_then(value_to_string)
        .is_none_or(|head| head != "AND")
    {
        return None;
    }
    if list
        .last()
        .and_then(value_to_string)
        .is_none_or(|tail| tail != "REJECT")
    {
        return None;
    }

    let mut has_tag = false;
    let mut persistence: Option<AllowlistRulePersistence> = None;
    let mut allow_expr: Option<&serde_yaml::Value> = None;

    for val in &list[1..list.len() - 1] {
        let serde_yaml::Value::Sequence(seq) = val else {
            continue;
        };

        if seq.len() == 2
            && value_to_string(seq.first().expect("len checked"))
                .is_some_and(|s| s == "PROCESS-TAG")
            && value_to_string(seq.get(1).expect("len checked")).is_some_and(|s| s == tag)
        {
            has_tag = true;
            continue;
        }

        if seq.len() == 2
            && value_to_string(seq.first().expect("len checked")).is_some_and(|s| s == "ALWAYS")
        {
            let marker = value_to_string(seq.get(1).expect("len checked"))?;
            persistence = parse_rule_marker_persistence(marker);
            continue;
        }

        if seq.len() == 2
            && value_to_string(seq.first().expect("len checked")).is_some_and(|s| s == "NOT")
            && matches!(seq.get(1), Some(serde_yaml::Value::Sequence(_)))
        {
            allow_expr = seq.get(1);
        }
    }

    if !has_tag {
        return None;
    }

    let persistence = persistence?;
    let normalized_allowlist = parse_allow_expr_atoms(allow_expr?, persistence)?;
    Some(GeneratedAllowlistRule {
        literal: rule_literal.to_string(),
        persistence,
        normalized_allowlist,
    })
}

fn parse_rule_literal_sequence(rule_literal: &str) -> Option<serde_yaml::Sequence> {
    serde_yaml::from_str::<serde_yaml::Sequence>((String::from("[") + rule_literal + "]").as_str())
        .ok()
}

fn parse_allow_expr_atoms(
    val: &serde_yaml::Value,
    persistence: AllowlistRulePersistence,
) -> Option<Vec<String>> {
    let serde_yaml::Value::Sequence(seq) = val else {
        return None;
    };

    if seq.len() == 2
        && value_to_string(seq.first().expect("len checked")).is_some_and(|s| s == "NEVER")
    {
        let marker = value_to_string(seq.get(1).expect("len checked"))?;
        let expr_persistence = parse_rule_marker_persistence(marker)?;
        if expr_persistence != persistence {
            return None;
        }
        return Some(Vec::new());
    }

    if let Some(atom) = parse_allow_atom_sequence(seq.as_slice()) {
        return Some(normalize_allowlist_atom_strings([atom_rule(&atom)]));
    }

    if seq.len() < 3 || value_to_string(seq.first().expect("len checked")).is_none_or(|s| s != "OR")
    {
        return None;
    }

    let mut atoms = Vec::new();
    for sub in &seq[1..] {
        let serde_yaml::Value::Sequence(sub_seq) = sub else {
            return None;
        };
        let atom = parse_allow_atom_sequence(sub_seq.as_slice())?;
        atoms.push(atom_rule(&atom));
    }

    Some(normalize_allowlist_atom_strings(atoms))
}

fn parse_allow_atom_sequence(seq: &[serde_yaml::Value]) -> Option<AllowlistAtom> {
    if seq.len() != 2 {
        return None;
    }

    let rule_type = value_to_string(seq.first().expect("len checked"))?;
    let value = value_to_string(seq.get(1).expect("len checked"))?;

    match rule_type {
        "DOMAIN" => Some(AllowlistAtom::Domain(value.to_string())),
        "DOMAIN-SUFFIX" => Some(AllowlistAtom::DomainSuffix(value.to_string())),
        "IP-CIDR" => {
            let net = value.parse::<IpNet>().ok()?;
            if matches!(net, IpNet::V4(_)) {
                Some(AllowlistAtom::IpCidr(net))
            } else {
                None
            }
        }
        "IP-CIDR6" => {
            let net = value.parse::<IpNet>().ok()?;
            if matches!(net, IpNet::V6(_)) {
                Some(AllowlistAtom::IpCidr(net))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_rule_marker_persistence(marker: &str) -> Option<AllowlistRulePersistence> {
    match marker {
        ALLOWLIST_RULE_MARKER_TEMPORARY => Some(AllowlistRulePersistence::Temporary),
        ALLOWLIST_RULE_MARKER_PERSISTENT => Some(AllowlistRulePersistence::Persistent),
        _ => None,
    }
}

fn rule_marker_by_persistence(persistence: AllowlistRulePersistence) -> &'static str {
    match persistence {
        AllowlistRulePersistence::Temporary => ALLOWLIST_RULE_MARKER_TEMPORARY,
        AllowlistRulePersistence::Persistent => ALLOWLIST_RULE_MARKER_PERSISTENT,
    }
}

fn normalize_allowlist_atoms(atoms: &[AllowlistAtom]) -> Vec<String> {
    normalize_allowlist_atom_strings(atoms.iter().map(atom_rule))
}

fn normalize_allowlist_atom_strings<I>(atoms: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let set = atoms.into_iter().collect::<BTreeSet<_>>();
    set.into_iter().collect()
}

async fn delete_allowlist_rule_literal(uds_path: &str, rule_literal: &str) -> anyhow::Result<()> {
    let (conn, _streaming_server) = UdsConnector::new(uds_path).await?;
    if !conn.delete_temporary_rule(rule_literal.to_string()).await? {
        anyhow::bail!("generated allowlist rule not found during cleanup");
    }
    Ok(())
}

fn validate_allowlist_flags(
    allowlist: Option<&str>,
    persistent: bool,
    force: bool,
) -> anyhow::Result<()> {
    if persistent && allowlist.is_none() {
        anyhow::bail!("--persistent requires --allowlist");
    }
    if force && allowlist.is_none() {
        anyhow::bail!("--force requires --allowlist");
    }
    Ok(())
}

fn execute_command(program: &str, args: &[String]) -> i32 {
    match std::process::Command::new(program).args(args).status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("boltconn run: failed to execute '{}': {}", program, e);
            1
        }
    }
}

fn parse_allowlist(raw: &str) -> anyhow::Result<Vec<AllowlistAtom>> {
    let mut atoms = Vec::new();
    for entry in raw.split(';') {
        let token = entry.trim();
        if token.is_empty() {
            continue;
        }
        atoms.push(parse_allowlist_atom(token)?);
    }
    Ok(atoms)
}

fn parse_allowlist_atom(token: &str) -> anyhow::Result<AllowlistAtom> {
    if let Some(suffix) = token.strip_prefix("*.") {
        if suffix.is_empty() || !is_valid_domain_name(suffix) {
            anyhow::bail!("invalid wildcard domain '{}'", token);
        }
        return Ok(AllowlistAtom::DomainSuffix(suffix.to_string()));
    }
    if token.contains('*') {
        anyhow::bail!("wildcard is only supported as '*.' prefix: '{}'", token);
    }
    if let Ok(net) = token.parse::<IpNet>() {
        return Ok(AllowlistAtom::IpCidr(net));
    }
    if let Ok(ip) = token.parse::<IpAddr>() {
        let net = match ip {
            IpAddr::V4(v4) => IpNet::new(IpAddr::V4(v4), 32)?,
            IpAddr::V6(v6) => IpNet::new(IpAddr::V6(v6), 128)?,
        };
        return Ok(AllowlistAtom::IpCidr(net));
    }
    if is_valid_domain_name(token) {
        return Ok(AllowlistAtom::Domain(token.to_string()));
    }
    anyhow::bail!("invalid allowlist entry '{}'", token)
}

fn is_valid_domain_name(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

fn build_generated_allowlist_rule_literal(
    tag: &str,
    atoms: &[AllowlistAtom],
    persistence: AllowlistRulePersistence,
) -> String {
    let marker = rule_marker_by_persistence(persistence);
    let allow_expr = match atoms.len() {
        0 => format!("NEVER, {}", marker),
        1 => atom_rule(atoms.first().expect("non-empty")),
        _ => {
            let subs = atoms
                .iter()
                .map(|a| format!("[{}]", atom_rule(a)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("OR, {}", subs)
        }
    };
    format!(
        "AND, [PROCESS-TAG, {}], [ALWAYS, {}], [NOT, [{}]], REJECT",
        tag, marker, allow_expr
    )
}

fn atom_rule(atom: &AllowlistAtom) -> String {
    match atom {
        AllowlistAtom::Domain(domain) => format!("DOMAIN, {}", domain),
        AllowlistAtom::DomainSuffix(suffix) => format!("DOMAIN-SUFFIX, {}", suffix),
        AllowlistAtom::IpCidr(net) => {
            if matches!(net, IpNet::V4(_)) {
                format!("IP-CIDR, {}", net)
            } else {
                format!("IP-CIDR6, {}", net)
            }
        }
    }
}

fn is_generated_allowlist_rule_for_tag(rule_literal: &str, tag: &str) -> bool {
    parse_generated_allowlist_rule_for_tag(rule_literal, tag).is_some()
}

fn value_to_string(val: &serde_yaml::Value) -> Option<&str> {
    match val {
        serde_yaml::Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_allowlist_atom_domain_ip_and_cidr() {
        assert_eq!(
            parse_allowlist_atom("github.com").unwrap(),
            AllowlistAtom::Domain("github.com".to_string())
        );
        assert_eq!(
            parse_allowlist_atom("*.api.openai.com").unwrap(),
            AllowlistAtom::DomainSuffix("api.openai.com".to_string())
        );
        assert_eq!(
            parse_allowlist_atom("1.1.1.1").unwrap(),
            AllowlistAtom::IpCidr("1.1.1.1/32".parse().unwrap())
        );
        assert_eq!(
            parse_allowlist_atom("17.0.0.0/8").unwrap(),
            AllowlistAtom::IpCidr("17.0.0.0/8".parse().unwrap())
        );
    }

    #[test]
    fn test_parse_allowlist_rejects_invalid_entries() {
        assert!(parse_allowlist_atom("*api.openai.com").is_err());
        assert!(parse_allowlist_atom("api.*.openai.com").is_err());
        assert!(parse_allowlist_atom("bad domain").is_err());
    }

    #[test]
    fn test_validate_allowlist_flag_combo() {
        assert!(validate_allowlist_flags(None, true, false).is_err());
        assert!(validate_allowlist_flags(None, false, true).is_err());
        assert!(validate_allowlist_flags(Some(""), true, true).is_ok());
        assert!(validate_allowlist_flags(None, false, false).is_ok());
    }

    #[test]
    fn test_parse_allowlist_empty_means_allow_nothing() {
        assert!(parse_allowlist("").unwrap().is_empty());
        assert!(parse_allowlist(" ; ; ").unwrap().is_empty());
        assert_eq!(parse_allowlist("github.com;;1.1.1.1").unwrap().len(), 2);
    }

    #[test]
    fn test_build_and_detect_generated_rule_for_same_tag() {
        let rule = build_generated_allowlist_rule_literal(
            "alpha",
            &[
                AllowlistAtom::Domain("github.com".to_string()),
                AllowlistAtom::IpCidr("1.1.1.1/32".parse().unwrap()),
            ],
            AllowlistRulePersistence::Temporary,
        );
        assert!(is_generated_allowlist_rule_for_tag(&rule, "alpha"));
        assert!(!is_generated_allowlist_rule_for_tag(&rule, "beta"));
    }

    #[test]
    fn test_generated_rule_literal_string_is_matched() {
        let literal = "AND, [PROCESS-TAG, alpha], [ALWAYS, __BOLTCONN_RUN_ALLOWLIST_TEMPORARY_V1__], [NOT, [OR, [DOMAIN, github.com], [DOMAIN-SUFFIX, api.openai.com], [IP-CIDR, 1.1.1.1/32], [IP-CIDR6, 2001:db8::/32]]], REJECT";
        assert!(is_generated_allowlist_rule_for_tag(literal, "alpha"));
        assert!(!is_generated_allowlist_rule_for_tag(literal, "beta"));
    }

    #[test]
    fn test_generated_empty_allowlist_rule_is_matched() {
        let literal = "AND, [PROCESS-TAG, alpha], [ALWAYS, __BOLTCONN_RUN_ALLOWLIST_TEMPORARY_V1__], [NOT, [NEVER, __BOLTCONN_RUN_ALLOWLIST_TEMPORARY_V1__]], REJECT";
        assert!(is_generated_allowlist_rule_for_tag(literal, "alpha"));
    }

    #[test]
    fn test_equivalence_uses_normalized_set() {
        let requested = normalize_allowlist_atoms(
            parse_allowlist("1.1.1.1;github.com;1.1.1.1;*.api.openai.com")
                .unwrap()
                .as_slice(),
        );
        let existing_literal = "AND, [PROCESS-TAG, alpha], [ALWAYS, __BOLTCONN_RUN_ALLOWLIST_TEMPORARY_V1__], [NOT, [OR, [DOMAIN-SUFFIX, api.openai.com], [DOMAIN, github.com], [IP-CIDR, 1.1.1.1/32]]], REJECT";
        let existing = parse_generated_allowlist_rule_for_tag(existing_literal, "alpha").unwrap();
        assert_eq!(existing.normalized_allowlist, requested);
    }

    #[test]
    fn test_rewrite_policy_noop_when_equivalent_and_same_persistence() {
        let existing = GeneratedAllowlistRule {
            literal: "x".to_string(),
            persistence: AllowlistRulePersistence::Temporary,
            normalized_allowlist: vec!["DOMAIN, github.com".to_string()],
        };

        let should_replace = evaluate_rewrite_policy(
            &existing,
            &["DOMAIN, github.com".to_string()],
            AllowlistRulePersistence::Temporary,
            false,
        )
        .unwrap();
        assert!(!should_replace);
    }

    #[test]
    fn test_rewrite_policy_temp_cannot_replace_even_with_force() {
        let existing = GeneratedAllowlistRule {
            literal: "x".to_string(),
            persistence: AllowlistRulePersistence::Temporary,
            normalized_allowlist: vec!["DOMAIN, github.com".to_string()],
        };

        assert!(
            evaluate_rewrite_policy(
                &existing,
                &["DOMAIN, api.openai.com".to_string()],
                AllowlistRulePersistence::Temporary,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn test_rewrite_policy_persistent_requires_force() {
        let existing = GeneratedAllowlistRule {
            literal: "x".to_string(),
            persistence: AllowlistRulePersistence::Temporary,
            normalized_allowlist: vec!["DOMAIN, github.com".to_string()],
        };

        assert!(
            evaluate_rewrite_policy(
                &existing,
                &["DOMAIN, github.com".to_string()],
                AllowlistRulePersistence::Persistent,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn test_rewrite_policy_persistent_with_force_replaces_temp_or_persistent() {
        let existing_temp = GeneratedAllowlistRule {
            literal: "x".to_string(),
            persistence: AllowlistRulePersistence::Temporary,
            normalized_allowlist: vec!["DOMAIN, github.com".to_string()],
        };
        let existing_persistent = GeneratedAllowlistRule {
            literal: "x".to_string(),
            persistence: AllowlistRulePersistence::Persistent,
            normalized_allowlist: vec!["DOMAIN, github.com".to_string()],
        };

        assert!(
            evaluate_rewrite_policy(
                &existing_temp,
                &["DOMAIN, api.openai.com".to_string()],
                AllowlistRulePersistence::Persistent,
                true,
            )
            .unwrap()
        );

        assert!(
            evaluate_rewrite_policy(
                &existing_persistent,
                &["DOMAIN, api.openai.com".to_string()],
                AllowlistRulePersistence::Persistent,
                true,
            )
            .unwrap()
        );
    }

    #[test]
    fn test_non_generated_rule_not_matched() {
        let rule = "AND, [PROCESS-TAG, alpha], [NOT, [DOMAIN, github.com]], REJECT";
        assert!(!is_generated_allowlist_rule_for_tag(rule, "alpha"));
    }

    #[test]
    fn test_near_miss_rules_not_recognized_as_generated() {
        // Missing marker subrule.
        let no_marker =
            "AND, [PROCESS-TAG, alpha], [NOT, [DOMAIN, github.com]], [ALWAYS, true], REJECT";
        assert!(!is_generated_allowlist_rule_for_tag(no_marker, "alpha"));

        // Same marker but non-REJECT action.
        let non_reject = "AND, [PROCESS-TAG, alpha], [ALWAYS, __BOLTCONN_RUN_ALLOWLIST_TEMPORARY_V1__], [NOT, [DOMAIN, github.com]], DIRECT";
        assert!(!is_generated_allowlist_rule_for_tag(non_reject, "alpha"));
    }
}
