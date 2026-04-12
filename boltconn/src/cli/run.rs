use crate::cli::request_uds::UdsConnector;
use crate::platform::process::validate_and_encode_tag;
use clap::Args;
use ipnet::IpNet;
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
    /// Remove generated allowlist rule after the subprocess exits
    #[arg(short = 'r', long = "restore")]
    pub restore: bool,
    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

const ALLOWLIST_RULE_MARKER: &str = "__BOLTCONN_RUN_ALLOWLIST_V1__";

#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowlistAtom {
    Domain(String),
    DomainSuffix(String),
    IpCidr(IpNet),
}

/// Set up the tag and exec the command. Returns the child's exit code (or -1 on error).
pub(crate) async fn run_with_tag(opts: RunOptions, uds_path: Option<&str>) -> i32 {
    let RunOptions {
        tag,
        allowlist,
        restore,
        command,
    } = opts;
    if let Err(e) = validate_allowlist_restore_flags(allowlist.as_deref(), restore) {
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

    let mut configured_allowlist_rule: Option<String> = None;
    if let Some(allowlist) = &allowlist {
        let Some(uds_path) = uds_path else {
            eprintln!("boltconn run: --allowlist requires a local controller socket");
            return 1;
        };
        match upsert_allowlist_rule_for_tag(&tag, allowlist, uds_path).await {
            Ok(rule) => configured_allowlist_rule = Some(rule),
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

    if restore && let Some(rule_literal) = configured_allowlist_rule {
        let Some(uds_path) = uds_path else {
            eprintln!("boltconn run: internal error: missing socket path for restore");
            return 1;
        };
        if let Err(e) = delete_allowlist_rule_literal(uds_path, rule_literal.as_str()).await {
            eprintln!("boltconn run: failed to restore allowlist rule: {}", e);
            return 1;
        }
    }

    exit_code
}

async fn upsert_allowlist_rule_for_tag(
    tag: &str,
    allowlist: &str,
    uds_path: &str,
) -> anyhow::Result<String> {
    let atoms = parse_allowlist(allowlist)?;
    let generated_rule = build_generated_allowlist_rule_literal(tag, &atoms);
    let (conn, _streaming_server) = UdsConnector::new(uds_path).await?;
    let existing_rules = conn.list_temporary_rule().await?;
    for rule in existing_rules {
        if is_generated_allowlist_rule_for_tag(&rule, tag) {
            #[allow(clippy::collapsible_if)]
            if !conn.delete_temporary_rule(rule).await? {
                anyhow::bail!("failed to delete old generated allowlist rule");
            }
        }
    }
    // The server prepends new temporary rules; adding last ensures this generated rule is on top.
    if !conn.add_temporary_rule(generated_rule.clone()).await? {
        anyhow::bail!("failed to add generated allowlist rule");
    }
    Ok(generated_rule)
}

async fn delete_allowlist_rule_literal(uds_path: &str, rule_literal: &str) -> anyhow::Result<()> {
    let (conn, _streaming_server) = UdsConnector::new(uds_path).await?;
    if !conn.delete_temporary_rule(rule_literal.to_string()).await? {
        anyhow::bail!("generated allowlist rule not found during restore");
    }
    Ok(())
}

fn validate_allowlist_restore_flags(allowlist: Option<&str>, restore: bool) -> anyhow::Result<()> {
    if restore && allowlist.is_none() {
        anyhow::bail!("--restore requires --allowlist");
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

fn build_generated_allowlist_rule_literal(tag: &str, atoms: &[AllowlistAtom]) -> String {
    let allow_expr = match atoms.len() {
        0 => format!("NEVER, {}", ALLOWLIST_RULE_MARKER),
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
        tag, ALLOWLIST_RULE_MARKER, allow_expr
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
    let Ok(list) = serde_yaml::from_str::<serde_yaml::Sequence>(
        (String::from("[") + rule_literal + "]").as_str(),
    ) else {
        return false;
    };
    if list.len() < 4 {
        return false;
    }
    if list
        .first()
        .and_then(value_to_string)
        .is_none_or(|head| head != "AND")
    {
        return false;
    }
    if list
        .last()
        .and_then(value_to_string)
        .is_none_or(|tail| tail != "REJECT")
    {
        return false;
    }

    let mut has_tag = false;
    let mut has_marker = false;
    let mut has_not_allow_expr = false;
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
            && value_to_string(seq.get(1).expect("len checked"))
                .is_some_and(|s| s == ALLOWLIST_RULE_MARKER)
        {
            has_marker = true;
            continue;
        }
        if seq.len() == 2
            && value_to_string(seq.first().expect("len checked")).is_some_and(|s| s == "NOT")
            && matches!(seq.get(1), Some(serde_yaml::Value::Sequence(_)))
            && is_allow_expr_sequence(seq.get(1).expect("len checked"))
        {
            has_not_allow_expr = true;
        }
    }
    has_tag && has_marker && has_not_allow_expr
}

fn is_allow_expr_sequence(val: &serde_yaml::Value) -> bool {
    let serde_yaml::Value::Sequence(seq) = val else {
        return false;
    };
    if seq.len() == 2
        && value_to_string(seq.first().expect("len checked")).is_some_and(|s| s == "NEVER")
        && value_to_string(seq.get(1).expect("len checked"))
            .is_some_and(|s| s == ALLOWLIST_RULE_MARKER)
    {
        return true;
    }
    if is_allow_atom_sequence(seq.as_slice()) {
        return true;
    }
    if seq.len() < 3 || value_to_string(seq.first().expect("len checked")).is_none_or(|s| s != "OR")
    {
        return false;
    }
    seq[1..].iter().all(|sub| {
        let serde_yaml::Value::Sequence(sub_seq) = sub else {
            return false;
        };
        is_allow_atom_sequence(sub_seq.as_slice())
    })
}

fn is_allow_atom_sequence(seq: &[serde_yaml::Value]) -> bool {
    if seq.len() != 2 {
        return false;
    }
    match value_to_string(seq.first().expect("len checked")) {
        Some("DOMAIN") | Some("DOMAIN-SUFFIX") | Some("IP-CIDR") | Some("IP-CIDR6") => {
            value_to_string(seq.get(1).expect("len checked")).is_some()
        }
        _ => false,
    }
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
    fn test_validate_allowlist_restore_flag_combo() {
        assert!(validate_allowlist_restore_flags(None, true).is_err());
        assert!(validate_allowlist_restore_flags(Some(""), true).is_ok());
        assert!(validate_allowlist_restore_flags(None, false).is_ok());
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
        );
        assert!(is_generated_allowlist_rule_for_tag(&rule, "alpha"));
        assert!(!is_generated_allowlist_rule_for_tag(&rule, "beta"));
    }

    #[test]
    fn test_generated_rule_literal_string_is_matched() {
        let literal = "AND, [PROCESS-TAG, alpha], [ALWAYS, __BOLTCONN_RUN_ALLOWLIST_V1__], [NOT, [OR, [DOMAIN, github.com], [DOMAIN-SUFFIX, api.openai.com], [IP-CIDR, 1.1.1.1/32], [IP-CIDR6, 2001:db8::/32]]], REJECT";
        assert!(is_generated_allowlist_rule_for_tag(literal, "alpha"));
        assert!(!is_generated_allowlist_rule_for_tag(literal, "beta"));
    }

    #[test]
    fn test_generated_empty_allowlist_rule_is_matched() {
        let literal = "AND, [PROCESS-TAG, alpha], [ALWAYS, __BOLTCONN_RUN_ALLOWLIST_V1__], [NOT, [NEVER, __BOLTCONN_RUN_ALLOWLIST_V1__]], REJECT";
        assert!(is_generated_allowlist_rule_for_tag(literal, "alpha"));
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
        let non_reject = "AND, [PROCESS-TAG, alpha], [ALWAYS, __BOLTCONN_RUN_ALLOWLIST_V1__], [NOT, [DOMAIN, github.com]], DIRECT";
        assert!(!is_generated_allowlist_rule_for_tag(non_reject, "alpha"));
    }
}
