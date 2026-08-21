use boltapi::{
    ConfigSourceLocation, DnsAttemptScope, DnsCacheStatus, DnsEndpoint, DnsErrorCode, DnsOutcome,
    DnsProtocol, DnsResponseKind, DnsScope, DnsSelection, LinkKind, RouteEgress, RouteHop,
    RouteSelection, Traffic,
};
use chrono::{DateTime, Local, Utc};
use serde::Serialize;

pub(super) fn enum_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(value)) => value,
        _ => "unknown".to_string(),
    }
}

pub(super) fn optional(value: Option<String>) -> String {
    value.unwrap_or_else(|| "-".to_string())
}

pub(super) fn truncate_end(value: &str, max_chars: usize) -> String {
    truncate(value, max_chars, false)
}

pub(super) fn truncate_start(value: &str, max_chars: usize) -> String {
    truncate(value, max_chars, true)
}

fn truncate(value: &str, max_chars: usize, from_start: bool) -> String {
    const MARKER: &str = "..";

    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= max_chars {
        return value.to_string();
    }

    let retained_chars = max_chars.saturating_sub(MARKER.len());
    if from_start {
        let skip_chars = chars.len() - retained_chars;
        MARKER
            .chars()
            .take(max_chars)
            .chain(chars.into_iter().skip(skip_chars))
            .collect()
    } else {
        chars
            .into_iter()
            .take(retained_chars)
            .chain(MARKER.chars().take(max_chars))
            .collect()
    }
}

pub(super) fn count(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(character);
    }
    output
}

pub(super) fn link_kind(kind: LinkKind) -> &'static str {
    match kind {
        LinkKind::Wireguard => "wg",
        LinkKind::Ssh => "ssh",
        LinkKind::Anytls => "anytls",
    }
}

pub(super) fn dns_protocol(protocol: DnsProtocol) -> &'static str {
    match protocol {
        DnsProtocol::Udp => "UDP",
        DnsProtocol::Tcp => "TCP",
        DnsProtocol::Dot => "DoT",
        DnsProtocol::Doh => "DoH",
    }
}

pub(super) fn route_selection(selection: &RouteSelection) -> String {
    selection.group.as_ref().map_or_else(
        || selection.selected.clone(),
        |group| format!("{group}/{}", selection.selected),
    )
}

pub(super) fn route_egress(egress: &RouteEgress) -> String {
    match egress {
        RouteEgress::Direct => "DIRECT".to_string(),
        RouteEgress::Interface { name } | RouteEgress::Link { name } => name.clone(),
        RouteEgress::Proxy { selection } => route_selection(selection),
    }
}

pub(super) fn route_hop(hop: &RouteHop) -> String {
    let selected = hop.group.as_ref().map_or_else(
        || hop.proxy.clone(),
        |group| format!("{group}/{}", hop.proxy),
    );
    match &hop.link {
        Some(link) => format!(
            "{selected} type={} generation={}",
            link_kind(link.kind),
            link.generation
        ),
        None => format!("{selected} type={}", hop.proxy_type),
    }
}

pub(super) fn config_location(location: &ConfigSourceLocation) -> String {
    format!("{}:{}", location.path, location.document_path)
}

pub(super) fn compact_bytes(bytes: u64) -> String {
    compact_quantity(bytes, &["", "K", "M", "G", "T"])
}

pub(super) fn bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    compact_quantity(bytes, &[" B", " KiB", " MiB", " GiB", " TiB"])
}

fn compact_quantity(value: u64, units: &[&str]) -> String {
    let mut scaled = value as f64;
    let mut unit = 0;
    while scaled >= 1024.0 && unit + 1 < units.len() {
        scaled /= 1024.0;
        unit += 1;
    }
    let number = if unit == 0 || scaled >= 10.0 {
        format!("{scaled:.0}")
    } else {
        trim_decimal(format!("{scaled:.1}"))
    };
    format!("{number}{}", units[unit])
}

pub(super) fn traffic(traffic: Traffic) -> String {
    format!(
        "↑{} ↓{}",
        compact_bytes(traffic.upload_bytes),
        compact_bytes(traffic.download_bytes)
    )
}

pub(super) fn duration(ms: u64) -> String {
    if ms < 1_000 {
        return format!("{ms}ms");
    }
    if ms < 60_000 {
        let seconds = ms as f64 / 1_000.0;
        return format!("{}s", trim_decimal(format!("{seconds:.3}")));
    }
    if ms < 3_600_000 {
        return format!("{}m{:02}s", ms / 60_000, ms % 60_000 / 1_000);
    }
    format!(
        "{}h{:02}m{:02}s",
        ms / 3_600_000,
        ms % 3_600_000 / 60_000,
        ms % 60_000 / 1_000
    )
}

pub(super) fn relative_age(timestamp_ms: Option<u64>, observed_at_ms: u64) -> String {
    let Some(timestamp_ms) = timestamp_ms else {
        return "never".to_string();
    };
    let elapsed_ms = observed_at_ms.saturating_sub(timestamp_ms);
    if elapsed_ms < 1_000 {
        "now".to_string()
    } else if elapsed_ms < 60_000 {
        format!("{}s ago", elapsed_ms / 1_000)
    } else if elapsed_ms < 3_600_000 {
        format!("{}m ago", elapsed_ms / 60_000)
    } else if elapsed_ms < 86_400_000 {
        format!("{}h ago", elapsed_ms / 3_600_000)
    } else {
        format!("{}d ago", elapsed_ms / 86_400_000)
    }
}

pub(super) fn local_time(timestamp_ms: u64, millis: bool) -> String {
    local_datetime_value(timestamp_ms).map_or_else(
        || "unavailable".to_string(),
        |timestamp| {
            if millis {
                timestamp.format("%H:%M:%S%.3f").to_string()
            } else {
                timestamp.format("%H:%M:%S").to_string()
            }
        },
    )
}

pub(super) fn local_date_time(timestamp_ms: u64) -> String {
    local_datetime_value(timestamp_ms).map_or_else(
        || "unavailable".to_string(),
        |timestamp| timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
    )
}

fn local_datetime_value(timestamp_ms: u64) -> Option<DateTime<Local>> {
    let timestamp_ms = i64::try_from(timestamp_ms).ok()?;
    DateTime::<Utc>::from_timestamp_millis(timestamp_ms).map(|value| value.with_timezone(&Local))
}

pub(super) fn dns_scope(scope: &DnsScope, compact: bool) -> String {
    match scope {
        DnsScope::Global { order } => format!("default[{order}]"),
        DnsScope::Policy { matchers } if compact => match matchers.split_first() {
            None => "policy:<empty>".to_string(),
            Some((first, [])) => format!("policy:{first}"),
            Some((first, rest)) => format!("policy:{first},+{}", rest.len()),
        },
        DnsScope::Policy { matchers } => format!("policy:{}", matchers.join(",")),
        DnsScope::Link { name } => format!("link:{name}"),
    }
}

pub(super) fn dns_scopes(scopes: &[DnsScope], compact: bool) -> String {
    scopes
        .iter()
        .map(|scope| dns_scope(scope, compact))
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn dns_endpoint(endpoint: &DnsEndpoint, compact: bool) -> String {
    match endpoint {
        DnsEndpoint::Network { addresses } => {
            let rendered = addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if compact && rendered.len() > 1 {
                format!("{} (+{})", rendered[0], rendered.len() - 1)
            } else if rendered.is_empty() {
                "unavailable".to_string()
            } else {
                rendered.join(", ")
            }
        }
        DnsEndpoint::Https { uri } => uri.clone(),
        DnsEndpoint::Dhcp {
            interface,
            current_server,
        } => {
            if compact {
                current_server.map_or_else(
                    || format!("dhcp:{interface}"),
                    |server| format!("{server} (dhcp:{interface})"),
                )
            } else {
                format!("dhcp:{interface}")
            }
        }
    }
}

pub(super) fn dns_outcome(outcome: &DnsOutcome) -> String {
    match outcome {
        DnsOutcome::Answered { response } => match response {
            DnsResponseKind::Answer => "answer".to_string(),
            DnsResponseKind::NxDomain => "nxdomain".to_string(),
            DnsResponseKind::NoData => "nodata".to_string(),
        },
        DnsOutcome::Timeout => "timeout".to_string(),
        DnsOutcome::Error { code, detail } => detail.as_ref().map_or_else(
            || dns_error(*code),
            |detail| format!("{} ({detail})", dns_error(*code)),
        ),
    }
}

pub(super) fn dns_outcome_compact(outcome: &DnsOutcome) -> String {
    match outcome {
        DnsOutcome::Error { code, .. } => dns_error(*code),
        _ => dns_outcome(outcome),
    }
}

pub(super) fn dns_error(code: DnsErrorCode) -> String {
    enum_name(&code)
}

pub(super) fn dns_selection(selection: &DnsSelection) -> String {
    match selection {
        DnsSelection::Hosts => "hosts".to_string(),
        DnsSelection::Global => "default".to_string(),
        DnsSelection::Policy { matcher } => format!("nameserver policy \"{matcher}\""),
        DnsSelection::Link { name } => format!("link {name}"),
        DnsSelection::Explicit { resolver_id } => {
            format!("resolver {}", short_id(resolver_id))
        }
    }
}

pub(super) fn dns_cache(cache: &DnsCacheStatus) -> String {
    match cache {
        DnsCacheStatus::Hit { resolver_id } => format!("hit ({})", short_id(resolver_id)),
        DnsCacheStatus::Miss => "miss".to_string(),
        DnsCacheStatus::NotApplicable => "not applicable".to_string(),
    }
}

pub(super) fn dns_attempt_scope(scope: &DnsAttemptScope) -> String {
    match scope {
        DnsAttemptScope::Global { order } => format!("default[{order}]"),
        DnsAttemptScope::Policy { matcher } => format!("policy:{matcher}"),
        DnsAttemptScope::Link { name } => format!("link:{name}"),
        DnsAttemptScope::Explicit => "explicit".to_string(),
    }
}

pub(super) fn short_id(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

fn trim_decimal(mut value: String) -> String {
    while value.ends_with('0') {
        value.pop();
    }
    if value.ends_with('.') {
        value.pop();
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_keeps_the_requested_side_and_includes_the_marker_in_the_limit() {
        assert_eq!(truncate_end("123456789", 7), "12345..");
        assert_eq!(truncate_start("123456789", 7), "..56789");
        assert_eq!(truncate_end("1234567", 7), "1234567");
        assert_eq!(truncate_start("1234567", 7), "1234567");
        assert_eq!(truncate_end("你好世界", 3), "你..");
        assert_eq!(truncate_start("你好世界", 3), "..界");
    }
}
