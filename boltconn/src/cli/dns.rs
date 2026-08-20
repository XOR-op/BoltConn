use crate::cli::format;
use boltapi::{
    DnsAnswer, DnsFailureKind, DnsLookupDetail, DnsLookupPurpose, DnsLookupResponse, DnsRecordType,
    DnsResolverAttempt, DnsResolverDetail, DnsResolverSummary, FakeIpMapping, Snapshot,
};
use std::fmt::Write as _;
use tabular::{Row, Table};

pub(super) fn render_list(snapshot: Snapshot<DnsResolverSummary>) -> String {
    let mut table = Table::new("{:<}  {:<}  {:<}  {:<}  {:<}  {:>}  {:>}  {:<}  {:<}");
    table.add_row(
        Row::new()
            .with_cell("ID")
            .with_cell("SCOPES")
            .with_cell("PROTO")
            .with_cell("RESOLVER")
            .with_cell("VIA")
            .with_cell("LOOKUPS")
            .with_cell("P50_LATENCY")
            .with_cell("LAST_RESULT")
            .with_cell("LAST_ACTIVE"),
    );
    for resolver in snapshot.items {
        table.add_row(
            Row::new()
                .with_cell(format::short_id(&resolver.id))
                .with_cell(format::dns_scopes(&resolver.scopes, true))
                .with_cell(format::dns_protocol(resolver.protocol))
                .with_cell(format::dns_endpoint(&resolver.endpoint, true))
                .with_cell(format::route_egress(&resolver.via))
                .with_cell(format::count(resolver.lookups))
                .with_cell(
                    resolver
                        .p50_latency_ms
                        .map(format::duration)
                        .unwrap_or_else(|| "-".to_string()),
                )
                .with_cell(
                    resolver
                        .last_result
                        .as_ref()
                        .map(format::dns_outcome_compact)
                        .unwrap_or_else(|| "-".to_string()),
                )
                .with_cell(format::relative_age(
                    resolver.last_active_at_ms,
                    snapshot.observed_at_ms,
                )),
        );
    }
    table.to_string()
}

pub(super) fn render_detail(detail: DnsResolverDetail) -> String {
    let mut output = String::new();
    let summary = &detail.summary;
    writeln!(output, "Resolver {}", format::short_id(&summary.id)).unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "Scopes:           {}",
        format::dns_scopes(&summary.scopes, false)
    )
    .unwrap();
    writeln!(
        output,
        "Protocol:         {}",
        format::dns_protocol(summary.protocol)
    )
    .unwrap();
    writeln!(
        output,
        "Endpoint:         {}",
        format::dns_endpoint(&summary.endpoint, false)
    )
    .unwrap();
    if !detail.current_endpoints.is_empty() {
        writeln!(
            output,
            "Current endpoint: {}",
            detail
                .current_endpoints
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();
    }
    if let Some(server_name) = &detail.tls_server_name {
        writeln!(output, "TLS server name:  {server_name}").unwrap();
    }
    let egress = if detail.chain.is_empty() {
        format!("BoltConn -> {}", format::route_egress(&summary.via))
    } else {
        format!(
            "BoltConn -> {}",
            detail
                .chain
                .iter()
                .map(format::route_hop)
                .collect::<Vec<_>>()
                .join(" -> ")
        )
    };
    writeln!(output, "Egress:           {egress}").unwrap();
    writeln!(
        output,
        "Timeout:          {}",
        format::duration(detail.timeout_ms)
    )
    .unwrap();
    writeln!(output, "Retries:          {}", detail.max_attempts).unwrap();
    writeln!(
        output,
        "Tracking since:   {}",
        format::local_date_time(detail.tracking_started_at_ms)
    )
    .unwrap();

    writeln!(output).unwrap();
    writeln!(output, "Statistics").unwrap();
    let mut statistics = Table::new("{:>}  {:>}  {:>}  {:>}  {:>}  {:<}  {:<}");
    statistics.add_row(
        Row::new()
            .with_cell("LOOKUPS")
            .with_cell("CACHE_HIT")
            .with_cell("ANSWERED")
            .with_cell("TIMEOUT")
            .with_cell("ERROR")
            .with_cell("LAST_RESULT")
            .with_cell("LAST_ACTIVE"),
    );
    statistics.add_row(
        Row::new()
            .with_cell(format::count(summary.lookups))
            .with_cell(format::count(detail.outcomes.cache_hits))
            .with_cell(format::count(detail.outcomes.answered))
            .with_cell(format::count(detail.outcomes.timeout))
            .with_cell(format::count(detail.outcomes.error))
            .with_cell(
                summary
                    .last_result
                    .as_ref()
                    .map(format::dns_outcome_compact)
                    .unwrap_or_else(|| "-".to_string()),
            )
            .with_cell(format::relative_age(
                summary.last_active_at_ms,
                detail.observed_at_ms,
            )),
    );
    write!(output, "{statistics}").unwrap();
    if !detail.outcomes.errors.is_empty() {
        writeln!(
            output,
            "Error breakdown: {}",
            detail
                .outcomes
                .errors
                .iter()
                .map(|entry| format!("{}={}", format::dns_error(entry.code), entry.count))
                .collect::<Vec<_>>()
                .join(",")
        )
        .unwrap();
    }

    writeln!(output).unwrap();
    writeln!(
        output,
        "Latency (last {} non-cache answered lookups)",
        detail.latency.sample_count
    )
    .unwrap();
    let mut latency = Table::new("{:<}  {:<}");
    latency.add_row(Row::new().with_cell("P50").with_cell("P90"));
    latency.add_row(
        Row::new()
            .with_cell(
                detail
                    .latency
                    .p50_ms
                    .map(format::duration)
                    .unwrap_or_else(|| "-".to_string()),
            )
            .with_cell(
                detail
                    .latency
                    .p90_ms
                    .map(format::duration)
                    .unwrap_or_else(|| "-".to_string()),
            ),
    );
    write!(output, "{latency}").unwrap();

    if !detail.failure_episodes.is_empty() {
        writeln!(output).unwrap();
        writeln!(output, "Failure episodes").unwrap();
        let mut episodes = Table::new("{:<}  {:<}  {:>}  {:<}  {:<}");
        episodes.add_row(
            Row::new()
                .with_cell("START")
                .with_cell("LAST")
                .with_cell("FAILURES")
                .with_cell("BREAKDOWN")
                .with_cell("RECOVERED"),
        );
        for episode in detail.failure_episodes {
            let breakdown = episode
                .breakdown
                .iter()
                .map(|entry| match &entry.failure {
                    DnsFailureKind::Timeout => format!("timeout={}", entry.count),
                    DnsFailureKind::Error { code } => {
                        format!("{}={}", format::dns_error(*code), entry.count)
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
            episodes.add_row(
                Row::new()
                    .with_cell(format::local_date_time(episode.started_at_ms))
                    .with_cell(format::local_date_time(episode.last_failure_at_ms))
                    .with_cell(format::count(episode.failures))
                    .with_cell(breakdown)
                    .with_cell(if episode.recovered_at_ms.is_some() {
                        "yes"
                    } else {
                        "no"
                    }),
            );
        }
        write!(output, "{episodes}").unwrap();
    }

    output
}

pub(super) fn render_lookup(
    response: DnsLookupResponse,
    resolvers: &[DnsResolverSummary],
) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "Selection: {}",
        format::dns_selection(&response.lookup.selection)
    )
    .unwrap();
    writeln!(
        output,
        "Cache:     {}",
        format::dns_cache(&response.lookup.cache)
    )
    .unwrap();
    writeln!(output).unwrap();
    write_lookup_evidence(&mut output, &response.lookup, resolvers);
    output
}

pub(super) fn render_lookup_section(
    lookup: &DnsLookupDetail,
    resolvers: &[DnsResolverSummary],
) -> String {
    let mut output = String::new();
    writeln!(output, "  Purpose:    {}", lookup_purpose(&lookup.purpose)).unwrap();
    let record_types = lookup
        .attempts
        .iter()
        .map(|attempt| format::enum_name(&attempt.record_type).to_uppercase())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("/");
    writeln!(
        output,
        "  Query:      {}{}",
        lookup.name,
        if record_types.is_empty() {
            String::new()
        } else {
            format!(" {record_types}")
        }
    )
    .unwrap();
    writeln!(
        output,
        "  Selection:  {}",
        format::dns_selection(&lookup.selection)
    )
    .unwrap();
    writeln!(output, "  Cache:      {}", format::dns_cache(&lookup.cache)).unwrap();
    let mut evidence = String::new();
    write_lookup_evidence(&mut evidence, lookup, resolvers);
    for line in evidence.lines() {
        writeln!(output, "  {line}").unwrap();
    }
    output
}

fn write_lookup_evidence(
    output: &mut String,
    lookup: &DnsLookupDetail,
    resolvers: &[DnsResolverSummary],
) {
    if !lookup.attempts.is_empty() {
        let mut attempts = Table::new("{:>}  {:<}  {:<}  {:<}  {:<}  {:>}  {:<}");
        attempts.add_row(
            Row::new()
                .with_cell("#")
                .with_cell("TYPE")
                .with_cell("SCOPE")
                .with_cell("RESOLVER")
                .with_cell("VIA")
                .with_cell("DURATION")
                .with_cell("RESULT"),
        );
        for (index, attempt) in lookup.attempts.iter().enumerate() {
            let resolver = resolvers
                .iter()
                .find(|resolver| resolver.id == attempt.resolver_id);
            attempts.add_row(attempt_row(index, attempt, resolver));
        }
        write!(output, "{attempts}").unwrap();
    } else {
        writeln!(output, "Attempts: none").unwrap();
    }

    writeln!(output, "Result:   {}", format::dns_outcome(&lookup.result)).unwrap();
    writeln!(output, "Duration: {}", format::duration(lookup.duration_ms)).unwrap();
    writeln!(output).unwrap();
    if lookup.answers.is_empty() {
        writeln!(output, "Answers: none").unwrap();
    } else {
        writeln!(output, "Answers").unwrap();
        let mut answers = Table::new("{:<}  {:<}  {:<}");
        answers.add_row(
            Row::new()
                .with_cell("TYPE")
                .with_cell("ADDRESS")
                .with_cell("SELECTED"),
        );
        for answer in &lookup.answers {
            answers.add_row(answer_row(answer));
        }
        write!(output, "{answers}").unwrap();
    }
}

fn attempt_row(
    index: usize,
    attempt: &DnsResolverAttempt,
    resolver: Option<&DnsResolverSummary>,
) -> Row {
    let (endpoint, via) = resolver.map_or_else(
        || {
            (
                format::short_id(&attempt.resolver_id).to_string(),
                "-".to_string(),
            )
        },
        |resolver| {
            (
                format::dns_endpoint(&resolver.endpoint, true),
                format::route_egress(&resolver.via),
            )
        },
    );
    Row::new()
        .with_cell(index + 1)
        .with_cell(record_type(attempt.record_type))
        .with_cell(format::dns_attempt_scope(&attempt.scope))
        .with_cell(endpoint)
        .with_cell(via)
        .with_cell(format::duration(attempt.duration_ms))
        .with_cell(format::dns_outcome_compact(&attempt.result))
}

fn answer_row(answer: &DnsAnswer) -> Row {
    Row::new()
        .with_cell(record_type(answer.record_type))
        .with_cell(answer.address)
        .with_cell(if answer.selected { "yes" } else { "no" })
}

fn record_type(record_type: DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "A",
        DnsRecordType::Aaaa => "AAAA",
    }
}

fn lookup_purpose(purpose: &DnsLookupPurpose) -> String {
    match purpose {
        DnsLookupPurpose::Destination => "destination".to_string(),
        DnsLookupPurpose::ProxyServer { proxy } => format!("proxy server ({proxy})"),
        DnsLookupPurpose::LinkServer { link } => format!("link server ({link})"),
        DnsLookupPurpose::Diagnostic => "diagnostic".to_string(),
    }
}

pub(super) fn render_mapping(mapping: FakeIpMapping) -> String {
    format!("{}\t{}\n", mapping.fake_ip, mapping.domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boltapi::{
        DnsCacheStatus, DnsErrorCode, DnsErrorCount, DnsFailureCount, DnsFailureEpisode,
        DnsLatency, DnsOutcome, DnsOutcomeCounts, DnsResponseKind, DnsScope, DnsSelection,
        RouteEgress,
    };

    #[test]
    fn empty_list_keeps_the_complete_header() {
        let output = render_list(Snapshot {
            observed_at_ms: 0,
            items: Vec::new(),
        });
        assert!(output.contains("ID"));
        assert!(output.contains("P50_LATENCY"));
        assert!(output.contains("LAST_ACTIVE"));
    }

    #[test]
    fn lookup_renders_failures_and_explicit_absence() {
        let output = render_lookup(
            DnsLookupResponse {
                observed_at_ms: 10,
                lookup: DnsLookupDetail {
                    purpose: DnsLookupPurpose::Diagnostic,
                    name: "example.com".to_string(),
                    selection: DnsSelection::Global,
                    cache: DnsCacheStatus::Miss,
                    attempts: vec![DnsResolverAttempt {
                        resolver_id: "0123456789abcdef".to_string(),
                        scope: boltapi::DnsAttemptScope::Global { order: 1 },
                        record_type: DnsRecordType::A,
                        duration_ms: 1_600,
                        result: DnsOutcome::Timeout,
                    }],
                    answers: Vec::new(),
                    result: DnsOutcome::Answered {
                        response: DnsResponseKind::NoData,
                    },
                    duration_ms: 1_600,
                },
            },
            &[DnsResolverSummary {
                id: "0123456789abcdef".to_string(),
                scopes: Vec::new(),
                protocol: boltapi::DnsProtocol::Udp,
                endpoint: boltapi::DnsEndpoint::Https {
                    uri: "https://dns.example/dns-query".to_string(),
                },
                via: RouteEgress::Direct,
                lookups: 1,
                p50_latency_ms: None,
                last_result: None,
                last_active_at_ms: None,
            }],
        );
        assert!(output.contains("https://dns.example/dns-query"));
        assert!(output.contains("timeout"));
        assert!(output.contains("nodata"));
        assert!(output.contains("Answers: none"));
    }

    #[test]
    fn resolver_detail_renders_failure_history_and_variable_endpoints() {
        let output = render_detail(DnsResolverDetail {
            observed_at_ms: 20_000,
            summary: DnsResolverSummary {
                id: "0123456789abcdef".to_string(),
                scopes: vec![DnsScope::Global { order: 1 }],
                protocol: boltapi::DnsProtocol::Udp,
                endpoint: boltapi::DnsEndpoint::Dhcp {
                    interface: "en0".to_string(),
                    current_server: Some("192.0.2.53:53".parse().unwrap()),
                },
                via: RouteEgress::Interface {
                    name: "en0".to_string(),
                },
                lookups: 5,
                p50_latency_ms: Some(31),
                last_result: Some(DnsOutcome::Timeout),
                last_active_at_ms: Some(19_000),
            },
            current_endpoints: vec!["192.0.2.53:53".parse().unwrap()],
            tls_server_name: None,
            chain: Vec::new(),
            timeout_ms: 5_000,
            max_attempts: 2,
            tracking_started_at_ms: 1_000,
            outcomes: DnsOutcomeCounts {
                cache_hits: 1,
                answered: 3,
                timeout: 1,
                error: 1,
                errors: vec![DnsErrorCount {
                    code: DnsErrorCode::Servfail,
                    count: 1,
                }],
            },
            latency: DnsLatency {
                sample_count: 2,
                p50_ms: Some(31),
                p90_ms: Some(44),
            },
            failure_episodes: vec![DnsFailureEpisode {
                started_at_ms: 10_000,
                last_failure_at_ms: 11_000,
                recovered_at_ms: Some(12_000),
                failures: 2,
                breakdown: vec![DnsFailureCount {
                    failure: DnsFailureKind::Timeout,
                    count: 2,
                }],
            }],
        });
        assert!(output.contains("Endpoint:         dhcp:en0"));
        assert!(output.contains("Current endpoint: 192.0.2.53:53"));
        assert!(!output.contains("TLS server name:"));
        assert!(output.contains("Error breakdown: servfail=1"));
        assert!(output.contains("Failure episodes"));
        assert!(output.contains("timeout=2"));
    }
}
