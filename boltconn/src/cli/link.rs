use crate::cli::{dns, format};
use boltapi::{DnsOutcome, DnsResolverSummary, LinkDetail, LinkReasonCode, LinkSummary, Snapshot};
use std::fmt::Write as _;
use tabular::{Row, Table};

pub(super) fn render_list(mut snapshot: Snapshot<LinkSummary>) -> String {
    snapshot
        .items
        .sort_by(|left, right| left.name.cmp(&right.name));
    let mut table = Table::new("{:<}  {:<}  {:<}  {:<}  {:>}  {:>}  {:<}  {:<}  {:<}  {:<}");
    table.add_row(
        Row::new()
            .with_cell("NAME")
            .with_cell("TYPE")
            .with_cell("STATE")
            .with_cell("HEALTH")
            .with_cell("GEN")
            .with_cell("ACTIVE")
            .with_cell("LAST_ACTIVE")
            .with_cell("TRAFFIC")
            .with_cell("TOTAL_TRAFFIC")
            .with_cell("REASON"),
    );
    for link in snapshot.items {
        table.add_row(
            Row::new()
                .with_cell(link.name)
                .with_cell(format::link_kind(link.kind))
                .with_cell(format::enum_name(&link.state))
                .with_cell(format::enum_name(&link.health))
                .with_cell(link.generation)
                .with_cell(link.active_conn_count)
                .with_cell(format::relative_age(
                    link.last_active_at_ms,
                    snapshot.observed_at_ms,
                ))
                .with_cell(format::traffic(link.traffic))
                .with_cell(format::traffic(link.total_traffic))
                .with_cell(format::optional(
                    link.reason
                        .as_ref()
                        .map(|reason| format::enum_name(&reason.code)),
                )),
        );
    }
    table.to_string()
}

pub(super) fn render_detail(detail: LinkDetail, resolvers: &[DnsResolverSummary]) -> String {
    let mut output = String::new();
    let summary = &detail.summary;
    writeln!(output, "Link:        {}", summary.name).unwrap();
    writeln!(output, "Type:        {}", format::link_kind(summary.kind)).unwrap();
    writeln!(output, "Generation:  {}", summary.generation).unwrap();
    writeln!(output, "State:       {}", format::enum_name(&summary.state)).unwrap();
    writeln!(
        output,
        "Health:      {}",
        format::enum_name(&summary.health)
    )
    .unwrap();
    writeln!(
        output,
        "Reason:      {}",
        format::optional(
            summary
                .reason
                .as_ref()
                .map(|reason| format::enum_name(&reason.code))
        )
    )
    .unwrap();
    if let Some(reason_detail) = summary
        .reason
        .as_ref()
        .and_then(|reason| reason.detail.as_deref())
    {
        writeln!(output, "Detail:      {reason_detail}").unwrap();
    }

    writeln!(output).unwrap();
    writeln!(
        output,
        "Created:      {}",
        format::local_time(detail.created_at_ms, true)
    )
    .unwrap();
    writeln!(
        output,
        "Last active:  {}  ({})",
        detail
            .summary
            .last_active_at_ms
            .map(|time| format::local_time(time, true))
            .unwrap_or_else(|| "never".to_string()),
        format::relative_age(detail.summary.last_active_at_ms, detail.observed_at_ms)
    )
    .unwrap();
    if let Some(ended_at_ms) = detail.ended_at_ms {
        writeln!(
            output,
            "Ended:        {}",
            format::local_time(ended_at_ms, true)
        )
        .unwrap();
        writeln!(
            output,
            "Duration:     {}",
            format::duration(detail.duration_ms)
        )
        .unwrap();
    }

    writeln!(output).unwrap();
    writeln!(output, "Active connections:  {}", summary.active_conn_count).unwrap();
    writeln!(
        output,
        "Traffic:             {}",
        format::traffic(summary.traffic)
    )
    .unwrap();
    writeln!(
        output,
        "Total traffic:       {}",
        format::traffic(summary.total_traffic)
    )
    .unwrap();

    writeln!(output).unwrap();
    writeln!(output, "Server:     {}", detail.server).unwrap();
    writeln!(
        output,
        "Connected:  {}",
        if detail.connected_endpoints.is_empty() {
            "unavailable".to_string()
        } else {
            detail
                .connected_endpoints
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    )
    .unwrap();

    writeln!(output).unwrap();
    writeln!(output, "Chain").unwrap();
    writeln!(output, "  BoltConn").unwrap();
    if detail.chain.is_empty() {
        writeln!(output, "    → {}  (this link)", summary.name).unwrap();
    } else {
        for (index, hop) in detail.chain.iter().enumerate() {
            writeln!(
                output,
                "    → {}{}",
                format::route_hop(hop),
                if index + 1 == detail.chain.len() {
                    "  (this link)"
                } else {
                    ""
                }
            )
            .unwrap();
        }
    }

    writeln!(output).unwrap();
    writeln!(output, "DNS").unwrap();
    writeln!(
        output,
        "  Queries:    {}",
        format::count(detail.dns.lookups)
    )
    .unwrap();
    writeln!(
        output,
        "  Cache hits: {}",
        format::count(detail.dns.outcomes.cache_hits)
    )
    .unwrap();
    writeln!(
        output,
        "  Answered:   {}",
        format::count(detail.dns.outcomes.answered)
    )
    .unwrap();
    writeln!(
        output,
        "  Timeouts:   {}",
        format::count(detail.dns.outcomes.timeout)
    )
    .unwrap();
    writeln!(
        output,
        "  Errors:     {}",
        format::count(detail.dns.outcomes.error)
    )
    .unwrap();
    if let Some(lookup) = &detail.dns.latest_lookup {
        if failure_explains_health(summary, &lookup.result) {
            writeln!(output, "  Latest lookup:").unwrap();
            write!(output, "{}", dns::render_lookup_section(lookup, resolvers)).unwrap();
        } else {
            let answers = lookup
                .answers
                .iter()
                .map(|answer| answer.address.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(
                output,
                "  Last lookup: {} → {}, {}",
                lookup.name,
                if answers.is_empty() {
                    format::dns_outcome(&lookup.result)
                } else {
                    answers
                },
                format::duration(lookup.duration_ms)
            )
            .unwrap();
        }
    } else {
        writeln!(output, "  Last lookup: never").unwrap();
    }
    output
}

fn failure_explains_health(summary: &LinkSummary, outcome: &DnsOutcome) -> bool {
    let failed_lookup = !matches!(outcome, DnsOutcome::Answered { .. });
    let dns_reason = summary.reason.as_ref().is_some_and(|reason| {
        matches!(
            reason.code,
            LinkReasonCode::DnsFailed | LinkReasonCode::DependencyFailed
        )
    });
    failed_lookup && dns_reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use boltapi::{
        DnsActivity, DnsOutcomeCounts, LinkHealth, LinkKind, LinkState, NetworkAddr, Traffic,
    };

    fn detail() -> LinkDetail {
        LinkDetail {
            observed_at_ms: 10_000,
            summary: LinkSummary {
                name: "shared-link-with-a-long-name".to_string(),
                kind: LinkKind::Ssh,
                state: LinkState::Idle,
                health: LinkHealth::Unknown,
                generation: 3,
                active_conn_count: 0,
                last_active_at_ms: None,
                traffic: Traffic {
                    upload_bytes: 0,
                    download_bytes: 0,
                },
                total_traffic: Traffic {
                    upload_bytes: 1_024,
                    download_bytes: 2_048,
                },
                reason: None,
            },
            created_at_ms: 1_000,
            ended_at_ms: None,
            duration_ms: 9_000,
            server: NetworkAddr::Domain {
                name: "ssh.example.com".to_string(),
                port: 22,
            },
            connected_endpoints: Vec::new(),
            chain: Vec::new(),
            dns: DnsActivity {
                lookups: 0,
                outcomes: DnsOutcomeCounts {
                    cache_hits: 0,
                    answered: 0,
                    timeout: 0,
                    error: 0,
                    errors: Vec::new(),
                },
                latest_lookup: None,
            },
        }
    }

    #[test]
    fn list_is_alphabetical_and_keeps_empty_header() {
        let empty = render_list(Snapshot {
            observed_at_ms: 10_000,
            items: Vec::new(),
        });
        assert!(empty.contains("NAME"));
        assert!(empty.contains("REASON"));

        let mut first = detail().summary;
        first.name = "z-link".to_string();
        let mut second = first.clone();
        second.name = "a-link".to_string();
        let output = render_list(Snapshot {
            observed_at_ms: 10_000,
            items: vec![first, second],
        });
        assert!(output.find("a-link").unwrap() < output.find("z-link").unwrap());
        assert!(output.contains("TOTAL_TRAFFIC"));
    }

    #[test]
    fn detail_renders_explicit_absence_for_unused_link() {
        let output = render_detail(detail(), &[]);
        assert!(output.contains("Connected:  unavailable"));
        assert!(output.contains("Last lookup: never"));
    }
}
