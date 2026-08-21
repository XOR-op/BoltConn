use crate::cli::{dns, format};
use boltapi::{
    ConnDetail, ConnOrigin, ConnSummary, DestinationResolution, IdentificationSource, RuleOrigin,
    Snapshot,
};
use std::fmt::Write as _;
use tabular::{Row, Table};

const ORIGIN_MAX_CHARS: usize = 15;
const TARGET_MAX_CHARS: usize = 50;

pub(super) fn render_list(mut snapshot: Snapshot<ConnSummary>) -> String {
    snapshot
        .items
        .sort_by_key(|connection| (connection.started_at_ms, connection.id));
    let mut table = Table::new("{:>}  {:<}  {:<}  {:>}  {:<}  {:<}  {:<}  {:<}  {:<}  {:<}");
    table.add_row(
        Row::new()
            .with_cell("ID")
            .with_cell("STATE")
            .with_cell("START")
            .with_cell("DUR")
            .with_cell("ORIGIN")
            .with_cell("PROTO")
            .with_cell("TARGET")
            .with_cell("VIA")
            .with_cell("TRAFFIC")
            .with_cell("RESULT"),
    );
    for connection in snapshot.items {
        table.add_row(
            Row::new()
                .with_cell(connection.id)
                .with_cell(format::enum_name(&connection.state))
                .with_cell(format::local_time(connection.started_at_ms, false))
                .with_cell(format::duration(connection.duration_ms))
                .with_cell(format::truncate_end(
                    &origin(&connection.origin),
                    ORIGIN_MAX_CHARS,
                ))
                .with_cell(connection.protocol.to_string())
                .with_cell(format::truncate_start(
                    &connection.target.to_string(),
                    TARGET_MAX_CHARS,
                ))
                .with_cell(format::optional(
                    connection.via.as_ref().map(format::route_selection),
                ))
                .with_cell(format::traffic(connection.traffic))
                .with_cell(format::optional(
                    connection.result.as_ref().map(format::enum_name),
                )),
        );
    }
    table.to_string()
}

pub(super) fn render_detail(
    detail: ConnDetail,
    resolvers: &[boltapi::DnsResolverSummary],
) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "Connection #{} — {}",
        detail.summary.id,
        format::enum_name(&detail.summary.state)
    )
    .unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "Result:       {}",
        format::optional(detail.summary.result.as_ref().map(format::enum_name))
    )
    .unwrap();
    writeln!(
        output,
        "Stage:        {}",
        format::optional(
            detail
                .termination
                .as_ref()
                .and_then(|termination| termination.stage.as_ref())
                .map(format::enum_name)
        )
    )
    .unwrap();
    writeln!(
        output,
        "Started:      {}",
        format::local_time(detail.summary.started_at_ms, true)
    )
    .unwrap();
    match detail.established_at_ms {
        Some(established_at_ms) => writeln!(
            output,
            "Established:  {}  (setup {})",
            format::local_time(established_at_ms, true),
            format::duration(established_at_ms.saturating_sub(detail.summary.started_at_ms))
        )
        .unwrap(),
        None => writeln!(output, "Established:  never").unwrap(),
    }
    writeln!(
        output,
        "Ended:        {}",
        detail
            .ended_at_ms
            .map(|time| format::local_time(time, true))
            .unwrap_or_else(|| "-".to_string())
    )
    .unwrap();
    writeln!(
        output,
        "Duration:     {}",
        format::duration(detail.summary.duration_ms)
    )
    .unwrap();
    if let Some(detail_text) = detail
        .termination
        .as_ref()
        .and_then(|termination| termination.detail.as_deref())
        .filter(|detail_text| {
            !detail_text.trim().is_empty()
                && detail
                    .summary
                    .result
                    .as_ref()
                    .is_none_or(|result| detail_text.trim() != format::enum_name(result))
        })
    {
        writeln!(output, "Detail:       {detail_text}").unwrap();
    }

    writeln!(output).unwrap();
    writeln!(output, "Flow").unwrap();
    writeln!(output, "  Inbound:     {}", detail.flow.inbound).unwrap();
    writeln!(output, "  Source:      {}", detail.flow.source).unwrap();
    writeln!(output, "  Protocol:    {}", detail.summary.protocol).unwrap();
    writeln!(output, "  Accepted:    {}", detail.flow.accepted).unwrap();
    match &detail.flow.identified {
        Some(identified) => writeln!(
            output,
            "  Identified:  {} ({})",
            identified.target,
            identification_source(identified.source)
        )
        .unwrap(),
        None => writeln!(output, "  Identified:  unavailable").unwrap(),
    }
    writeln!(
        output,
        "  Resolved:    {}",
        resolution(&detail.flow.resolution)
    )
    .unwrap();

    if let Some(process) = &detail.process {
        writeln!(output).unwrap();
        writeln!(output, "Process").unwrap();
        writeln!(output, "  Name:     {}", process.name).unwrap();
        writeln!(output, "  PID:      {}", process.pid).unwrap();
        if let Some(tag) = &process.tag {
            writeln!(output, "  Tag:      {tag}").unwrap();
        }
        writeln!(output, "  Path:     {}", process.path).unwrap();
        writeln!(output, "  Command:  {}", process.cmdline).unwrap();
        let parents = process
            .parents
            .iter()
            .filter(|parent| parent.path.is_some() || parent.cmdline.is_some())
            .collect::<Vec<_>>();
        if !parents.is_empty() {
            writeln!(output, "  Parents:").unwrap();
            for parent in parents {
                let path = parent.path.as_deref().unwrap_or("unavailable");
                let executable = parent
                    .name
                    .as_deref()
                    .filter(|name| !name.is_empty())
                    .or_else(|| {
                        std::path::Path::new(path)
                            .file_name()
                            .and_then(|name| name.to_str())
                    })
                    .unwrap_or("unavailable");
                if let Some(command) = &parent.cmdline {
                    writeln!(output, "    {executable} — {command}").unwrap();
                } else {
                    writeln!(output, "    {executable} — {path}").unwrap();
                }
            }
        }
    }

    writeln!(output).unwrap();
    writeln!(output, "Route").unwrap();
    if let Some(route) = &detail.route {
        writeln!(output, "  Matched:      {}", route.matched_rule).unwrap();
        writeln!(output, "  Source:       {}", rule_origin(&route.origin)).unwrap();
        if !route.expanded_from.is_empty() {
            writeln!(
                output,
                "  Expanded via: {}",
                route
                    .expanded_from
                    .iter()
                    .map(format::config_location)
                    .collect::<Vec<_>>()
                    .join(" -> ")
            )
            .unwrap();
        }
        writeln!(
            output,
            "  Selected:     {}",
            format::route_selection(&route.selected)
        )
        .unwrap();
    } else {
        writeln!(output, "  Not selected.").unwrap();
    }

    writeln!(output).unwrap();
    writeln!(output, "DNS").unwrap();
    if detail.dns.total_lookups == 0 {
        match detail.flow.resolution {
            DestinationResolution::Delegated => writeln!(output, "  Delegated to proxy.").unwrap(),
            DestinationResolution::NotRequired => writeln!(output, "  Not required.").unwrap(),
            _ => writeln!(output, "  Not used.").unwrap(),
        }
    } else {
        if detail.dns.total_lookups > detail.dns.lookups.len() as u64 {
            writeln!(
                output,
                "  Showing latest {} of {} lookups.",
                detail.dns.lookups.len(),
                detail.dns.total_lookups
            )
            .unwrap();
        }
        for (index, lookup) in detail.dns.lookups.iter().enumerate() {
            if index > 0 {
                writeln!(output).unwrap();
            }
            write!(output, "{}", dns::render_lookup_section(lookup, resolvers)).unwrap();
        }
    }

    writeln!(output).unwrap();
    writeln!(output, "Links").unwrap();
    if detail.links.is_empty() {
        writeln!(output, "  No shared links.").unwrap();
    } else {
        for link in &detail.links {
            writeln!(
                output,
                "  {}  type={}  generation={}",
                link.name,
                format::link_kind(link.kind),
                link.generation
            )
            .unwrap();
        }
    }

    writeln!(output).unwrap();
    writeln!(output, "Traffic").unwrap();
    writeln!(
        output,
        "  Uploaded:    {}",
        format::bytes(detail.summary.traffic.upload_bytes)
    )
    .unwrap();
    writeln!(
        output,
        "  Downloaded:  {}",
        format::bytes(detail.summary.traffic.download_bytes)
    )
    .unwrap();
    output
}

fn origin(origin: &ConnOrigin) -> String {
    match origin {
        ConnOrigin::Process { name, tag } => tag
            .as_ref()
            .map_or_else(|| name.clone(), |tag| format!("{name}{{{tag}}}")),
        ConnOrigin::Network { source_ip } => source_ip.to_string(),
    }
}

fn identification_source(source: IdentificationSource) -> &'static str {
    match source {
        IdentificationSource::FakeIpMapping => "fake-IP mapping",
        IdentificationSource::TlsSni => "TLS SNI",
        IdentificationSource::HttpHost => "HTTP Host",
    }
}

fn resolution(resolution: &DestinationResolution) -> String {
    match resolution {
        DestinationResolution::NotStarted => "not started".to_string(),
        DestinationResolution::InProgress => "in progress".to_string(),
        DestinationResolution::Resolved { address } => address.to_string(),
        DestinationResolution::Delegated => "delegated to proxy".to_string(),
        DestinationResolution::NotRequired => "not required".to_string(),
        DestinationResolution::Failed => "unavailable".to_string(),
    }
}

fn rule_origin(origin: &RuleOrigin) -> String {
    match origin {
        RuleOrigin::Config { location } => format::config_location(location),
        RuleOrigin::Temporary => "temporary rule".to_string(),
        RuleOrigin::External => "external decision".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boltapi::{
        ConnDnsActivity, ConnFlow, ConnResultCode, ConnState, ConnTermination, NetworkAddr,
        SessionProtocol, Traffic,
    };

    fn summary(state: ConnState, result: Option<ConnResultCode>) -> ConnSummary {
        ConnSummary {
            id: 42,
            state,
            started_at_ms: 1_000,
            duration_ms: 5_017,
            origin: ConnOrigin::Process {
                name: "curl".to_string(),
                tag: Some("api-test".to_string()),
            },
            protocol: SessionProtocol::Tls,
            target: NetworkAddr::Domain {
                name: "a-very-long-api-name.example.com".to_string(),
                port: 443,
            },
            via: None,
            traffic: Traffic {
                upload_bytes: 0,
                download_bytes: 1_024,
            },
            result,
        }
    }

    #[test]
    fn list_renders_terminal_and_live_absence_with_values_within_limits() {
        let empty = render_list(Snapshot {
            observed_at_ms: 10_000,
            items: Vec::new(),
        });
        assert!(empty.contains("ID"));
        assert!(empty.contains("RESULT"));

        let output = render_list(Snapshot {
            observed_at_ms: 10_000,
            items: vec![
                summary(ConnState::Active, None),
                summary(ConnState::Failed, Some(ConnResultCode::DnsTimeout)),
            ],
        });
        assert!(output.contains("a-very-long-api-name.example.com:443"));
        assert!(output.contains("curl{api-test}"));
        assert!(output.contains("dns_timeout"));
        assert!(output.contains("↑0 ↓1K"));
    }

    #[test]
    fn list_truncates_origin_at_the_end_and_target_at_the_start() {
        let mut connection = summary(ConnState::Active, None);
        connection.origin = ConnOrigin::Process {
            name: "verylongapplication".to_string(),
            tag: None,
        };
        connection.target = NetworkAddr::Domain {
            name: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz".to_string(),
            port: 1234,
        };

        let output = render_list(Snapshot {
            observed_at_ms: 10_000,
            items: vec![connection],
        });

        assert!(output.contains("verylongappli.."));
        assert!(output.contains("..jklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz:1234"));
        assert!(!output.contains("verylongapplication"));
        assert!(!output.contains("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz:1234"));
    }

    #[test]
    fn detail_explicitly_renders_meaningful_absence() {
        let detail = ConnDetail {
            observed_at_ms: 10_000,
            summary: summary(ConnState::Failed, Some(ConnResultCode::DnsTimeout)),
            established_at_ms: None,
            ended_at_ms: Some(6_017),
            flow: ConnFlow {
                inbound: "tun".to_string(),
                source: "198.18.0.1:1234".parse().unwrap(),
                accepted: NetworkAddr::Socket {
                    address: "198.18.0.7:443".parse().unwrap(),
                },
                identified: None,
                resolution: DestinationResolution::Failed,
            },
            process: None,
            route: None,
            dns: ConnDnsActivity {
                total_lookups: 0,
                lookups: Vec::new(),
            },
            links: Vec::new(),
            termination: Some(ConnTermination {
                code: ConnResultCode::DnsTimeout,
                stage: Some(boltapi::ConnStage::Resolving),
                detail: None,
            }),
        };
        let output = render_detail(detail, &[]);
        assert!(output.contains("Established:  never"));
        assert!(output.contains("Identified:  unavailable"));
        assert!(output.contains("Resolved:    unavailable"));
        assert!(output.contains("Not selected."));
        assert!(output.contains("Not used."));
        assert!(output.contains("No shared links."));
        assert!(!output.contains("Process\n"));
    }

    #[test]
    fn parent_process_uses_executable_name_before_full_command() {
        let detail = ConnDetail {
            observed_at_ms: 10_000,
            summary: summary(ConnState::Active, None),
            established_at_ms: Some(2_000),
            ended_at_ms: None,
            flow: ConnFlow {
                inbound: "tun".to_string(),
                source: "198.18.0.1:1234".parse().unwrap(),
                accepted: NetworkAddr::Socket {
                    address: "198.18.0.7:443".parse().unwrap(),
                },
                identified: None,
                resolution: DestinationResolution::NotStarted,
            },
            process: Some(boltapi::ProcessSchema {
                pid: 9_241,
                path: "/Applications/Firefox.app/Contents/MacOS/firefox".to_string(),
                name: "firefox".to_string(),
                cmdline: "firefox --profile default".to_string(),
                cwd: "/tmp".to_string(),
                parents: vec![boltapi::ProcessParentSchema {
                    pid: 9_200,
                    name: Some("launcher".to_string()),
                    path: Some("/Applications/Launcher.app/Contents/MacOS/launcher".to_string()),
                    cmdline: Some(
                        "/Applications/Launcher.app/Contents/MacOS/launcher --open firefox"
                            .to_string(),
                    ),
                    cwd: None,
                }],
                tag: None,
            }),
            route: None,
            dns: ConnDnsActivity {
                total_lookups: 0,
                lookups: Vec::new(),
            },
            links: Vec::new(),
            termination: None,
        };

        let output = render_detail(detail, &[]);
        assert!(output.contains(
            "    launcher — /Applications/Launcher.app/Contents/MacOS/launcher --open firefox"
        ));
        assert!(!output.contains("    /Applications/Launcher.app/Contents/MacOS/launcher —"));
    }
}
