use crate::config::{FirewallSubnetMode, FirewallSubnetPreset, RawDockerMasqueradeConfig};
use std::io;
use std::net::IpAddr;
use std::process::{Command, Stdio};

/// Detects whether to use nft or iptables, and inserts NAT POSTROUTING rules
/// to bypass Docker's MASQUERADE for traffic destined to the TUN device.
///
/// Docker adds MASQUERADE rules like:
///   `-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE`
/// which rewrites the source IP of container traffic, preventing us from
/// identifying the original source. We insert a higher-priority RETURN rule:
///   `-I POSTROUTING 1 -s 172.17.0.0/16 -o <tun> -j RETURN`
/// so that traffic routed through our TUN device skips the MASQUERADE.
pub struct FirewallGuard {
    backend: FirewallBackend,
    rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone)]
struct FirewallRule {
    subnet: String,
    tun_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallBackend {
    Nft,
    IptablesNft,
    IptablesLegacy,
}

fn command_succeeds(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn command_output(cmd: &str, args: &[&str]) -> io::Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if output.status.success() {
        String::from_utf8(output.stdout).map_err(io::Error::other)
    } else {
        Err(io::Error::other(format!(
            "{} exited with {}",
            cmd, output.status
        )))
    }
}

/// Detect whether the kernel's nat table is managed by nft natively,
/// iptables-nft (iptables translating to nft), or legacy iptables.
fn detect_backend() -> Option<FirewallBackend> {
    // Check if nft is available and the nat table exists in nft
    if let Ok(output) = command_output("nft", &["list", "tables"]) {
        let has_nft_nat = output.lines().any(|l| {
            // e.g. "table ip nat"
            let parts: Vec<&str> = l.split_whitespace().collect();
            parts.len() >= 3 && parts[0] == "table" && parts[1] == "ip" && parts[2] == "nat"
        });
        if has_nft_nat {
            // The nat table exists in nft. Check if it's managed by iptables-nft
            // by looking for the iptables-nft comment marker in chain names or rules.
            if let Ok(detail) = command_output("nft", &["list", "table", "ip", "nat"]) {
                if detail.contains("iptables") || detail.contains("compat") {
                    // Table is created/managed by iptables-nft translation layer.
                    // We must use iptables to modify it, not raw nft commands.
                    if command_succeeds("iptables", &["-t", "nat", "-L", "POSTROUTING", "-n"]) {
                        return Some(FirewallBackend::IptablesNft);
                    }
                }
                // Pure nft nat table
                return Some(FirewallBackend::Nft);
            }
        }
    }

    // No nft nat table. Check if iptables is available with a nat table.
    if command_succeeds("iptables", &["-t", "nat", "-L", "POSTROUTING", "-n"]) {
        return Some(FirewallBackend::IptablesLegacy);
    }

    None
}

/// Find Docker bridge subnets by enumerating network interfaces whose names
/// start with "docker" or "br-" (custom Docker networks) and extracting their
/// IPv4 subnets.
fn find_docker_subnets() -> Vec<String> {
    let mut subnets = Vec::new();
    for iface in pnet_datalink::interfaces() {
        if iface.name.starts_with("docker") || iface.name.starts_with("br-") {
            for ip in &iface.ips {
                if let IpAddr::V4(_) = ip.ip() {
                    subnets.push(ip.to_string());
                }
            }
        }
    }
    subnets
}

const DEFAULT_DOCKER_SUBNET: &str = "172.16.0.0/12";

impl FirewallGuard {
    /// Insert NAT bypass rules for the given TUN device based on the config.
    /// Returns `None` if disabled, no subnets found, or no firewall backend available.
    pub fn setup(tun_name: &str, config: &RawDockerMasqueradeConfig) -> Option<Self> {
        if !config.enabled {
            tracing::trace!("docker-masquerade firewall bypass disabled by config");
            return None;
        }

        let subnets = match &config.subnet {
            FirewallSubnetMode::Named(FirewallSubnetPreset::Default) => {
                vec![DEFAULT_DOCKER_SUBNET.to_string()]
            }
            FirewallSubnetMode::Named(FirewallSubnetPreset::Auto) => {
                let found = find_docker_subnets();
                if found.is_empty() {
                    tracing::trace!("no Docker bridge subnets found, skipping firewall rules");
                    return None;
                }
                found
            }
            FirewallSubnetMode::List(list) => {
                if list.is_empty() {
                    return None;
                }
                list.clone()
            }
        };

        let backend = detect_backend()?;
        tracing::trace!(?backend, "detected firewall backend");

        let mut rules = Vec::new();
        for subnet in &subnets {
            let rule = FirewallRule {
                subnet: subnet.clone(),
                tun_name: tun_name.to_string(),
            };
            if let Err(e) = insert_rule(backend, &rule) {
                tracing::warn!(subnet, error = %e, "failed to insert firewall bypass rule");
                continue;
            }
            tracing::trace!(subnet, "inserted NAT bypass rule for Docker subnet");
            rules.push(rule);
        }

        if rules.is_empty() {
            return None;
        }

        Some(Self { backend, rules })
    }
}

fn insert_rule(backend: FirewallBackend, rule: &FirewallRule) -> io::Result<()> {
    match backend {
        FirewallBackend::Nft => {
            // nft insert rule ip nat POSTROUTING position 0 ip saddr <subnet> oifname <tun> return
            crate::platform::run_command(Command::new("nft").args([
                "insert",
                "rule",
                "ip",
                "nat",
                "POSTROUTING",
                "ip",
                "saddr",
                &rule.subnet,
                "oifname",
                &rule.tun_name,
                "counter",
                "return",
            ]))
        }
        FirewallBackend::IptablesNft | FirewallBackend::IptablesLegacy => {
            crate::platform::run_command(Command::new("iptables").args([
                "-t",
                "nat",
                "-I",
                "POSTROUTING",
                "1",
                "-s",
                &rule.subnet,
                "-o",
                &rule.tun_name,
                "-j",
                "RETURN",
            ]))
        }
    }
}

fn remove_rule(backend: FirewallBackend, rule: &FirewallRule) -> io::Result<()> {
    match backend {
        FirewallBackend::Nft => {
            // For nft, we need to find the handle of our rule to delete it.
            // List rules with handles, find ours, then delete by handle.
            let output = command_output(
                "nft",
                &["-a", "list", "chain", "ip", "nat", "POSTROUTING"],
            )?;
            for line in output.lines() {
                // Match lines containing our subnet and tun name
                if line.contains(&rule.subnet)
                    && line.contains(&rule.tun_name)
                    && line.contains("return")
                {
                    // Extract handle number from "# handle N"
                    if let Some(handle) = line.rsplit("# handle ").next().and_then(|s| {
                        let s = s.trim();
                        if s.chars().all(|c| c.is_ascii_digit()) {
                            Some(s.to_string())
                        } else {
                            None
                        }
                    }) {
                        crate::platform::run_command(Command::new("nft").args([
                            "delete",
                            "rule",
                            "ip",
                            "nat",
                            "POSTROUTING",
                            "handle",
                            &handle,
                        ]))?;
                        return Ok(());
                    }
                }
            }
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "nft rule handle not found",
            ))
        }
        FirewallBackend::IptablesNft | FirewallBackend::IptablesLegacy => {
            crate::platform::run_command(Command::new("iptables").args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                &rule.subnet,
                "-o",
                &rule.tun_name,
                "-j",
                "RETURN",
            ]))
        }
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        for rule in &self.rules {
            if let Err(e) = remove_rule(self.backend, rule) {
                tracing::warn!(subnet = rule.subnet, error = %e, "failed to remove firewall bypass rule");
            } else {
                tracing::trace!(subnet = rule.subnet, "removed NAT bypass rule");
            }
        }
    }
}
