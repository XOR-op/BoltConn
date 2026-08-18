use crate::config::{FirewallSubnetMode, FirewallSubnetPreset, RawDockerMasqueradeConfig};
use std::io;
use std::io::Write;
use std::process::{Command, Stdio};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(
    target_os = "windows",
    not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
))]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::{KillSwitchGuard, cleanup_stale_kill_switch};
#[cfg(target_os = "macos")]
pub use macos::{KillSwitchGuard, cleanup_stale_kill_switch};
#[cfg(any(
    target_os = "windows",
    not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
))]
pub use windows::{KillSwitchGuard, cleanup_stale_kill_switch};

pub(super) const KILL_SWITCH_BYPASS_IPV4: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];
pub(super) const KILL_SWITCH_BYPASS_IPV6: &[&str] = &["::1/128", "fc00::/7", "fe80::/10"];

pub(super) fn validate_interface_name(name: &str) -> io::Result<()> {
    // Firewall rule languages require interpolation for interface names. Kernel-created
    // interface names use this conservative character set, which also prevents rule injection.
    if name.is_empty()
        || name.len() > 63
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid firewall interface name: {name:?}"),
        ));
    }
    Ok(())
}

pub(super) fn run_command_with_input(cmd: &mut Command, input: &str) -> io::Result<String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other(format!("failed to open {program} stdin")))?
        .write_all(input.as_bytes());
    let output = child.wait_with_output()?;
    write_result?;
    if output.status.success() {
        String::from_utf8(output.stdout).map_err(io::Error::other)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::other(format!(
            "{program} exited with {}: {}",
            output.status,
            stderr.trim()
        )))
    }
}

/// Detects whether to use nft or iptables, and inserts NAT POSTROUTING rules
/// to bypass Docker's MASQUERADE for traffic destined to the TUN device.
///
/// Docker adds MASQUERADE rules like:
///   `-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE`
/// which rewrites the source IP of container traffic, preventing us from
/// identifying the original source. We insert a higher-priority RETURN rule:
///   `-I POSTROUTING 1 -s 172.17.0.0/16 -o <tun> -j RETURN`
/// so that traffic routed through our TUN device skips the MASQUERADE.
pub struct DockerMasqueradeGuard {
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
                if ip.ip().is_ipv4() {
                    subnets.push(ip.to_string());
                }
            }
        }
    }
    subnets
}

const DEFAULT_DOCKER_SUBNET: &str = "172.16.0.0/12";

impl DockerMasqueradeGuard {
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
            let output =
                command_output("nft", &["-a", "list", "chain", "ip", "nat", "POSTROUTING"])?;
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

impl Drop for DockerMasqueradeGuard {
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

#[cfg(test)]
mod tests {
    use super::validate_interface_name;

    #[test]
    fn validates_kernel_style_interface_names() {
        assert!(validate_interface_name("utun12").is_ok());
        assert!(validate_interface_name("wg-bolt.1").is_ok());
        assert!(validate_interface_name("eth0:1").is_ok());
    }

    #[test]
    fn rejects_interface_name_rule_injection() {
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("eth0\nblock all").is_err());
        assert!(validate_interface_name("eth0\"").is_err());
    }
}
