use super::{
    KILL_SWITCH_BYPASS_IPV4, KILL_SWITCH_BYPASS_IPV6, command_succeeds, run_command_with_input,
    validate_interface_name,
};
use crate::platform::{self, BOLTCONN_FWMARK};
use std::io;
use std::process::Command;

const NFT_TABLE: &str = "boltconn";
const IPTABLES_CHAIN: &str = "BOLTCONN_KILLSWITCH";

#[derive(Debug, Clone, Copy)]
enum Backend {
    Nftables,
    Iptables,
}

pub struct KillSwitchGuard {
    backend: Backend,
    active: bool,
}

impl KillSwitchGuard {
    pub fn setup(tun_name: &str) -> io::Result<Self> {
        validate_interface_name(tun_name)?;

        match install_iptables(tun_name) {
            Ok(()) => {
                if let Err(nft_error) = cleanup_nftables() {
                    let iptables_cleanup = cleanup_iptables();
                    return match iptables_cleanup {
                        Ok(()) => Err(io::Error::other(format!(
                            "installed iptables kill switch but failed to remove stale \
                             nftables rules: {nft_error}"
                        ))),
                        Err(iptables_error) => Err(io::Error::other(format!(
                            "failed to remove stale nftables rules ({nft_error}); failed to \
                             roll back iptables rules ({iptables_error})"
                        ))),
                    };
                }
                tracing::info!(backend = "iptables", "Kill switch has been enabled");
                Ok(Self {
                    backend: Backend::Iptables,
                    active: true,
                })
            }
            Err(iptables_error) => {
                // An iptables setup spans IPv4 and IPv6 commands. Clean both families before
                // falling back so a partial first attempt is never left unmanaged.
                cleanup_iptables().map_err(|cleanup_error| {
                    io::Error::other(format!(
                        "failed to install iptables kill switch ({iptables_error}); \
                         failed to clean partial iptables rules ({cleanup_error})"
                    ))
                })?;
                tracing::warn!(error = %iptables_error, "iptables kill switch unavailable; trying nftables");

                match install_nftables(tun_name) {
                    Ok(()) => {
                        tracing::info!(backend = "nftables", "Kill switch has been enabled");
                        Ok(Self {
                            backend: Backend::Nftables,
                            active: true,
                        })
                    }
                    Err(nft_error) => {
                        // The nft batch is atomic, but an older BoltConn table may still exist.
                        let nft_cleanup = cleanup_nftables();
                        match nft_cleanup {
                            Ok(()) => Err(io::Error::other(format!(
                                "iptables kill switch unavailable ({iptables_error}); \
                                 nftables fallback failed ({nft_error})"
                            ))),
                            Err(cleanup_error) => Err(io::Error::other(format!(
                                "iptables kill switch unavailable ({iptables_error}); \
                                 nftables fallback failed ({nft_error}); failed to clean stale \
                                 nftables rules ({cleanup_error})"
                            ))),
                        }
                    }
                }
            }
        }
    }

    pub fn teardown(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        let result = match self.backend {
            Backend::Nftables => cleanup_nftables(),
            Backend::Iptables => cleanup_iptables(),
        };
        if result.is_ok() {
            self.active = false;
            tracing::info!("Kill switch has been disabled");
        }
        result
    }
}

impl Drop for KillSwitchGuard {
    fn drop(&mut self) {
        if let Err(error) = self.teardown() {
            tracing::error!(%error, "failed to remove Linux kill switch");
        }
    }
}

pub fn cleanup_stale_kill_switch() -> io::Result<()> {
    let mut errors = Vec::new();
    if let Err(error) = cleanup_nftables() {
        errors.push(format!("nftables: {error}"));
    }
    if let Err(error) = cleanup_iptables() {
        errors.push(format!("iptables: {error}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(errors.join("; ")))
    }
}

fn nft_table_exists() -> bool {
    command_succeeds("nft", &["list", "table", "inet", NFT_TABLE])
}

fn render_nftables(tun_name: &str, replace_existing: bool) -> String {
    let mut rules = String::new();
    if replace_existing {
        rules.push_str("delete table inet boltconn\n");
    }
    rules.push_str(
        "table inet boltconn {\n\
             set bypass_v4 {\n\
                 type ipv4_addr\n\
                 flags interval\n\
                 elements = { ",
    );
    rules.push_str(&KILL_SWITCH_BYPASS_IPV4.join(", "));
    rules.push_str(
        " }\n\
             }\n\
             set bypass_v6 {\n\
                 type ipv6_addr\n\
                 flags interval\n\
                 elements = { ",
    );
    rules.push_str(&KILL_SWITCH_BYPASS_IPV6.join(", "));
    rules.push_str(&format!(
        " }}\n\
             }}\n\
             chain output {{\n\
                 type filter hook output priority filter; policy accept;\n\
                 oifname \"lo\" return\n\
                 oifname \"{tun_name}\" return\n\
                 ip daddr @bypass_v4 return\n\
                 ip6 daddr @bypass_v6 return\n\
                 ct direction reply meta skuid 0 return\n\
                 meta mark {BOLTCONN_FWMARK:#010x} return\n\
                 meta l4proto {{ tcp, udp }} reject\n\
             }}\n\
         }}\n"
    ));
    rules
}

fn install_nftables(tun_name: &str) -> io::Result<()> {
    let rules = render_nftables(tun_name, nft_table_exists());
    run_command_with_input(Command::new("nft").args(["-f", "-"]), &rules).map(|_| ())
}

fn cleanup_nftables() -> io::Result<()> {
    if !command_succeeds("nft", &["--version"]) || !nft_table_exists() {
        return Ok(());
    }
    platform::run_command(Command::new("nft").args(["delete", "table", "inet", NFT_TABLE]))
}

fn run_iptables(command: &str, args: &[String]) -> io::Result<()> {
    platform::run_command(Command::new(command).args(args))
}

fn iptables_chain_exists(command: &str) -> bool {
    command_succeeds(command, &["-w", "-L", IPTABLES_CHAIN, "-n"])
}

fn cleanup_iptables_family(command: &str) -> io::Result<()> {
    if !command_succeeds(command, &["--version"]) {
        return Ok(());
    }

    while command_succeeds(command, &["-w", "-C", "OUTPUT", "-j", IPTABLES_CHAIN]) {
        run_iptables(
            command,
            &[
                "-w".into(),
                "-D".into(),
                "OUTPUT".into(),
                "-j".into(),
                IPTABLES_CHAIN.into(),
            ],
        )?;
    }
    if iptables_chain_exists(command) {
        run_iptables(command, &["-w".into(), "-F".into(), IPTABLES_CHAIN.into()])?;
        run_iptables(command, &["-w".into(), "-X".into(), IPTABLES_CHAIN.into()])?;
    }
    Ok(())
}

fn cleanup_iptables() -> io::Result<()> {
    let ipv4 = cleanup_iptables_family("iptables");
    let ipv6 = cleanup_iptables_family("ip6tables");
    match (ipv4, ipv6) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(ipv4), Err(ipv6)) => Err(io::Error::other(format!(
            "IPv4 cleanup failed: {ipv4}; IPv6 cleanup failed: {ipv6}"
        ))),
    }
}

fn append_rule(command: &str, args: &[&str]) -> io::Result<()> {
    let mut command_args = vec!["-w".to_string(), "-A".into(), IPTABLES_CHAIN.into()];
    command_args.extend(args.iter().map(|arg| (*arg).to_string()));
    run_iptables(command, &command_args)
}

fn install_iptables_family(command: &str, tun_name: &str, bypass: &[&str]) -> io::Result<()> {
    run_iptables(command, &["-w".into(), "-N".into(), IPTABLES_CHAIN.into()])?;
    append_rule(command, &["-o", "lo", "-j", "RETURN"])?;
    append_rule(command, &["-o", tun_name, "-j", "RETURN"])?;
    for subnet in bypass {
        append_rule(command, &["-d", subnet, "-j", "RETURN"])?;
    }
    append_rule(
        command,
        &[
            "-m",
            "conntrack",
            "--ctdir",
            "REPLY",
            "-m",
            "owner",
            "--uid-owner",
            "0",
            "-j",
            "RETURN",
        ],
    )?;
    let mark = format!("{BOLTCONN_FWMARK:#010x}/0xffffffff");
    append_rule(command, &["-m", "mark", "--mark", &mark, "-j", "RETURN"])?;
    append_rule(
        command,
        &["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"],
    )?;
    append_rule(command, &["-p", "udp", "-j", "REJECT"])?;
    run_iptables(
        command,
        &[
            "-w".into(),
            "-I".into(),
            "OUTPUT".into(),
            "1".into(),
            "-j".into(),
            IPTABLES_CHAIN.into(),
        ],
    )
}

fn install_iptables(tun_name: &str) -> io::Result<()> {
    if !command_succeeds("iptables", &["--version"])
        || !command_succeeds("ip6tables", &["--version"])
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "neither a usable nftables backend nor both iptables families are available",
        ));
    }

    cleanup_iptables()?;
    let result = install_iptables_family("iptables", tun_name, KILL_SWITCH_BYPASS_IPV4)
        .and_then(|()| install_iptables_family("ip6tables", tun_name, KILL_SWITCH_BYPASS_IPV6));
    if let Err(error) = result {
        let cleanup_result = cleanup_iptables();
        return match cleanup_result {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(io::Error::other(format!(
                "failed to install iptables kill switch ({error}); rollback failed ({cleanup_error})"
            ))),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::render_nftables;
    use crate::platform::BOLTCONN_FWMARK;

    #[test]
    fn nftables_rules_cover_bypasses_mark_and_reply_traffic() {
        let rules = render_nftables("tun42", false);
        assert!(rules.contains("oifname \"lo\" return"));
        assert!(rules.contains("oifname \"tun42\" return"));
        assert!(rules.contains("192.168.0.0/16"));
        assert!(rules.contains("fc00::/7"));
        assert!(rules.contains("ct direction reply meta skuid 0 return"));
        assert!(rules.contains(&format!("meta mark {BOLTCONN_FWMARK:#010x} return")));
        assert!(rules.contains("meta l4proto { tcp, udp } reject"));
    }

    #[test]
    fn nftables_replacement_is_a_single_batch() {
        let rules = render_nftables("tun0", true);
        assert!(rules.starts_with("delete table inet boltconn\n"));
        assert!(rules.contains("table inet boltconn"));
    }
}
