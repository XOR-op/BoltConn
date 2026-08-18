use super::{
    KILL_SWITCH_BYPASS_IPV4, KILL_SWITCH_BYPASS_IPV6, run_command_with_input,
    validate_interface_name,
};
use crate::platform;
use crate::platform::MACOS_PLACEHOLDER_DNS;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

const PF_ANCHOR: &str = "com.apple/boltconn";
const PF_TOKEN_PATH: &str = "/var/run/boltconn-pf.token";
const CAPTIVE_AGENT_USER: &str = "_captiveagent";

pub struct KillSwitchGuard {
    token: String,
    active: bool,
}

impl KillSwitchGuard {
    pub fn setup(tun_name: &str) -> io::Result<Self> {
        validate_interface_name(tun_name)?;
        let rules = render_pf_rules(tun_name);

        // Parse before touching the live anchor. Loading a child of com.apple/* leaves the
        // system ruleset intact and replaces only BoltConn's private rules.
        run_command_with_input(
            Command::new("pfctl").args(["-n", "-a", PF_ANCHOR, "-f", "-"]),
            &rules,
        )?;
        run_command_with_input(
            Command::new("pfctl").args(["-a", PF_ANCHOR, "-f", "-"]),
            &rules,
        )?;

        let old_token = match read_token() {
            Ok(token) => Some(token),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let token = match enable_pf() {
            Ok(token) => token,
            Err(error) => {
                if old_token.is_none() {
                    let _ = flush_anchor();
                }
                return Err(error);
            }
        };

        if let Err(error) = flush_non_tun_states(tun_name) {
            let _ = release_pf_token(&token);
            if old_token.is_none() {
                let _ = flush_anchor();
            }
            return Err(error);
        }

        if let Err(error) = fs::write(PF_TOKEN_PATH, format!("{token}\n")) {
            let _ = release_pf_token(&token);
            if old_token.is_none() {
                let _ = flush_anchor();
            }
            return Err(error);
        }

        if let Some(old_token) = old_token
            && old_token != token
            && let Err(error) = release_pf_token(&old_token)
        {
            // The new reference and token are already durable. A leaked old reference is less
            // harmful than disabling PF or rolling back a working kill switch.
            tracing::warn!(%error, "failed to release stale PF enable reference");
        }

        tracing::info!(backend = "pf", "Kill switch has been enabled");
        Ok(Self {
            token,
            active: true,
        })
    }

    pub fn teardown(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }

        let anchor_result = flush_anchor();
        let token_result = release_pf_token(&self.token);
        if token_result.is_ok() {
            remove_token_file()?;
        }

        match (anchor_result, token_result) {
            (Ok(()), Ok(())) => {
                self.active = false;
                tracing::info!("Kill switch has been disabled");
                Ok(())
            }
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(anchor), Err(token)) => Err(io::Error::other(format!(
                "failed to flush PF anchor ({anchor}); failed to release PF token ({token})"
            ))),
        }
    }
}

impl Drop for KillSwitchGuard {
    fn drop(&mut self) {
        if let Err(error) = self.teardown() {
            tracing::error!(%error, "failed to remove macOS kill switch");
        }
    }
}

pub fn cleanup_stale_kill_switch() -> io::Result<()> {
    let anchor_result = flush_anchor();
    let token_result = match read_token() {
        Ok(token) => release_pf_token(&token),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };
    if token_result.is_ok() {
        remove_token_file()?;
    }

    match (anchor_result, token_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(anchor), Err(token)) => Err(io::Error::other(format!(
            "failed to flush PF anchor ({anchor}); failed to release PF token ({token})"
        ))),
    }
}

fn render_pf_rules(tun_name: &str) -> String {
    let bypass = KILL_SWITCH_BYPASS_IPV4
        .iter()
        .chain(KILL_SWITCH_BYPASS_IPV6)
        // to allow DNS hijack
        .chain([MACOS_PLACEHOLDER_DNS.to_string().as_str()].iter())
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    // macOS binds captive-network probes to the physical Wi-Fi interface. Keep this
    // exception user-scoped so other desktop applications cannot bypass the TUN.
    format!(
        "table <boltconn_bypass> const {{ {bypass} }}\n\
         pass out quick on ! {tun_name} inet proto {{ tcp, udp }} \
             from any to any user = {CAPTIVE_AGENT_USER}\n\
         pass out quick on ! {tun_name} inet6 proto {{ tcp, udp }} \
             from any to any user = {CAPTIVE_AGENT_USER}\n\
         block return out quick on ! {tun_name} inet proto {{ tcp, udp }} \
             from any to ! <boltconn_bypass> user != 0\n\
         block return out quick on ! {tun_name} inet proto {{ tcp, udp }} \
             from any to ! <boltconn_bypass> user unknown\n\
         block return out quick on ! {tun_name} inet6 proto {{ tcp, udp }} \
             from any to ! <boltconn_bypass> user != 0\n\
         block return out quick on ! {tun_name} inet6 proto {{ tcp, udp }} \
             from any to ! <boltconn_bypass> user unknown\n"
    )
}

fn pfctl_output(args: &[&str]) -> io::Result<String> {
    let output = Command::new("pfctl")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    if output.status.success() {
        Ok(combined)
    } else {
        Err(io::Error::other(format!(
            "pfctl exited with {}: {}",
            output.status,
            combined.trim()
        )))
    }
}

fn enable_pf() -> io::Result<String> {
    let output = pfctl_output(&["-E"])?;
    output
        .lines()
        .find_map(|line| {
            let (label, token) = line.split_once(':')?;
            if label.trim().eq_ignore_ascii_case("token") {
                let token = token.trim();
                (!token.is_empty()
                    && token
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() || byte == b'x'))
                .then(|| token.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| io::Error::other(format!("pfctl -E returned no enable token: {output}")))
}

fn release_pf_token(token: &str) -> io::Result<()> {
    platform::run_command(Command::new("pfctl").args(["-X", token]))
}

fn flush_anchor() -> io::Result<()> {
    platform::run_command(Command::new("pfctl").args(["-a", PF_ANCHOR, "-F", "rules"]))
}

fn flush_non_tun_states(tun_name: &str) -> io::Result<()> {
    let interfaces: BTreeSet<String> = pnet_datalink::interfaces()
        .into_iter()
        .filter(|interface| {
            interface.is_up() && !interface.is_loopback() && interface.name != tun_name
        })
        .map(|interface| interface.name)
        .collect();
    for interface in interfaces {
        validate_interface_name(&interface)?;
        platform::run_command(Command::new("pfctl").args(["-i", &interface, "-F", "states"]))?;
    }
    Ok(())
}

fn read_token() -> io::Result<String> {
    let token = fs::read_to_string(PF_TOKEN_PATH)?.trim().to_string();
    if token.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty PF enable token",
        ))
    } else {
        Ok(token)
    }
}

fn remove_token_file() -> io::Result<()> {
    match fs::remove_file(Path::new(PF_TOKEN_PATH)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::render_pf_rules;

    #[test]
    fn pf_rules_bypass_lan_root_and_captive_agent() {
        let rules = render_pf_rules("utun42");
        assert!(rules.contains("10.0.0.0/8"));
        assert!(rules.contains("fe80::/10"));
        assert!(rules.contains("on ! utun42"));
        assert!(rules.contains("to ! <boltconn_bypass> user != 0"));
        assert!(rules.contains("user unknown"));

        let captive_v4 = "pass out quick on ! utun42 inet proto { tcp, udp } \
             from any to any user = _captiveagent";
        let captive_v6 = "pass out quick on ! utun42 inet6 proto { tcp, udp } \
             from any to any user = _captiveagent";
        let first_block = rules.find("block return out quick").unwrap();
        assert!(rules.contains(captive_v4));
        assert!(rules.contains(captive_v6));
        assert!(rules.find(captive_v4).unwrap() < first_block);
        assert!(rules.find(captive_v6).unwrap() < first_block);
    }
}
