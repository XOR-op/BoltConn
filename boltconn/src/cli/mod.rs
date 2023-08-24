mod cert;
mod clean;
mod request;
mod request_uds;
mod request_web;

use crate::Args;
use anyhow::anyhow;
use is_root::is_root;
use std::path::PathBuf;
use std::process::exit;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub(crate) enum ProxyOptions {
    /// Set group's proxy
    Set { group: String, proxy: String },
    /// List all groups
    List,
}

#[derive(Debug, StructOpt)]
pub(crate) enum ConnOptions {
    /// List all active connections
    List,
    Stop {
        nth: Option<usize>,
    },
}

#[derive(Debug, StructOpt)]
pub(crate) enum LogOptions {
    /// List all logs
    List,
}

#[derive(Debug, StructOpt)]
pub(crate) enum DebugOptions {
    /// List all sessions
    Session,
}

#[derive(Debug, StructOpt)]
pub(crate) enum TunOptions {
    /// Set TUN
    Set { s: String },
    /// Get TUN status
    Get,
}

#[derive(Debug, StructOpt)]
pub(crate) struct CertOptions {
    #[structopt(short, long)]
    path: Option<String>,
}

#[derive(Debug, StructOpt)]
pub(crate) enum TempRuleOptions {
    /// Add a temporary rule to the head of rule list
    Add { literal: String },
    /// Delete temporary rules matching this prefix
    Delete { literal: String },
    /// Delete all temporary rules
    Clear,
}

#[derive(Debug, StructOpt)]
pub(crate) enum InterceptOptions {
    /// List all captured data
    List,
    /// List data ranged from *start* to *end*
    Range { start: u32, end: Option<u32> },
    /// Get details of the packet
    Get { id: u32 },
}

#[derive(Debug, StructOpt)]
pub(crate) struct StartOptions {
    /// Path of configutation. Default to $HOME/.config/boltconn
    #[structopt(short, long)]
    pub config: Option<PathBuf>,
    /// Path of application data. Default to $HOME/.local/share/boltconn
    #[structopt(short = "d", long = "data")]
    pub app_data: Option<PathBuf>,
    /// Path of certificate. Default to ${app_data}/cert
    #[structopt(long)]
    pub cert: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
pub(crate) enum SubCommand {
    /// Start Main Program
    Start(StartOptions),
    /// Proxy Settings
    Proxy(ProxyOptions),
    /// Connection Settings
    Conn(ConnOptions),
    /// Logs Operations
    Log(LogOptions),
    /// Generate Certificates
    Cert(CertOptions),
    /// Captured HTTP Data
    Intercept(InterceptOptions),
    /// Adjust TUN Status
    Tun(TunOptions),
    /// Modify Temporary Rules
    Rule(TempRuleOptions),
    /// Clean Unexpected Shutdown
    Clean,
    /// Reload Configuration
    Reload,
}

pub(crate) async fn controller_main(args: Args) -> ! {
    let default_uds_path = "/var/run/boltconn.sock";
    if matches!(args.cmd, SubCommand::Clean) {
        if !is_root() {
            eprintln!("Must be run with root/admin privilege");
            exit(-1)
        } else {
            clean::clean_route_table();
            clean::remove_unix_socket(default_uds_path);
            exit(0)
        }
    }
    let requestor = match match args.url {
        None => request::Requester::new_uds(PathBuf::from(default_uds_path)).await,
        Some(url) => request::Requester::new_web(url),
    } {
        Ok(r) => r,
        Err(err) => {
            eprintln!("{}", err);
            exit(-1)
        }
    };
    let result = match args.cmd {
        SubCommand::Proxy(opt) => match opt {
            ProxyOptions::Set { group, proxy } => requestor.set_group_proxy(group, proxy).await,
            ProxyOptions::List => requestor.get_group_list().await,
        },
        SubCommand::Conn(opt) => match opt {
            ConnOptions::List => requestor.get_connections().await,
            ConnOptions::Stop { nth } => requestor.stop_connections(nth).await,
        },
        SubCommand::Log(opt) => match opt {
            LogOptions::List => {
                // todo
                Ok(())
            }
        },
        SubCommand::Cert(opt) => {
            if !is_root() {
                eprintln!("Must be run with root/admin privilege");
                exit(-1)
            } else {
                fn fetch_path() -> anyhow::Result<String> {
                    let p = PathBuf::from(std::env::var("HOME")?)
                        .join(".config")
                        .join("../..");
                    if !p.exists() {
                        Err(anyhow!("${{HOME}}/.config/boltconn does not exist"))?;
                    }
                    let p = p.join("cert");
                    if !p.exists() {
                        std::fs::create_dir(p.clone())?;
                    }
                    Ok(p.to_string_lossy().to_string())
                }
                match match opt.path {
                    None => fetch_path(),
                    Some(p) => Ok(p),
                } {
                    Ok(path) => cert::generate_cert(path),
                    Err(e) => Err(e),
                }
            }
        }
        SubCommand::Tun(opt) => match opt {
            TunOptions::Get => requestor.get_tun().await,
            TunOptions::Set { s } => requestor.set_tun(s.as_str()).await,
        },
        SubCommand::Intercept(opt) => match opt {
            InterceptOptions::List => requestor.intercept(None).await,
            InterceptOptions::Range { start, end } => requestor.intercept(Some((start, end))).await,
            InterceptOptions::Get { id } => requestor.get_intercept_payload(id).await,
        },
        SubCommand::Clean => unreachable!(),
        SubCommand::Reload => requestor.reload_config().await,
        SubCommand::Rule(opt) => match opt {
            TempRuleOptions::Add { literal } => requestor.add_temporary_rule(literal).await,
            TempRuleOptions::Delete { literal } => requestor.delete_temporary_rule(literal).await,
            TempRuleOptions::Clear => requestor.clear_temporary_rule().await,
        },
        SubCommand::Start(_) => unreachable!(),
    };
    match result {
        Ok(_) => exit(0),
        Err(err) => {
            eprintln!("{}", err);
            exit(-1)
        }
    }
}
