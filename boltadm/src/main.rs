mod cert;
mod clean;
mod request;
mod request_uds;
mod request_web;

use crate::request::Requester;
use anyhow::anyhow;
use is_root::is_root;
use std::path::PathBuf;
use std::process::exit;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "boltadm", about = "Controller for BoltConn")]
struct Args {
    /// RESTful API URL; if not set, BoltAdm will use unix domain socket as default.
    #[structopt(short, long)]
    pub url: Option<String>,
    #[structopt(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, StructOpt)]
enum ProxyOptions {
    /// Set group's proxy
    Set { group: String, proxy: String },
    /// List all groups
    List,
}

#[derive(Debug, StructOpt)]
enum ConnOptions {
    /// List all active connections
    List,
    Stop {
        nth: Option<usize>,
    },
}

#[derive(Debug, StructOpt)]
enum LogOptions {
    /// List all logs
    List,
}

#[derive(Debug, StructOpt)]
enum DebugOptions {
    /// List all sessions
    Session,
}

#[derive(Debug, StructOpt)]
enum TunOptions {
    /// Set TUN
    Set { s: String },
    /// Get TUN status
    Get,
}

#[derive(Debug, StructOpt)]
struct CertOptions {
    #[structopt(short, long)]
    path: Option<String>,
}

#[derive(Debug, StructOpt)]
enum TempRuleOptions {
    /// Add a temporary rule to the head of rule list
    Add { literal: String },
    /// Delete temporary rules matching this prefix
    Delete { literal: String },
    /// Delete all temporary rules
    Clear,
}

#[derive(Debug, StructOpt)]
enum InterceptOptions {
    /// List all captured data
    List,
    /// List data ranged from *start* to *end*
    Range { start: u32, end: Option<u32> },
    /// Get details of the packet
    Get { id: u32 },
}

#[derive(Debug, StructOpt)]
enum SubCommand {
    /// Proxy Settings
    Proxy(ProxyOptions),
    /// Connection Settings
    Conn(ConnOptions),
    /// Logs Operations
    Log(LogOptions),
    /// Generate Certificates
    Cert(CertOptions),
    /// Captured HTTP data
    Intercept(InterceptOptions),
    /// Adjust TUN status
    Tun(TunOptions),
    /// Modify Temporary Rules
    Rule(TempRuleOptions),
    /// Clean unexpected shutdown
    Clean,
    /// Reload Configuration
    Reload,
}

#[tokio::main]
async fn main() {
    let args: Args = Args::from_args();
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
        None => Requester::new_uds(PathBuf::from(default_uds_path)).await,
        Some(url) => Requester::new_web(url),
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
                        .join("boltconn");
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
    };
    match result {
        Ok(_) => exit(0),
        Err(err) => {
            eprintln!("{}", err);
            exit(-1)
        }
    }
}
