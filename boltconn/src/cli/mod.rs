mod cert;
mod clean;
mod request;
mod request_uds;
mod request_web;

use crate::ProgramArgs;
use anyhow::anyhow;
use clap::{Args, Subcommand};
use is_root::is_root;
use std::path::PathBuf;
use std::process::exit;

#[derive(Debug, Subcommand)]
pub(crate) enum ProxyOptions {
    /// Set group's proxy
    Set { group: String, proxy: String },
    /// List all groups
    List,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConnOptions {
    /// List all active connections
    List,
    Stop {
        nth: Option<usize>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum TunOptions {
    /// Set TUN
    Set { s: String },
    /// Get TUN status
    Get,
}

#[derive(Debug, Args)]
pub(crate) struct CertOptions {
    #[arg(short, long)]
    path: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TempRuleOptions {
    /// Add a temporary rule to the head of rule list
    Add { literal: String },
    /// Delete temporary rules matching this prefix
    Delete { literal: String },
    /// Delete all temporary rules
    Clear,
}

#[derive(Debug, Subcommand)]
pub(crate) enum InterceptOptions {
    /// List all captured data
    List,
    /// List data ranged from *start* to *end*
    Range { start: u32, end: Option<u32> },
    /// Get details of the packet
    Get { id: u32 },
}

#[derive(Debug, Args)]
pub(crate) struct StartOptions {
    /// Path of configuration. Default to $HOME/.config/boltconn
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    /// Path of application data. Default to $HOME/.local/share/boltconn
    #[arg(short = 'd', long = "data")]
    pub app_data: Option<PathBuf>,
    /// Path of certificate. Default to ${app_data}/cert
    #[arg(long)]
    pub cert: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct InitOptions {
    /// Path of configuration. Default to $HOME/.config/boltconn
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    /// Path of application data. Default to $HOME/.local/share/boltconn
    #[arg(short = 'd', long = "data")]
    pub app_data: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SubCommand {
    /// Start Main Program
    Start(StartOptions),
    /// Create Configurations
    Init(InitOptions),
    /// Proxy Settings
    #[command(subcommand)]
    Proxy(ProxyOptions),
    /// Connection Settings
    #[command(subcommand)]
    Conn(ConnOptions),
    /// Generate Certificates
    Cert(CertOptions),
    /// Captured HTTP Data
    #[command(subcommand)]
    Intercept(InterceptOptions),
    /// Adjust TUN Status
    #[command(subcommand)]
    Tun(TunOptions),
    /// Modify Temporary Rules
    #[command(subcommand)]
    Rule(TempRuleOptions),
    /// Clean Unexpected Shutdown
    Clean,
    /// Reload Configuration
    Reload,
    #[clap(hide = true)]
    Internal,
}

pub(crate) async fn controller_main(args: ProgramArgs) -> ! {
    let default_uds_path = "/var/run/boltconn.sock";
    match args.cmd {
        SubCommand::Init(init) => {
            fn create(init: InitOptions) -> anyhow::Result<()> {
                let (config, data, _) =
                    crate::config::parse_paths(&init.config, &init.app_data, &None)?;
                if crate::config::test_or_create_config(&config)? {
                    println!(
                        "Successfully created config at {}",
                        config.to_string_lossy()
                    );
                }
                if crate::config::test_or_create_state(&data)? {
                    println!("Successfully created state at {}", data.to_string_lossy());
                }
                Ok(())
            }
            match create(init) {
                Ok(_) => exit(0),
                Err(err) => {
                    eprintln!("Error occurred: {}", err);
                    exit(-1)
                }
            }
        }
        SubCommand::Cert(opt) => {
            if !is_root() {
                eprintln!("Must be run with root/admin privilege");
                exit(-1)
            } else {
                fn fetch_path() -> anyhow::Result<PathBuf> {
                    let p = PathBuf::from(std::env::var("HOME")?).join(".local/share/boltconn");
                    if !p.exists() {
                        Err(anyhow!("${{HOME}}/.local/share/boltconn does not exist"))?;
                    }
                    let p = p.join("cert");
                    if !p.exists() {
                        crate::config::test_or_create_path(&p)?;
                    }
                    Ok(p)
                }
                match match match opt.path {
                    None => fetch_path(),
                    Some(p) => Ok(p),
                } {
                    Ok(path) => cert::generate_cert(path),
                    Err(e) => Err(e),
                } {
                    Ok(_) => exit(0),
                    Err(err) => {
                        eprintln!("{}", err);
                        exit(-1)
                    }
                }
            }
        }
        SubCommand::Clean => {
            if !is_root() {
                eprintln!("Must be run with root/admin privilege");
                exit(-1)
            } else {
                clean::clean_route_table();
                clean::remove_unix_socket(default_uds_path);
                exit(0)
            }
        }
        _ => (),
    }
    let requester = match match args.url {
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
            ProxyOptions::Set { group, proxy } => requester.set_group_proxy(group, proxy).await,
            ProxyOptions::List => requester.get_group_list().await,
        },
        SubCommand::Conn(opt) => match opt {
            ConnOptions::List => requester.get_connections().await,
            ConnOptions::Stop { nth } => requester.stop_connections(nth).await,
        },
        SubCommand::Tun(opt) => match opt {
            TunOptions::Get => requester.get_tun().await,
            TunOptions::Set { s } => requester.set_tun(s.as_str()).await,
        },
        SubCommand::Intercept(opt) => match opt {
            InterceptOptions::List => requester.intercept(None).await,
            InterceptOptions::Range { start, end } => requester.intercept(Some((start, end))).await,
            InterceptOptions::Get { id } => requester.get_intercept_payload(id).await,
        },
        SubCommand::Reload => requester.reload_config().await,
        SubCommand::Rule(opt) => match opt {
            TempRuleOptions::Add { literal } => requester.add_temporary_rule(literal).await,
            TempRuleOptions::Delete { literal } => requester.delete_temporary_rule(literal).await,
            TempRuleOptions::Clear => requester.clear_temporary_rule().await,
        },
        SubCommand::Start(_)
        | SubCommand::Init(_)
        | SubCommand::Cert(_)
        | SubCommand::Clean
        | SubCommand::Internal => {
            unreachable!()
        }
    };
    match result {
        Ok(_) => exit(0),
        Err(err) => {
            eprintln!("{}", err);
            exit(-1)
        }
    }
}
