mod cert;
mod clean;
mod request;
mod request_uds;
mod request_web;
mod streaming;

use crate::app::app_uds_addr;
use crate::cli::streaming::ConnectionState;
use crate::ProgramArgs;
use anyhow::anyhow;
use clap::{Args, CommandFactory, Subcommand, ValueHint};
use colored::Colorize;
use is_root::is_root;
use std::path::PathBuf;
use std::process::exit;

#[derive(Debug, Subcommand)]
pub(crate) enum ProxyOptions {
    /// Set group's proxy
    Set {
        #[clap(value_hint = ValueHint::Other)]
        group: String,
        #[clap(value_hint = ValueHint::Other)]
        proxy: String,
    },
    /// Get group's proxy
    Get {
        #[clap(value_hint = ValueHint::Other)]
        group: String,
    },
    /// List all groups
    List {
        #[arg(short, long)]
        full: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConnOptions {
    /// List all active connections
    List,
    /// Stop connection
    Stop {
        #[clap(value_hint = ValueHint::Other)]
        nth: Option<usize>,
    },
    /// Connection logs limit
    #[command(subcommand)]
    Limit(LogsLimitOptions),
    /// Manage multiplexed master connections
    #[command(subcommand)]
    Master(MasterConnOptions),
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub(crate) enum TunSetOptions {
    On,
    Off,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub(crate) enum TunOptions {
    /// Set TUN
    #[command(subcommand)]
    Set(TunSetOptions),
    /// Get TUN status
    Get,
}

#[derive(Debug, Args)]
pub(crate) struct CertOptions {
    #[arg(short, long)]
    path: Option<PathBuf>,
    #[arg(long)]
    rootless: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TempRuleOptions {
    /// Add a temporary rule to the head of rule list
    Add {
        #[clap(value_hint = ValueHint::Other)]
        literal: String,
    },
    /// Delete temporary rules matching this prefix
    Delete {
        #[clap(value_hint = ValueHint::Other)]
        literal: String,
    },
    /// List all temporary rules
    List,
    /// Delete all temporary rules
    Clear,
}

#[derive(Debug, Subcommand)]
pub(crate) enum DnsOptions {
    /// Lookup real address of a domain
    Lookup {
        #[clap(value_hint = ValueHint::Other)]
        domain_name: String,
    },
    /// Find the internal mapping of a fake IP
    Mapping {
        #[clap(value_hint = ValueHint::Other)]
        fake_ip: String,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum InterceptOptions {
    /// List all captured data
    List,
    /// List data ranged from *start* to *end*
    Range {
        #[clap(value_hint = ValueHint::Other)]
        start: u32,
        #[clap(value_hint = ValueHint::Other)]
        end: Option<u32>,
    },
    /// Get details of the packet
    Get {
        #[clap(value_hint = ValueHint::Other)]
        id: u32,
    },
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
    /// Whether to enable TUN interface at startup. Default to true.
    #[arg(short = 't', long = "tun")]
    pub enable_tun: Option<bool>,
    /// Run in rootless mode. Certain features may not be available in this mode.
    #[arg(long)]
    pub rootless: bool,
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

#[derive(Debug, Clone, Copy, Subcommand)]
pub(crate) enum PromptOptions {
    Bash,
    Zsh,
    Fish,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GenerateOptions {
    /// Create configurations
    Init(InitOptions),
    /// Generate certificates
    Cert(CertOptions),
    /// Generate auto-completion profiles for shells
    #[command(subcommand)]
    Prompt(PromptOptions),
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub(crate) enum LogsLimitOptions {
    /// Set the limit of logs
    Set {
        #[clap(value_hint = ValueHint::Other)]
        limit: u32,
    },
    /// Get the limit of logs
    Get,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct WgOptions {
    pub name: String,
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum MasterConnOptions {
    /// Show the WireGuard master connections
    ListWg,
    /// Stop a WireGuard connection
    StopWg(WgOptions),
}

#[derive(Debug, Subcommand)]
pub(crate) enum SubCommand {
    /// Start the main program
    Start(StartOptions),
    /// Reload configurations
    Reload,
    /// Validate configurations
    Validate(StartOptions),
    /// Connection settings
    #[command(subcommand)]
    Conn(ConnOptions),
    /// Captured HTTP data
    #[command(subcommand)]
    Intercept(InterceptOptions),
    /// Proxy settings
    #[command(subcommand)]
    Proxy(ProxyOptions),
    /// DNS information
    #[command(subcommand)]
    Dns(DnsOptions),
    /// Modify temporary rules
    #[command(subcommand)]
    TempRule(TempRuleOptions),
    /// Adjust TUN status
    #[command(subcommand)]
    Tun(TunOptions),
    /// Display logs
    Log,
    /// Clean unexpected shutdown
    Clean,
    /// Generate necessary files before the first run
    #[command(subcommand)]
    Generate(GenerateOptions),
    #[cfg(feature = "internal-test")]
    #[clap(hide = true)]
    Internal,
}

pub(crate) async fn controller_main(args: ProgramArgs) -> ! {
    let unix_default_path = "/var/run/boltconn.sock";
    let unix_rootless_fallback_path = "/tmp/boltconn.sock";
    #[cfg(unix)]
    let default_uds_path = {
        // test if the default path exists
        if std::path::Path::new(unix_default_path)
            .try_exists()
            .is_ok_and(|v| v)
        {
            Some(unix_default_path.to_string())
        } else {
            let rootless_path = app_uds_addr(true);

            if std::path::Path::new(&rootless_path)
                .try_exists()
                .is_ok_and(|v| v)
            {
                Some(rootless_path)
            } else {
                None
            }
        }
    };
    #[cfg(windows)]
    let default_uds_path = Some(r"\\.\pipe\boltconn".to_string());
    match args.cmd {
        SubCommand::Generate(GenerateOptions::Init(init)) => {
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
        SubCommand::Generate(GenerateOptions::Cert(opt)) => {
            if !is_root() && !opt.rootless {
                eprintln!("Expect be run with root/admin privilege to prevent unauthorized access to certificates. If you expect to generate certificates without hardening the permissions, please use --rootless option.");
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
                    Ok(path) => cert::generate_cert(path, opt.rootless),
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
        SubCommand::Generate(GenerateOptions::Prompt(shell)) => {
            let generator = match shell {
                PromptOptions::Bash => clap_complete::Shell::Bash,
                PromptOptions::Zsh => clap_complete::Shell::Zsh,
                PromptOptions::Fish => clap_complete::Shell::Fish,
            };
            let mut command = ProgramArgs::command();
            let bin_name = command.get_name().to_string();
            clap_complete::generate(generator, &mut command, bin_name, &mut std::io::stdout());
            exit(0)
        }
        SubCommand::Clean => {
            if !is_root() {
                eprintln!("Must be run with root/admin privilege");
                exit(-1)
            } else {
                clean::clean_route_table();
                clean::remove_unix_socket(unix_default_path);
                clean::remove_unix_socket(unix_rootless_fallback_path);
                clean::remove_unix_socket(crate::app::app_uds_addr(true));
                exit(0)
            }
        }
        SubCommand::Log => {
            if args.url.is_some() {
                eprintln!("Log command does not support remote connection");
                exit(-1)
            }
            let state = match ConnectionState::new(&validate_uds_path(
                default_uds_path,
                unix_default_path,
                unix_rootless_fallback_path,
            ))
            .await
            {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("{}", err);
                    exit(-1)
                }
            };
            state.stream_log().await.unwrap();
            exit(0)
        }
        SubCommand::Validate(opt) => {
            let (config_path, data_path, cert_path) = match crate::process_path(&opt) {
                Ok(r) => r,
                Err(_) => exit(-1),
            };
            if let Err(e) = crate::app::validate_config(&config_path, &data_path, &cert_path).await
            {
                eprintln!("{}", e);
                exit(-1)
            } else {
                println!("{}", "Configuration is valid".green());
                exit(0)
            }
        }
        _ => (),
    }

    let requester = match match args.url {
        None => {
            let default_uds_path = validate_uds_path(
                default_uds_path,
                unix_default_path,
                unix_rootless_fallback_path,
            );
            request::Requester::new_uds(&default_uds_path).await
        }
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
            ProxyOptions::Get { group } => requester.get_group_proxy(group).await,
            ProxyOptions::List { full: short } => requester.get_group_list(short).await,
        },
        SubCommand::Conn(opt) => match opt {
            ConnOptions::List => requester.get_connections().await,
            ConnOptions::Stop { nth } => requester.stop_connections(nth).await,
            ConnOptions::Limit(opt) => match opt {
                LogsLimitOptions::Set { limit } => requester.set_conn_log_limit(limit).await,
                LogsLimitOptions::Get => requester.get_conn_log_limit().await,
            },
            ConnOptions::Master(opt) => match opt {
                MasterConnOptions::ListWg => requester.master_conn_stats().await,
                MasterConnOptions::StopWg(opt) => requester.stop_master_conn(opt.name).await,
            },
        },
        SubCommand::Tun(opt) => match opt {
            TunOptions::Get => requester.get_tun().await,
            TunOptions::Set(s) => {
                requester
                    .set_tun(match s {
                        TunSetOptions::On => true,
                        TunSetOptions::Off => false,
                    })
                    .await
            }
        },
        SubCommand::Intercept(opt) => match opt {
            InterceptOptions::List => requester.intercept(None).await,
            InterceptOptions::Range { start, end } => requester.intercept(Some((start, end))).await,
            InterceptOptions::Get { id } => requester.get_intercept_payload(id).await,
        },
        SubCommand::Reload => requester.reload_config().await,
        SubCommand::TempRule(opt) => match opt {
            TempRuleOptions::Add { literal } => requester.add_temporary_rule(literal).await,
            TempRuleOptions::Delete { literal } => requester.delete_temporary_rule(literal).await,
            TempRuleOptions::List => requester.list_temporary_rule().await,
            TempRuleOptions::Clear => requester.clear_temporary_rule().await,
        },
        SubCommand::Dns(opt) => match opt {
            DnsOptions::Lookup { domain_name } => requester.real_lookup(domain_name).await,
            DnsOptions::Mapping { fake_ip } => requester.fake_ip_to_real(fake_ip).await,
        },
        SubCommand::Start(_)
        | SubCommand::Generate(_)
        | SubCommand::Clean
        | SubCommand::Log
        | SubCommand::Validate(_) => {
            unreachable!()
        }
        #[cfg(feature = "internal-test")]
        SubCommand::Internal => internal_code(requester).await,
    };
    match result {
        Ok(_) => exit(0),
        Err(err) => {
            eprintln!("{}", err);
            exit(-1)
        }
    }
}

#[cfg(feature = "internal-test")]
use crate::cli::request::Requester;
/// This function is a shortcut for testing things conveniently. Only for development use.
#[cfg(feature = "internal-test")]
async fn internal_code(_requester: Requester) -> anyhow::Result<()> {
    println!("This option is not for end-user.");
    Ok(())
}

fn validate_uds_path(
    path_result: Option<String>,
    default_path: &str,
    rootless_path: &str,
) -> String {
    if path_result.is_none() {
        eprintln!("No connection socket found either in {} or {} (rootless mode). Please start the server first.", default_path, rootless_path);
        exit(-1)
    }
    path_result.unwrap()
}
