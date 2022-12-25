mod cert;
mod clean;
mod request;

use crate::request::Requester;
use is_root::is_root;
use std::process::exit;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "boltmgr", about = "Controller for BoltConn")]
struct Args {
    /// RESTful API port
    #[structopt(short, long, default_value = "18086")]
    pub port: u16,
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
struct CertOptions {
    #[structopt(short, long, default_value = "./_private/ca")]
    path: String,
}

#[derive(Debug, StructOpt)]
enum MitmOptions {
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
    /// API for Debugging
    Debug(DebugOptions),
    /// Generate Certificates
    Cert(CertOptions),
    /// Captured HTTP data
    Mitm(MitmOptions),
    /// Clean unexpected shutdown
    Clean,
}

#[tokio::main]
async fn main() {
    let args: Args = Args::from_args();
    let requestor = Requester { port: args.port };
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
        SubCommand::Debug(opt) => match opt {
            DebugOptions::Session => requestor.get_sessions().await,
        },
        SubCommand::Cert(opt) => cert::generate_cert(opt.path),
        SubCommand::Mitm(opt) => match opt {
            MitmOptions::List => requestor.get_mitm(None).await,
            MitmOptions::Range { start, end } => requestor.get_mitm(Some((start, end))).await,
            MitmOptions::Get { id } => requestor.get_mitm_payload(id).await,
        },
        SubCommand::Clean => {
            if !is_root() {
                eprintln!("Must be run with root/admin privilege");
                exit(-1)
            } else {
                clean::clean_route_table();
                Ok(())
            }
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
