mod cert;
mod request;

use crate::request::Requester;
use std::process::exit;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "boltctl", about = "Controller for BoltConn")]
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
enum CaptureOptions {
    /// List all captured data
    List,
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
    Capture(CaptureOptions),
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
            ConnOptions::List => requestor.get_active_conn().await,
        },
        SubCommand::Log(opt) => match opt {
            LogOptions::List => Ok(()),
        },
        SubCommand::Debug(opt) => match opt {
            DebugOptions::Session => requestor.get_sessions().await,
        },
        SubCommand::Cert(opt) => cert::generate_cert(opt.path),
        SubCommand::Capture(opt) => match opt {
            CaptureOptions::List => requestor.get_captured().await,
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
