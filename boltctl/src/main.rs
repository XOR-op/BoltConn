mod request;

use std::process::exit;
use colored::Colorize;
use structopt::StructOpt;
use crate::request::Requester;

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
    Set {
        group: String,
        proxy: String,
    },
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
enum SubCommand {
    /// Proxy Settings
    Proxy(ProxyOptions),
    /// Connection Settings
    Conn(ConnOptions),
    /// Logs Operations
    Log(LogOptions),
    /// API for Debugging
    Debug(DebugOptions),
}

#[tokio::main]
async fn main() {
    let args: Args = Args::from_args();
    let requestor = Requester { port: args.port };
    let result = match args.cmd {
        SubCommand::Proxy(opt) => {
            match opt {
                ProxyOptions::Set { group, proxy } => {
                    requestor.set_group_proxy(group, proxy).await
                }
                ProxyOptions::List => {
                    requestor.get_group_list().await
                }
            }
        }
        SubCommand::Conn(opt) => {
            match opt { ConnOptions::List => { Ok(()) } }
        }
        SubCommand::Log(opt) => {
            match opt { LogOptions::List => { Ok(()) } }
        }
        SubCommand::Debug(opt) => {
            match opt { DebugOptions::Session => { Ok(()) } }
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
