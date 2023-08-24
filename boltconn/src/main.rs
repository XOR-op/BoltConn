#![allow(dead_code)]

extern crate core;

use crate::app::App;
use crate::cli::SubCommand;
use crate::platform::set_maximum_opened_files;
use is_root::is_root;
use network::{
    dns::Dns,
    packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt},
};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use structopt::StructOpt;

mod adapter;
mod app;
mod cli;
mod common;
mod config;
mod dispatch;
mod external;
mod intercept;
mod network;
mod platform;
mod proxy;
mod transport;

#[derive(Debug, StructOpt)]
#[structopt(name = "boltconn", about = "Cli interface of BoltConn")]
struct Args {
    /// RESTful API URL; if not set, the controller will use unix domain socket as default.
    #[structopt(short, long)]
    pub url: Option<String>,
    #[structopt(subcommand)]
    pub cmd: SubCommand,
}

fn main() -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    let _guard = rt.enter();
    let args: Args = Args::from_args();
    let cmds = match args.cmd {
        SubCommand::Start(sub) => sub,
        _ => rt.block_on(cli::controller_main(args)),
    };
    if !is_root() {
        eprintln!("BoltConn must be run with root privilege");
        return ExitCode::FAILURE;
    }
    let target_fd_size = 7568;
    let result = set_maximum_opened_files(target_fd_size);
    match result {
        Ok(n) => {
            if n != target_fd_size {
                eprintln!(
                    "Warning: target maximum fd={}, only set to {}",
                    target_fd_size, n
                );
            }
        }
        Err(err) => {
            eprintln!(
                "Failed to increase maximum opened files to {}: {}",
                target_fd_size, err
            );
            return ExitCode::FAILURE;
        }
    }
    let (config_path, data_path, cert_path) =
        match parse_paths(&cmds.config, &cmds.app_data, &cmds.cert) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Failed to load config and app data: {}", e);
                return ExitCode::FAILURE;
            }
        };
    let app = match rt.block_on(App::create(config_path, data_path, cert_path)) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(app.serve_command());
    tracing::info!("Exiting...");
    rt.shutdown_timeout(Duration::from_millis(300));
    ExitCode::SUCCESS
}

fn parse_paths(
    config: &Option<PathBuf>,
    app_data: &Option<PathBuf>,
    cert: &Option<PathBuf>,
) -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
    let config_path = match config {
        None => {
            let home = PathBuf::from(std::env::var("HOME")?);
            home.join(".config").join("boltconn")
        }
        Some(p) => p.clone(),
    };
    let data_path = match app_data {
        None => {
            let home = PathBuf::from(std::env::var("HOME")?);
            home.join(".local").join("share").join("boltconn")
        }
        Some(p) => p.clone(),
    };
    let cert_path = match cert {
        None => data_path.join("cert"),
        Some(p) => p.clone(),
    };
    Ok((config_path, data_path, cert_path))
}
