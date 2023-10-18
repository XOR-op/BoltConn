#![allow(dead_code)]

extern crate core;

use crate::app::App;
use crate::cli::SubCommand;
use crate::platform::set_maximum_opened_files;
use clap::Parser;
use is_root::is_root;
use network::{
    dns::Dns,
    packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt},
};
use std::process::ExitCode;
use std::time::Duration;

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

#[derive(Debug, Parser)]
#[structopt(name = "boltconn", about = "Cli interface of BoltConn")]
struct ProgramArgs {
    /// RESTful API URL; if not set, the controller will use unix domain socket as default.
    #[arg(short, long)]
    pub url: Option<String>,
    #[command(subcommand)]
    pub cmd: SubCommand,
}

fn main() -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    let _guard = rt.enter();
    let args: ProgramArgs = ProgramArgs::parse();
    let cmds = match args.cmd {
        SubCommand::Start(sub) => sub,
        #[cfg(feature = "internal-test")]
        SubCommand::Internal => return internal_code(),
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
        match config::parse_paths(&cmds.config, &cmds.app_data, &cmds.cert) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Failed to load config and app data: {}", e);
                return ExitCode::FAILURE;
            }
        };
    // test if the paths exist
    if !config_path.try_exists().is_ok_and(|x| x) {
        eprintln!(
            "Config path {} not found.\nDo you forget to run `boltconn init` first?",
            config_path.to_string_lossy()
        );
        return ExitCode::FAILURE;
    }
    if !data_path.try_exists().is_ok_and(|x| x) {
        eprintln!(
            "Data path {} not found.\nDo you forget to run `boltconn init` first?",
            data_path.to_string_lossy()
        );
        return ExitCode::FAILURE;
    }
    if !cert_path.try_exists().is_ok_and(|x| x) {
        eprintln!(
            "Certificate path {} not found.\nDo you forget to run `sudo boltconn init` first?",
            cert_path.to_string_lossy()
        );
        return ExitCode::FAILURE;
    }
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

/// This function is a shortcut for testing things conveniently. Only for development use.
#[cfg(feature = "internal-test")]
fn internal_code() -> ExitCode {
    println!("This option is not for end-user.");
    ExitCode::SUCCESS
}
