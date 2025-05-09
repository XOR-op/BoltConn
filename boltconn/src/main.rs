#![allow(dead_code)]

extern crate core;

use crate::app::App;
use crate::cli::{StartOptions, SubCommand};
use crate::platform::set_maximum_opened_files;
use clap::Parser;
use is_root::is_root;
use network::{
    dns::Dns,
    packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt},
};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

mod adapter;
mod app;
mod cli;
mod common;
mod config;
mod dispatch;
mod external;
mod instrument;
mod intercept;
mod network;
mod platform;
mod proxy;
mod transport;

// System default allocator (glibc) won't reclaim freed memory actively on Linux.
// Without enough SWAP and RAM, this may cause OOM. Use MiMalloc to mitigate this issue.
#[cfg(target_os = "linux")]
use mimalloc::MiMalloc;
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const GIT_VERSION: &str = git_version::git_version!(fallback = "UNKNOWN-GIT-VER");
const fn get_version() -> &'static str {
    const_format::concatcp!(env!("CARGO_PKG_VERSION"), " (", GIT_VERSION, ")")
}

#[derive(Debug, Parser)]
#[clap(name = "boltconn", about = "CLI interface of BoltConn", version = get_version())]
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
        _ => rt.block_on(cli::controller_main(args)),
    };
    if !is_root() && !cmds.rootless {
        eprintln!("BoltConn must be run with root privilege or under rootless mode. See `boltconn start --help` for more information.");
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

    let (config_path, data_path, cert_path) = match process_path(&cmds) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let app = match rt.block_on(App::create(
        config_path,
        data_path,
        cert_path,
        cmds.enable_tun,
        cmds.rootless,
    )) {
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

pub(crate) fn process_path(cmds: &StartOptions) -> Result<(PathBuf, PathBuf, PathBuf), ExitCode> {
    let (config_path, data_path, cert_path) =
        match config::parse_paths(&cmds.config, &cmds.app_data, &cmds.cert) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Failed to load config and app data: {}", e);
                return Err(ExitCode::FAILURE);
            }
        };
    // test if the paths exist
    if !config_path.try_exists().is_ok_and(|x| x) {
        eprintln!(
            "Config path {} not found.\nDo you forget to run `boltconn generate` first?",
            config_path.to_string_lossy()
        );
        return Err(ExitCode::FAILURE);
    }
    if !data_path.try_exists().is_ok_and(|x| x) {
        eprintln!(
            "Data path {} not found.\nDo you forget to run `boltconn generate` first?",
            data_path.to_string_lossy()
        );
        return Err(ExitCode::FAILURE);
    }
    if !cert_path.try_exists().is_ok_and(|x| x) {
        eprintln!(
            "Certificate path {} not found.\nDo you forget to run `boltconn generate` first?",
            cert_path.to_string_lossy()
        );
        return Err(ExitCode::FAILURE);
    }
    Ok((config_path, data_path, cert_path))
}
