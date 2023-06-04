#![allow(dead_code)]

extern crate core;

use crate::app::App;
use is_root::is_root;
use network::{
    dns::Dns,
    packet::transport_layer::{TcpPkt, TransLayerPkt, UdpPkt},
};
use std::path::PathBuf;
use std::process::ExitCode;
use structopt::StructOpt;

mod adapter;
mod app;
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
#[structopt(name = "boltconn", about = "BoltConn core binary")]
struct Args {
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

fn main() -> ExitCode {
    if !is_root() {
        eprintln!("BoltConn must be run with root privilege.");
        return ExitCode::from(1);
    }
    let args: Args = Args::from_args();
    let (config_path, data_path, cert_path) =
        match parse_paths(&args.config, &args.app_data, &args.cert) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Failed to load config and app data: {}", e);
                return ExitCode::from(1);
            }
        };
    let app = match App::new(config_path, data_path, cert_path) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    ExitCode::from(0)
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
