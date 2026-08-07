use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

mod app;

#[derive(Debug, Parser)]
#[command(name = "bolt-tui", about = "Terminal interface for BoltConn", version)]
pub(crate) struct ProgramArgs {
    #[command(subcommand)]
    command: TuiCommand,
}

#[derive(Debug, Subcommand)]
enum TuiCommand {
    /// Review `.REQUEST` approvals from the instrument server.
    Approve(ApproveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ApproveArgs {
    /// Instrument endpoint as a bare host:port; skips config lookup when provided.
    #[arg(short, long)]
    pub(crate) url: Option<String>,
    /// Path to the BoltConn configuration directory.
    #[arg(short, long)]
    pub(crate) config: Option<PathBuf>,
    /// Comma-separated instrument subscriber IDs.
    #[arg(short = 'i', long)]
    pub(crate) id: String,
    /// Instrument WebSocket secret; requires --url and skips config lookup.
    #[arg(long)]
    pub(crate) secret: Option<String>,
}

fn main() -> ExitCode {
    let args = ProgramArgs::parse();
    let runtime = tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");
    let result = match args.command {
        TuiCommand::Approve(args) => runtime.block_on(app::run(args)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
