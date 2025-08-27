use std::ffi::OsStr;
use std::io;
use std::process::{Command, Stdio};

pub mod dhcp;
pub mod route;

pub mod process;
mod sys;
pub use sys::*;

pub fn errno_err(msg: &str) -> io::Error {
    io::Error::new(io::Error::last_os_error().kind(), msg)
}

pub fn run_command(cmd: &mut Command) -> io::Result<()> {
    let mut handle = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let status = handle.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Subcommand exit status: {}",
            status
        )))
    }
}

pub fn run_command_with_args<I, S>(cmd: &str, args: I) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_command(Command::new(cmd).args(args))
}

pub(super) fn get_command_output<I, S>(cmd: &str, args: I) -> io::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if output.status.success() {
        String::from_utf8(output.stdout).map_err(io::Error::other)
    } else {
        Err(io::Error::other(format!(
            "Subcommand exit status: {}",
            output.status
        )))
    }
}
