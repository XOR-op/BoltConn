use std::process::Command;
use std::{fmt, io};
use thiserror::Error;

pub mod tun_device;

#[derive(Debug, Error)]
pub enum SysError {
    CmdIo(#[from] io::Error),
    ExitStatus(std::process::ExitStatus),
    Tun(errno::Errno),
}

impl fmt::Display for SysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            SysError::CmdIo(ref err) => write!(f, "IO Error: {}", err),
            SysError::ExitStatus(ref err) => write!(f, "Exit Status: {:?}", err),
            SysError::Tun(ref err) => write!(f, "Failed to open TUN device: {}", err),
        }
    }
}

fn run_command(cmd: &str, args: &[&str]) -> Result<(), SysError> {
    let mut handle = Command::new(cmd).args(args).spawn()?;
    let status = handle.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(SysError::ExitStatus(status))
    }
}

fn run_privileged_command(cmd: &str, args: &[&str]) -> Result<(), SysError> {
    let mut handle = Command::new("sudo").arg(cmd).args(args).spawn()?;
    let status = handle.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(SysError::ExitStatus(status))
    }
}
