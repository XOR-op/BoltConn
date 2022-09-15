use std::process::Command;
use std::{fmt, io};
use thiserror::Error;

pub mod tun_device;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;


#[derive(Debug, Error)]
pub enum SysError {
    IoError(#[from] io::Error),
    ExitStatus(std::process::ExitStatus),
}

impl fmt::Display for SysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            SysError::IoError(ref err) => write!(f, "IO Error: {}", err),
            SysError::ExitStatus(ref err) => write!(f, "Exit Status: {:?}", err),
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
