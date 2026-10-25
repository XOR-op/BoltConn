use crate::platform::get_user_info;
use anyhow::Context;
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use nix::unistd::{ForkResult, dup2, fork, pipe, read, setsid, write};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// Fork into the background and return in the child only.
///
/// The parent blocks until the child calls [`notify_ready`] and then exits successfully. If the
/// child exits before that, the parent exits with failure; the child has already reported the
/// error on the terminal because stderr stays attached until [`notify_ready`].
///
/// Must be called before any thread is spawned, i.e. before the tokio runtime is created.
pub fn daemonize(log_path: Option<&Path>) -> anyhow::Result<OwnedFd> {
    let output = match log_path {
        Some(path) => OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open log file {}", path.display()))?,
        None => OpenOptions::new().write(true).open("/dev/null")?,
    };
    let devnull = File::open("/dev/null")?;
    let (ready_rx, ready_tx) = pipe()?;
    // SAFETY: the process is still single-threaded.
    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            drop(ready_tx);
            let mut buf = [0u8; 1];
            let ready = loop {
                match read(ready_rx.as_raw_fd(), &mut buf) {
                    Err(Errno::EINTR) => continue,
                    result => break matches!(result, Ok(1)),
                }
            };
            if ready {
                println!("BoltConn started in background (pid {child})");
                // Exit without running destructors, which belong to the child now.
                std::process::exit(0)
            } else {
                std::process::exit(1)
            }
        }
        ForkResult::Child => {
            drop(ready_rx);
            setsid()?;
            if let Some(path) = log_path
                && let Some(user_info) = get_user_info()
            {
                user_info
                    .chown(path)
                    .with_context(|| format!("Failed to chown log file {}", path.display()))?;
            }
            dup2(devnull.as_raw_fd(), libc::STDIN_FILENO)?;
            dup2(output.as_raw_fd(), libc::STDOUT_FILENO)?;
            std::env::set_current_dir("/")?;
            Ok(ready_tx)
        }
    }
}

/// Redirect stderr away from the terminal and let the waiting parent exit.
pub fn notify_ready(ready_tx: OwnedFd) {
    let _ = dup2(libc::STDOUT_FILENO, libc::STDERR_FILENO);
    let _ = write(&ready_tx, &[1]);
}

/// Pid file exclusively locked for the lifetime of the process.
pub struct PidFile {
    path: PathBuf,
    _file: Flock<File>,
}

impl PidFile {
    pub fn acquire(path: &Path) -> anyhow::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("Failed to open pid file {}", path.display()))?;
        let mut file = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(file) => file,
            Err((mut file, errno)) if errno == Errno::EWOULDBLOCK => {
                let mut pid = String::new();
                let _ = file.read_to_string(&mut pid);
                match pid.trim() {
                    "" => anyhow::bail!("BoltConn is already running"),
                    pid => anyhow::bail!("BoltConn is already running (pid {pid})"),
                }
            }
            Err((_, errno)) => {
                return Err(errno).context(format!("Failed to lock pid file {}", path.display()));
            }
        };
        file.set_len(0)?;
        writeln!(file, "{}", std::process::id())?;
        Ok(Self {
            path: path.to_path_buf(),
            _file: file,
        })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        // Unlink while still holding the lock, which is released afterwards when the file closes.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Remove the control socket left by an instance that did not exit cleanly.
/// Must be called while holding the [`PidFile`] lock.
pub fn remove_stale_socket(path: &Path) -> anyhow::Result<()> {
    if !path.try_exists().is_ok_and(|x| x) {
        return Ok(());
    }
    eprintln!("Warning: removing stale socket {}", path.display());
    std::fs::remove_file(path)
        .with_context(|| format!("Failed to remove stale socket {}", path.display()))
}
