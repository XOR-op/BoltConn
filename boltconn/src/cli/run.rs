use crate::platform::process::validate_and_encode_tag;
use clap::Args;

#[derive(Debug, Args)]
pub(crate) struct RunOptions {
    /// Tag string to assign to the launched process (must be non-empty and
    /// base64-encode to at most 21 characters to satisfy the macOS shm name limit)
    #[arg(short = 't', long = "tag")]
    pub tag: String,
    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// Set up the tag and exec the command. Returns the child's exit code (or -1 on error).
pub(crate) fn run_with_tag(opts: RunOptions) -> i32 {
    let encoded = match validate_and_encode_tag(&opts.tag) {
        Ok(e) => e,
        Err(msg) => {
            eprintln!("boltconn run: invalid tag: {}", msg);
            return 1;
        }
    };

    #[cfg(unix)]
    if let Err(e) = crate::platform::process::setup_tag_fd(&encoded) {
        eprintln!("boltconn run: failed to set up tag fd: {}", e);
        return 1;
    }

    #[cfg(target_os = "windows")]
    crate::platform::process::setup_tag_env(&encoded);

    let mut iter = opts.command.into_iter();
    let program = match iter.next() {
        Some(p) => p,
        None => {
            eprintln!("boltconn run: no command specified");
            return 1;
        }
    };
    let args: Vec<String> = iter.collect();

    match std::process::Command::new(&program).args(&args).status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("boltconn run: failed to execute '{}': {}", program, e);
            1
        }
    }
}
