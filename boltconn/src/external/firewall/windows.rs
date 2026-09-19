use std::io;

pub struct KillSwitchGuard;

impl KillSwitchGuard {
    pub fn setup(_tun_name: &str) -> io::Result<Self> {
        tracing::warn!(
            "Kill switch is not supported on Windows; traffic outside BoltConn is not blocked"
        );
        Ok(Self)
    }

    pub fn teardown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn cleanup_stale_kill_switch() -> io::Result<()> {
    Ok(())
}
