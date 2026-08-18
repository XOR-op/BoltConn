use std::io;

pub struct KillSwitchGuard;

impl KillSwitchGuard {
    pub fn setup(_tun_name: &str) -> io::Result<Self> {
        tracing::debug!("Kill switch is a no-op on Windows");
        Ok(Self)
    }

    pub fn teardown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn cleanup_stale_kill_switch() -> io::Result<()> {
    Ok(())
}
