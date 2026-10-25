use ipnet::Ipv4Net;

use super::windows_tun_identity::{ensure_guid_available, stable_adapter_guid};
use crate::common::async_session::AsyncSession;

use std::{io, sync::Arc};

pub(crate) struct TunInstance {
    session: Option<AsyncSession>,
    adapter: Arc<wintun::Adapter>,
}

impl TunInstance {
    pub fn new() -> io::Result<(Self, String)> {
        let name = "utun13";
        Self::with_guid(name, Some(stable_adapter_guid(name)?))
    }

    #[cfg(test)]
    pub(crate) fn with_name(name: &str) -> io::Result<(Self, String)> {
        Self::with_guid(name, None)
    }

    fn with_guid(name: &str, guid: Option<u128>) -> io::Result<(Self, String)> {
        // Do not touch a pre-existing interface with our chosen name.
        match crate::platform::get_iface_index(name) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("interface {name:?} already exists"),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if let Some(guid) = guid {
            ensure_guid_available(guid)?;
        }
        let executable = std::env::current_exe()?;
        let directory = executable
            .parent()
            .ok_or_else(|| io::Error::other("executable has no parent directory"))?;
        // Cargo puts test executables in target/debug/deps. Use the same DLL
        // as the application in target/debug for explicitly enabled driver tests.
        #[cfg(test)]
        let directory = directory.parent().unwrap_or(directory);
        let library = directory.join("wintun.dll");
        let module = unsafe { wintun::load_from_path(&library) }.map_err(|error| {
            io::Error::other(format!("Failed to load {}: {error}", library.display()))
        })?;
        let device = wintun::Adapter::create(&module, name, "utun", guid).map_err(|error| {
            io::Error::other(format!(
                "Failed to create Wintun adapter: {error}; Windows error: {}",
                io::Error::last_os_error()
            ))
        })?;
        if let Some(guid) = guid
            && crate::platform::get_iface_guid(name)? != windows::core::GUID::from_u128(guid)
        {
            return Err(io::Error::other(
                "Wintun did not create the requested adapter GUID",
            ));
        }
        let session = device
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(io::Error::from)?;
        Ok((
            Self {
                session: Some(AsyncSession::new(session)),
                adapter: device,
            },
            name.to_string(),
        ))
    }

    pub fn take_fd(&mut self) -> Option<AsyncSession> {
        self.session.take()
    }

    pub fn interface_up(&self, name: &str) -> io::Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match crate::platform::get_iface_address(name) {
                Ok(_) => return Ok(()),
                Err(error) if std::time::Instant::now() >= deadline => return Err(error),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    }

    pub fn set_address(&self, name: &str, addr: Ipv4Net) -> io::Result<()> {
        let index = crate::platform::get_iface_index(name)?;
        // Pass arguments directly, without shell quotes embedded in the adapter
        // name. Use its numeric index to also support names containing spaces.
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "set", "address"])
            .arg(format!("name={index}"))
            .arg("source=static")
            .arg(format!("address={}", addr.addr()))
            .arg(format!("mask={}", addr.netmask()))
            .arg("gateway=none")
            .arg("store=active")
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "Failed to set Wintun IPv4 address ({index}, {addr}): {}; stdout: {}; stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim(),
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires administrator and Wintun; creates a temporary adapter with a stable test GUID"]
    fn stable_adapter_identity_lifecycle() {
        assert!(is_root::is_root());
        let name = "BoltConn stable GUID test";
        let guid = stable_adapter_guid(name).unwrap();
        assert_ne!(guid, stable_adapter_guid("utun13").unwrap());
        for _ in 0..2 {
            let (tun, _) = TunInstance::with_guid(name, Some(guid)).unwrap();
            assert_eq!(
                crate::platform::get_iface_guid(name).unwrap(),
                windows::core::GUID::from_u128(guid)
            );
            // A different name must not let a second caller take this identity.
            let error = match TunInstance::with_guid("BoltConn GUID collision test", Some(guid)) {
                Err(error) => error,
                Ok(_) => panic!("an occupied adapter GUID was accepted"),
            };
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            tun.set_address(name, "198.18.255.253/32".parse().unwrap())
                .unwrap();
            tun.interface_up(name).unwrap();
            drop(tun);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if ensure_guid_available(guid).is_ok() {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "adapter GUID remains occupied after removal"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }

    #[test]
    #[ignore = "requires administrator rights and wintun.dll; creates a temporary adapter and may install the Wintun driver"]
    fn adapter_lifecycle() {
        let executable = std::env::current_exe().unwrap();
        let log_path = executable
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("wintun-lifecycle.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(log))
            .try_init();
        println!("Wintun diagnostics: {}", log_path.display());
        let elevated = is_root::is_root();
        tracing::info!(elevated, "Wintun adapter test starting");
        assert!(
            elevated,
            "Wintun requires an elevated terminal: open PowerShell with Run as administrator"
        );
        let name = "BoltConn lifecycle test";
        let address: Ipv4Net = "198.18.255.254/32".parse().unwrap();
        for _ in 0..2 {
            let (mut tun, actual_name) = TunInstance::with_name(name).unwrap_or_else(|error| {
                tracing::error!(%error, "Wintun adapter creation failed");
                panic!("{error}");
            });
            tun.set_address(&actual_name, address).unwrap();
            tun.interface_up(&actual_name).unwrap();
            assert_eq!(
                crate::platform::get_iface_address(&actual_name).unwrap(),
                std::net::IpAddr::V4(address.addr())
            );
            let session = tun.take_fd().unwrap();
            // The reader is idle in receive_blocking. Dropping it must release
            // the session and let the adapter disappear, without needing traffic.
            drop(session);
            drop(tun);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match crate::platform::get_iface_index(name) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                    result => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "adapter was not removed: {result:?}"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        }
    }
}
