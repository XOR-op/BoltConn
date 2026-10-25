use std::{io, net::Ipv4Addr};
use windows::{
    Win32::{
        Foundation::ERROR_SUCCESS,
        NetworkManagement::IpHelper::{
            DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER,
            FreeInterfaceDnsSettings, GetInterfaceDnsSettings, SetInterfaceDnsSettings,
        },
    },
    core::{GUID, PWSTR},
};

use super::windows_interface::get_iface_guid;

struct DnsSettings(DNS_INTERFACE_SETTINGS);

impl DnsSettings {
    fn read(guid: GUID) -> io::Result<Self> {
        let mut settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            ..Default::default()
        };
        let result = unsafe { GetInterfaceDnsSettings(guid, &mut settings) };
        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result.0 as i32));
        }
        Ok(Self(settings))
    }

    fn servers(&self) -> io::Result<String> {
        // NameServer is the static override, not the effective DHCP resolver list.
        if self.0.NameServer.is_null() {
            Ok(String::new())
        } else {
            unsafe { self.0.NameServer.to_string() }.map_err(io::Error::other)
        }
    }
}

impl Drop for DnsSettings {
    fn drop(&mut self) {
        unsafe { FreeInterfaceDnsSettings(&mut self.0) };
    }
}

fn set_servers(guid: GUID, servers: &str) -> io::Result<()> {
    // An empty string clears the static override, restoring automatic DNS.
    let mut servers: Vec<u16> = servers.encode_utf16().chain(Some(0)).collect();
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER),
        NameServer: PWSTR(servers.as_mut_ptr()),
        ..Default::default()
    };
    // Only IPv4 nameservers are changed. Suffixes, registration, and IPv6 settings
    // are neither copied back nor modified.
    let result = unsafe { SetInterfaceDnsSettings(guid, &settings) };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result.0 as i32));
    }
    Ok(())
}

fn same_servers(first: &str, second: &str) -> bool {
    let split = |c: char| c == ',' || c.is_ascii_whitespace();
    first
        .split(split)
        .filter(|s| !s.is_empty())
        .eq(second.split(split).filter(|s| !s.is_empty()))
}

struct DnsRecord {
    name: String,
    guid: GUID,
    original: String,
    changed: bool,
}

pub struct SystemDnsHandle {
    records: Vec<DnsRecord>,
    override_servers: String,
    active: bool,
}

impl SystemDnsHandle {
    /// Snapshot every target before making any change. The caller retains this
    /// handle even if apply/rollback fails, so restoration can be retried.
    pub fn prepare(tun_name: &str, outbound_name: &str) -> io::Result<Self> {
        let mut records: Vec<DnsRecord> = Vec::new();
        for name in [tun_name, outbound_name] {
            let guid = get_iface_guid(name)?;
            if records.iter().any(|record| record.guid == guid) {
                continue;
            }
            records.push(DnsRecord {
                name: name.to_owned(),
                guid,
                original: DnsSettings::read(guid)?.servers()?,
                changed: false,
            });
        }
        Ok(Self {
            records,
            override_servers: String::new(),
            active: false,
        })
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn apply(&mut self, address: Ipv4Addr) -> io::Result<()> {
        self.apply_with(address, set_servers)
    }

    fn apply_with(
        &mut self,
        address: Ipv4Addr,
        mut set: impl FnMut(GUID, &str) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.active {
            return Ok(());
        }
        if self.records.iter().any(|record| record.changed) {
            return Err(io::Error::other(
                "previous DNS restoration must finish before enabling TUN",
            ));
        }
        self.override_servers = address.to_string();
        for record in &mut self.records {
            // Include the attempted operation in rollback, even when an API
            // error could have followed a partial change.
            record.changed = true;
            if let Err(error) = set(record.guid, &self.override_servers) {
                let original =
                    io::Error::other(format!("setting DNS on {} failed: {error}", record.name));
                return match self.restore() {
                    Ok(()) => Err(original),
                    Err(rollback) => Err(io::Error::other(format!(
                        "{original}; DNS rollback failed: {rollback}"
                    ))),
                };
            }
        }
        self.active = true;
        Ok(())
    }

    pub fn restore(&mut self) -> io::Result<()> {
        self.active = false;
        let mut errors = Vec::new();
        for record in self
            .records
            .iter_mut()
            .rev()
            .filter(|record| record.changed)
        {
            let result = (|| {
                let current = DnsSettings::read(record.guid)?.servers()?;
                if same_servers(&current, &record.original) {
                    return Ok(());
                }
                if !same_servers(&current, &self.override_servers) {
                    return Err(io::Error::other(
                        "DNS was changed externally; leaving those settings untouched",
                    ));
                }
                set_servers(record.guid, &record.original)?;
                let restored = DnsSettings::read(record.guid)?.servers()?;
                if !same_servers(&restored, &record.original) {
                    return Err(io::Error::other(
                        "DNS settings did not match after restoration",
                    ));
                }
                Ok(())
            })();
            match result {
                Ok(()) => record.changed = false,
                Err(error) => errors.push(format!("{}: {error}", record.name)),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }
}

impl Drop for SystemDnsHandle {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            tracing::error!(%error, "failed to restore Windows DNS settings");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{network::TunInstance, platform};
    use windows::Win32::{
        Foundation::ERROR_NOT_FOUND, NetworkManagement::IpHelper::GetIpForwardEntry2,
    };

    fn auxiliary_settings(guid: GUID) -> (Vec<String>, Vec<u32>) {
        let state = DnsSettings::read(guid).unwrap();
        let strings = [
            state.0.Domain,
            state.0.SearchList,
            state.0.ProfileNameServer,
        ]
        .into_iter()
        .map(|p| {
            if p.is_null() {
                String::new()
            } else {
                unsafe { p.to_string().unwrap() }
            }
        })
        .collect();
        let values = vec![
            state.0.RegistrationEnabled,
            state.0.RegisterAdapterName,
            state.0.EnableLLMNR,
            state.0.QueryAdapterName,
        ];
        (strings, values)
    }

    #[test]
    #[ignore = "requires administrator and Wintun; changes DNS and host routes only on two temporary adapters"]
    fn temporary_adapter_configuration() {
        assert!(is_root::is_root());
        let (first, first_name) = TunInstance::with_name("BoltConn DNS test A").unwrap();
        first
            .set_address(&first_name, "198.18.255.251/32".parse().unwrap())
            .unwrap();
        first.interface_up(&first_name).unwrap();
        let (second, second_name) = TunInstance::with_name("BoltConn DNS test B").unwrap();
        second
            .set_address(&second_name, "198.18.255.252/32".parse().unwrap())
            .unwrap();
        second.interface_up(&second_name).unwrap();
        let first_guid = get_iface_guid(&first_name).unwrap();
        let second_guid = get_iface_guid(&second_name).unwrap();
        let resolver = "198.18.99.88".parse().unwrap();
        let original_static = "192.0.2.53,198.51.100.53";
        set_servers(first_guid, "").unwrap();
        set_servers(second_guid, original_static).unwrap();
        let first_aux = auxiliary_settings(first_guid);
        let second_aux = auxiliary_settings(second_guid);
        let assert_original = || {
            assert!(
                DnsSettings::read(first_guid)
                    .unwrap()
                    .servers()
                    .unwrap()
                    .is_empty()
            );
            assert!(same_servers(
                &DnsSettings::read(second_guid).unwrap().servers().unwrap(),
                original_static
            ));
            assert_eq!(auxiliary_settings(first_guid), first_aux);
            assert_eq!(auxiliary_settings(second_guid), second_aux);
        };
        assert_original();
        for _ in 0..2 {
            let mut handle = SystemDnsHandle::prepare(&first_name, &second_name).unwrap();
            handle.apply(resolver).unwrap();
            handle.apply(resolver).unwrap(); // Repeated enable must retain the original snapshot.
            assert!(handle.is_active());
            for guid in [first_guid, second_guid] {
                assert_eq!(
                    DnsSettings::read(guid).unwrap().servers().unwrap(),
                    "198.18.99.88"
                );
            }
            assert_eq!(auxiliary_settings(first_guid), first_aux);
            assert_eq!(auxiliary_settings(second_guid), second_aux);
            handle.restore().unwrap();
            handle.restore().unwrap();
            assert!(!handle.is_active());
            assert_original();
        }
        println!(
            "PASS: automatic DNS, ordered static DNS, repeated enable/disable, suffix and registration preservation"
        );

        // Failure before, and after, a second write must both restore earlier writes.
        for fail_after_write in [false, true] {
            let mut handle = SystemDnsHandle::prepare(&first_name, &second_name).unwrap();
            let mut calls = 0;
            let error = handle
                .apply_with(resolver, |guid, servers| {
                    calls += 1;
                    if calls == 2 && !fail_after_write {
                        return Err(io::Error::other("injected second-adapter failure"));
                    }
                    set_servers(guid, servers)?;
                    if calls == 2 {
                        return Err(io::Error::other("injected failure after second write"));
                    }
                    Ok(())
                })
                .unwrap_err();
            assert!(error.to_string().contains("injected"));
            assert!(!handle.is_active());
            assert!(handle.records.iter().all(|r| !r.changed));
            assert_original();
        }
        assert!(SystemDnsHandle::prepare(&first_name, "BoltConn nonexistent interface").is_err());
        assert_original();
        println!("PASS: snapshot failure and partial-apply rollback");

        let mut handle = SystemDnsHandle::prepare(&first_name, &second_name).unwrap();
        handle.apply(resolver).unwrap();
        set_servers(second_guid, "203.0.113.53").unwrap();
        assert!(
            handle
                .restore()
                .unwrap_err()
                .to_string()
                .contains("changed externally")
        );
        assert!(
            DnsSettings::read(first_guid)
                .unwrap()
                .servers()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            DnsSettings::read(second_guid).unwrap().servers().unwrap(),
            "203.0.113.53"
        );
        assert!(handle.records.iter().any(|r| r.changed));
        // Simulate the external change being undone, then retry the retained snapshot.
        set_servers(second_guid, "198.18.99.88").unwrap();
        handle.restore().unwrap();
        assert_original();
        drop(handle);
        let mut handle = SystemDnsHandle::prepare(&first_name, &first_name).unwrap();
        assert_eq!(handle.records.len(), 1);
        handle.apply(resolver).unwrap();
        drop(handle);
        assert_original();
        println!(
            "PASS: external changes preserved, failed restoration retried, Drop fallback and duplicate target"
        );

        // Same prefix on two test adapters: deleting A must leave B intact.
        let prefix: ipnet::Ipv4Net = "198.19.255.250/32".parse().unwrap();
        platform::add_route_entry(prefix.into(), &first_name).unwrap();
        platform::add_route_entry(prefix.into(), &second_name).unwrap();
        platform::delete_route_entry_on_interface(prefix.into(), &first_name).unwrap();
        platform::delete_route_entry_on_interface(prefix.into(), &first_name).unwrap();
        let mut row = super::super::windows_sys::route_row(prefix.into(), &second_name).unwrap();
        assert_eq!(unsafe { GetIpForwardEntry2(&mut row) }, ERROR_SUCCESS);
        // The pre-existing second route causes setup to fail. Only the first new
        // route is rolled back; the pre-existing route must remain.
        let another: ipnet::Ipv4Net = "198.19.255.249/32".parse().unwrap();
        assert!(platform::route::setup_ipv4_routes(&second_name, &[another, prefix]).is_err());
        assert_eq!(unsafe { GetIpForwardEntry2(&mut row) }, ERROR_SUCCESS);
        let mut rolled_back =
            super::super::windows_sys::route_row(another.into(), &second_name).unwrap();
        assert_eq!(
            unsafe { GetIpForwardEntry2(&mut rolled_back) },
            ERROR_NOT_FOUND
        );
        platform::delete_route_entry_on_interface(prefix.into(), &second_name).unwrap();
        println!(
            "PASS: interface-specific route deletion and partial-setup rollback preserve existing routes"
        );
        // Adapter destruction also removes all test addresses and configuration.
        drop(second);
        drop(first);
    }
}
