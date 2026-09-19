use sha2::{Digest, Sha256};
use std::io;
use windows::{
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            DICS_FLAG_GLOBAL, DIGCF_PRESENT, DIREG_DRV, GUID_DEVCLASS_NET, HDEVINFO,
            SP_DEVINFO_DATA, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
            SetupDiGetClassDevsW, SetupDiOpenDevRegKey,
        },
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS},
        System::Registry::{
            HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegCloseKey,
            RegGetValueW,
        },
    },
    core::{PCWSTR, w},
};

// This namespace and encoding define persistent adapter identity. Changing them
// would invalidate interface-specific Windows firewall/network configuration.
const ADAPTER_NAMESPACE: &[u8] = b"BoltConn Windows TUN adapter GUID v1\0";

pub(super) fn stable_adapter_guid(name: &str) -> io::Result<u128> {
    Ok(derive_adapter_guid(machine_guid()?, name))
}

fn derive_adapter_guid(machine: u128, name: &str) -> u128 {
    let name = name.to_ascii_lowercase();
    let mut hash = Sha256::new();
    hash.update(ADAPTER_NAMESPACE);
    hash.update(machine.to_be_bytes());
    hash.update((name.len() as u64).to_be_bytes());
    hash.update(name.as_bytes());
    let mut bytes: [u8; 16] = hash.finalize()[..16].try_into().unwrap();
    // RFC 9562 UUIDv8: custom SHA-256 derivation, with RFC variant bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    u128::from_be_bytes(bytes)
}

fn machine_guid() -> io::Result<u128> {
    // Read the existing installation identity. The 64-bit view keeps identity
    // independent of executable bitness. No registry value is created/changed.
    let mut buffer = [0u16; 64];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Microsoft\\Cryptography"),
            w!("MachineGuid"),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::other(format!(
            "cannot read Windows MachineGuid for stable TUN identity: {}",
            io::Error::from_raw_os_error(status.0 as i32),
        )));
    }
    let end = buffer
        .iter()
        .position(|&c| c == 0)
        .ok_or_else(invalid_machine_guid)?;
    let value = String::from_utf16(&buffer[..end]).map_err(|_| invalid_machine_guid())?;
    parse_machine_guid(&value)
}

fn invalid_machine_guid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Windows MachineGuid is missing or malformed",
    )
}

fn parse_machine_guid(value: &str) -> io::Result<u128> {
    let value = value.trim();
    let value = value
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(value);
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
    {
        return Err(invalid_machine_guid());
    }
    let guid =
        u128::from_str_radix(&value.replace('-', ""), 16).map_err(|_| invalid_machine_guid())?;
    if guid == 0 {
        return Err(invalid_machine_guid());
    }
    Ok(guid)
}

pub(super) fn ensure_guid_available(guid: u128) -> io::Result<()> {
    // IP Helper can retain an interface row after device removal (observed with
    // a firewall interface filter). Check present network devices instead,
    // including disabled adapters and adapters without IP bindings. All access
    // is read-only; retained Windows configuration is left to Wintun/Windows.
    struct DeviceSet(HDEVINFO);
    impl Drop for DeviceSet {
        fn drop(&mut self) {
            let _ = unsafe { SetupDiDestroyDeviceInfoList(self.0) };
        }
    }
    let devices = DeviceSet(unsafe {
        SetupDiGetClassDevsW(
            Some(&GUID_DEVCLASS_NET),
            PCWSTR::null(),
            None,
            DIGCF_PRESENT,
        )
    }?);
    for index in 0.. {
        let mut device = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        if let Err(error) = unsafe { SetupDiEnumDeviceInfo(devices.0, index, &mut device) } {
            if error.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                return Ok(());
            }
            return Err(error.into());
        }
        let key = unsafe {
            SetupDiOpenDevRegKey(
                devices.0,
                &device,
                DICS_FLAG_GLOBAL.0,
                0,
                DIREG_DRV,
                KEY_QUERY_VALUE.0,
            )
        }?;
        let mut buffer = [0u16; 64];
        let mut size = std::mem::size_of_val(&buffer) as u32;
        let status = unsafe {
            let result = RegGetValueW(
                key,
                PCWSTR::null(),
                w!("NetCfgInstanceId"),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut size),
            );
            let _ = RegCloseKey(key);
            result
        };
        // Some network-class devices have no assigned network interface GUID.
        if status == ERROR_FILE_NOT_FOUND {
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        let value = String::from_utf16_lossy(&buffer[..end]);
        if value
            .trim_matches(['{', '}'])
            .replace('-', "")
            .eq_ignore_ascii_case(&format!("{guid:032x}"))
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the BoltConn adapter GUID is already in use",
            ));
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_and_separates_machines_and_adapters() {
        let machine = parse_machine_guid("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let first = derive_adapter_guid(machine, "utun13");
        // Freeze the identity format independently of later refactoring.
        assert_eq!(first, 0x3177bcef_686d_8685_a826_7c5a698b335f);
        assert_eq!(first, derive_adapter_guid(machine, "UTUN13"));
        assert_ne!(first, derive_adapter_guid(machine + 1, "utun13"));
        assert_ne!(first, derive_adapter_guid(machine, "BoltConn test"));
        assert_eq!(first.to_be_bytes()[6] >> 4, 8);
        assert_eq!(first.to_be_bytes()[8] >> 6, 2);
    }

    #[test]
    fn machine_identity_normalization_and_validation() {
        assert_eq!(
            parse_machine_guid("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            parse_machine_guid("{00112233-4455-6677-8899-AABBCCDDEEFF}").unwrap(),
        );
        for bad in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "not-a-guid",
            "00112233_4455-6677-8899-aabbccddeeff",
        ] {
            assert!(parse_machine_guid(bad).is_err());
        }
    }

    #[test]
    fn existing_machine_identity_is_readable() {
        let first = stable_adapter_guid("utun13").unwrap();
        assert_eq!(first, stable_adapter_guid("utun13").unwrap());
    }
}
