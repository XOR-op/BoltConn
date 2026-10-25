use crate::proxy::error::DnsError;
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    ptr,
};
use windows::{
    Win32::{
        Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS},
        NetworkManagement::Dhcp::{
            DHCPAPI_PARAMS, DHCPCAPI_PARAMS_ARRAY, DHCPCAPI_REQUEST_SYNCHRONOUS, DhcpCApiCleanup,
            DhcpCApiInitialize, DhcpRequestParams,
        },
    },
    core::PCWSTR,
};

/// Blocking DHCP client query; callers must run discovery off async workers.
/// Option 6 comes from the DHCP client, not the adapter's effective DNS settings
/// (which BoltConn can override while TUN is enabled).
pub fn get_dhcp_dns(iface_name: &str) -> Result<IpAddr, DnsError> {
    request_dns(iface_name).map(IpAddr::V4).map_err(|error| {
        tracing::debug!("Windows DHCP DNS on {iface_name}: {error}");
        DnsError::DhcpNameServer("Windows DHCP client did not provide a usable DNS server")
    })
}

// Coordinate process-wide initialization/cleanup across concurrent interfaces.
static CLIENT_USERS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
struct DhcpClient;
impl DhcpClient {
    fn acquire() -> io::Result<Self> {
        let mut users = CLIENT_USERS.lock().unwrap();
        if *users == 0 {
            let mut version = 0;
            let status = unsafe { DhcpCApiInitialize(&mut version) };
            if status != ERROR_SUCCESS.0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
        }
        *users += 1;
        Ok(Self)
    }
}
impl Drop for DhcpClient {
    fn drop(&mut self) {
        let mut users = CLIENT_USERS.lock().unwrap();
        *users -= 1;
        if *users == 0 {
            unsafe { DhcpCApiCleanup() };
        }
    }
}

fn request_dns(iface_name: &str) -> io::Result<Ipv4Addr> {
    let guid = crate::platform::get_iface_guid(iface_name)?;
    let adapter: Vec<u16> = format!("{{{guid:?}}}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let _client = DhcpClient::acquire()?;
    let mut size = 1024u32;
    for _ in 0..4 {
        if size > 64 * 1024 {
            return Err(io::Error::other("DHCP option buffer is too large"));
        }
        let mut buffer = vec![0u8; size as usize];
        let mut option = DHCPAPI_PARAMS {
            OptionId: 6,
            ..Default::default()
        };
        let status = unsafe {
            DhcpRequestParams(
                DHCPCAPI_REQUEST_SYNCHRONOUS,
                ptr::null_mut(),
                PCWSTR(adapter.as_ptr()),
                ptr::null_mut(),
                DHCPCAPI_PARAMS_ARRAY::default(),
                DHCPCAPI_PARAMS_ARRAY {
                    nParams: 1,
                    Params: &mut option,
                },
                buffer.as_mut_ptr(),
                &mut size,
                PCWSTR::null(),
            )
        };
        if status == ERROR_MORE_DATA.0 {
            continue;
        }
        if status != ERROR_SUCCESS.0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // The API returns a pointer into our buffer. Validate its range and use
        // the owned buffer's slice, so no native pointer escapes this call.
        let offset = (option.Data as usize).checked_sub(buffer.as_ptr() as usize);
        let data = offset
            .and_then(|start| {
                start
                    .checked_add(option.nBytesData as usize)
                    .map(|end| (start, end))
            })
            .and_then(|(start, end)| buffer.get(start..end))
            .ok_or_else(|| io::Error::other("DHCP DNS option is missing or outside its buffer"))?;
        return parse_dns_option(data);
    }
    Err(io::Error::other("DHCP option buffer kept changing"))
}

fn parse_dns_option(data: &[u8]) -> io::Result<Ipv4Addr> {
    if data.is_empty() || data.len() % 4 != 0 {
        return Err(io::Error::other("missing or malformed DHCP DNS option"));
    }
    data.chunks_exact(4)
        .map(|bytes| Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
        .find(|ip| {
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
        })
        .ok_or_else(|| io::Error::other("DHCP DNS option contains no usable IPv4 server"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_six_uses_first_usable_server() {
        assert_eq!(
            parse_dns_option(&[192, 168, 1, 1, 8, 8, 8, 8]).unwrap(),
            Ipv4Addr::new(192, 168, 1, 1)
        );
        assert_eq!(
            parse_dns_option(&[
                0, 0, 0, 0, 127, 0, 0, 1, 224, 0, 0, 1, 255, 255, 255, 255, 1, 1, 1, 1
            ])
            .unwrap(),
            Ipv4Addr::new(1, 1, 1, 1)
        );
        for data in [
            &[][..],
            &[1, 2, 3],
            &[1, 2, 3, 4, 5],
            &[0, 0, 0, 0],
            &[127, 0, 0, 1],
        ] {
            assert!(parse_dns_option(data).is_err());
        }
    }

    #[test]
    fn missing_interface_is_reported() {
        assert!(get_dhcp_dns("boltconn-nonexistent-dhcp-interface").is_err());
    }

    #[test]
    #[ignore = "queries DHCP option 6 on BOLTCONN_TEST_DHCP_INTERFACE; may send DHCP-INFORM"]
    fn live_dhcp_dns() {
        let iface = std::env::var("BOLTCONN_TEST_DHCP_INTERFACE").unwrap();
        let expected: IpAddr = std::env::var("BOLTCONN_TEST_DHCP_DNS")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(get_dhcp_dns(&iface).unwrap(), expected);
    }
}
