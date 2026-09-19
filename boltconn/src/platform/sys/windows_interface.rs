use std::{
    io, mem,
    net::{IpAddr, Ipv4Addr},
    os::windows::io::RawSocket,
};
use windows::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS},
    NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, GetBestRoute2, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_ROW2,
    },
    Networking::WinSock::{
        AF_INET, IP_UNICAST_IF, IPPROTO_IP, IpDadStateDeprecated, IpDadStatePreferred, SOCKADDR_IN,
        SOCKADDR_INET, SOCKET, SOCKET_ERROR, WSAGetLastError, setsockopt,
    },
};

#[derive(Debug)]
struct Interface {
    name: String,
    index: u32,
    addresses: Vec<Ipv4Addr>,
}

fn interfaces() -> io::Result<Vec<Interface>> {
    let mut size = 15 * 1024u32;
    for _ in 0..4 {
        // The API places linked structures and strings in this allocation. Allocate
        // with the structure's alignment, not Vec<u8>'s alignment of one byte.
        let count = (size as usize).div_ceil(mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut storage = vec![mem::MaybeUninit::<IP_ADAPTER_ADDRESSES_LH>::uninit(); count];
        let head = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let result = unsafe {
            GetAdaptersAddresses(
                AF_INET.0 as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                None,
                Some(head),
                &mut size,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW.0 {
            continue;
        }
        if result == ERROR_NO_DATA.0 {
            return Ok(Vec::new());
        }
        if result != ERROR_SUCCESS.0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let mut result = Vec::new();
        let mut current = head;
        // All pointers below are provided by a successful API call and remain
        // valid until storage is dropped. Only owned data leaves this function.
        unsafe {
            while let Some(adapter) = current.as_ref() {
                let mut addresses = Vec::new();
                let mut unicast = adapter.FirstUnicastAddress;
                while let Some(address) = unicast.as_ref() {
                    if (address.DadState == IpDadStatePreferred
                        || address.DadState == IpDadStateDeprecated)
                        && address.Address.iSockaddrLength as usize >= mem::size_of::<SOCKADDR_IN>()
                        && !address.Address.lpSockaddr.is_null()
                        && (*address.Address.lpSockaddr).sa_family == AF_INET
                    {
                        let socket_address = &*address.Address.lpSockaddr.cast::<SOCKADDR_IN>();
                        let ip = ipv4_address(socket_address);
                        if !ip.is_unspecified() {
                            addresses.push(ip);
                        }
                    }
                    unicast = address.Next;
                }
                result.push(Interface {
                    name: adapter.FriendlyName.to_string().map_err(io::Error::other)?,
                    index: adapter.Anonymous1.Anonymous.IfIndex,
                    addresses,
                });
                current = adapter.Next;
            }
        }
        return Ok(result);
    }
    Err(io::Error::other(
        "Windows interface list kept changing during enumeration",
    ))
}

fn interface(name: &str) -> io::Result<Interface> {
    interfaces()?
        .into_iter()
        .find(|iface| iface.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Windows interface {name:?} not found"),
            )
        })
}

pub(crate) fn get_iface_index(name: &str) -> io::Result<u32> {
    let index = interface(name)?.index;
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "interface has no IPv4 index",
        ));
    }
    Ok(index)
}

pub(super) fn get_iface_luid(
    name: &str,
) -> io::Result<windows::Win32::NetworkManagement::Ndis::NET_LUID_LH> {
    use windows::Win32::NetworkManagement::{
        IpHelper::ConvertInterfaceIndexToLuid, Ndis::NET_LUID_LH,
    };
    let mut luid = NET_LUID_LH::default();
    let result = unsafe { ConvertInterfaceIndexToLuid(get_iface_index(name)?, &mut luid) };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result.0 as i32));
    }
    Ok(luid)
}

pub(crate) fn get_iface_guid(name: &str) -> io::Result<windows::core::GUID> {
    use windows::{Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToGuid, core::GUID};
    let luid = get_iface_luid(name)?;
    let mut guid = GUID::zeroed();
    let result = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result.0 as i32));
    }
    Ok(guid)
}

pub fn get_iface_address(name: &str) -> io::Result<IpAddr> {
    interface(name)?
        .addresses
        .first()
        .copied()
        .map(IpAddr::V4)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("Windows interface {name:?} has no usable IPv4 address"),
            )
        })
}

pub fn get_default_v4_route() -> io::Result<(IpAddr, String)> {
    // Preserve the previous auto-selection policy (route to 1.1.1.1), without
    // launching PowerShell or parsing formatted/localized console output.
    let mut destination = SOCKADDR_IN {
        sin_family: AF_INET,
        ..Default::default()
    };
    destination.sin_addr.S_un.S_addr = u32::from_ne_bytes([1, 1, 1, 1]);
    let destination = SOCKADDR_INET { Ipv4: destination };
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let result = unsafe { GetBestRoute2(None, 0, None, &destination, 0, &mut route, &mut source) };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result.0 as i32));
    }
    let adapter = interfaces()?
        .into_iter()
        .find(|iface| iface.index == route.InterfaceIndex)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "default IPv4 route interface disappeared",
            )
        })?;
    if unsafe { source.si_family } != AF_INET {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "default route has no IPv4 source address",
        ));
    }
    let address = unsafe { ipv4_address(&source.Ipv4) };
    if address.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "default route source is unspecified",
        ));
    }
    Ok((address.into(), adapter.name))
}

fn ipv4_address(address: &SOCKADDR_IN) -> Ipv4Addr {
    Ipv4Addr::from(unsafe { address.sin_addr.S_un.S_addr }.to_ne_bytes())
}

pub fn bind_to_interface_v4(socket: RawSocket, name: &str) -> io::Result<()> {
    let index = get_iface_index(name)?;
    // Unlike most Winsock options, IP_UNICAST_IF takes network byte order.
    let result = unsafe {
        setsockopt(
            SOCKET(socket as usize),
            IPPROTO_IP.0,
            IP_UNICAST_IF,
            Some(&index.to_be_bytes()),
        )
    };
    if result == SOCKET_ERROR {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawSocket;
    use windows::{Win32::Networking::WinSock::getsockopt, core::PSTR};

    #[test]
    fn native_loopback_lookup_and_socket_binding() {
        let loopback = interfaces()
            .unwrap()
            .into_iter()
            .find(|iface| iface.addresses.iter().any(Ipv4Addr::is_loopback))
            .unwrap();
        assert!(get_iface_address(&loopback.name).unwrap().is_loopback());
        assert_eq!(get_iface_index(&loopback.name).unwrap(), loopback.index);
        for kind in [socket2::Type::DGRAM, socket2::Type::STREAM] {
            let socket = socket2::Socket::new(socket2::Domain::IPV4, kind, None).unwrap();
            bind_to_interface_v4(socket.as_raw_socket(), &loopback.name).unwrap();
            let mut index = 0u32;
            let mut length = mem::size_of::<u32>() as i32;
            assert_eq!(
                unsafe {
                    getsockopt(
                        SOCKET(socket.as_raw_socket() as usize),
                        IPPROTO_IP.0,
                        IP_UNICAST_IF,
                        PSTR((&mut index as *mut u32).cast()),
                        &mut length,
                    )
                },
                0
            );
            // The getter returns host byte order, unlike the setter.
            assert_eq!(index, loopback.index);
        }
    }

    #[test]
    fn missing_interface_is_reported() {
        assert_eq!(
            get_iface_address("boltconn-nonexistent-interface")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            get_iface_index("boltconn-nonexistent-interface")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    #[ignore = "requires an active IPv4 default route; run on the Windows test machine"]
    fn native_default_route_matches_adapter_address() {
        let (address, name) = get_default_v4_route().unwrap();
        assert!(
            interface(&name)
                .unwrap()
                .addresses
                .iter()
                .any(|ip| IpAddr::V4(*ip) == address)
        );
    }
}
