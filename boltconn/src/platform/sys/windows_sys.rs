use ipnet::IpNet;
use std::{io, net::Ipv4Addr};
use windows::Win32::{
    Foundation::{ERROR_NOT_FOUND, ERROR_SUCCESS},
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    },
    Networking::WinSock::{AF_INET, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_INET},
};

use super::windows_interface::get_iface_luid;

pub(super) fn route_row(subnet: IpNet, name: &str) -> io::Result<MIB_IPFORWARD_ROW2> {
    let IpNet::V4(subnet) = subnet else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows TUN routes support IPv4 only",
        ));
    };
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = get_iface_luid(name)?;
    row.DestinationPrefix.Prefix = socket_address(subnet.network());
    row.DestinationPrefix.PrefixLength = subnet.prefix_len();
    row.NextHop = socket_address(Ipv4Addr::UNSPECIFIED);
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Metric = 0;
    Ok(row)
}

fn socket_address(ip: Ipv4Addr) -> SOCKADDR_INET {
    let mut address = SOCKADDR_IN {
        sin_family: AF_INET,
        ..Default::default()
    };
    address.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
    SOCKADDR_INET { Ipv4: address }
}

pub fn add_route_entry(subnet: IpNet, name: &str) -> io::Result<()> {
    let row = route_row(subnet, name)?;
    let result = unsafe { CreateIpForwardEntry2(&row) };
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result.0 as i32))
    }
}

pub fn delete_route_entry_on_interface(subnet: IpNet, name: &str) -> io::Result<()> {
    let row = match route_row(subnet, name) {
        Ok(row) => row,
        // Removing the adapter also removes its routes.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let result = unsafe { DeleteIpForwardEntry2(&row) };
    if result == ERROR_SUCCESS || result == ERROR_NOT_FOUND {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result.0 as i32))
    }
}

pub fn delete_route_entry(subnet: IpNet) -> io::Result<()> {
    // The CLI cleanup must never delete matching routes on other interfaces.
    delete_route_entry_on_interface(subnet, "utun13")
}

pub fn get_user_info() -> Option<UserInfo> {
    let name = std::env::var("USERNAME").ok()?;
    Some(UserInfo { name })
}

pub fn set_maximum_opened_files(target_size: u32) -> io::Result<u32> {
    tracing::debug!("set_maximum_opened_files does nothing on windows");
    Ok(target_size)
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub name: String,
}

impl UserInfo {
    pub fn chown(&self, _path: &std::path::Path) -> io::Result<()> {
        tracing::debug!("chown not supported on windows now");
        Ok(())
    }

    pub fn root() -> UserInfo {
        UserInfo {
            name: "root".to_string(),
        }
    }
}
