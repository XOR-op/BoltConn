use crate::proxy::error::DnsError;
use std::net::IpAddr;

pub fn get_dhcp_dns(_iface_name: &str) -> Result<IpAddr, DnsError> {
    Err(DnsError::DhcpNameServer(
        "DHCP DNS discovery is not supported on Windows; configure an explicit DNS server",
    ))
}
