pub mod ipv4;
pub mod udp;
pub mod tcp;
pub mod ipv6;

#[derive(Debug, Clone, Copy)]
pub enum PayloadProtocol {
    TCP,
    UDP,
    ICMP,
    UNKNOWN,
}