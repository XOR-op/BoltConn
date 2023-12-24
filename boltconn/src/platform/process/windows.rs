use windows::{
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_ESTAB, TCP_TABLE_CLASS,
            TCP_TABLE_OWNER_PID_CONNECTIONS, UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6},
        System::Threading::{
            OpenProcess, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

use crate::platform::process::{NetworkType, ProcessInfo};
use std::{
    mem,
    net::{IpAddr, SocketAddr},
};

pub fn get_pid(addr: SocketAddr, net_type: NetworkType) -> std::io::Result<libc::pid_t> {
    let family = match addr {
        SocketAddr::V4(_) => AF_INET,
        SocketAddr::V6(_) => AF_INET6,
    };

    let data = get_table(family, net_type)?;
    let pid = RecordSearcher::new(&addr, NetworkType).search(&data, addr)?;
    Ok(pid as libc::pid_t)
}

fn get_table(family: ADDRESS_FAMILY, net_type: NetworkType) -> std::io::Result<Vec<u8>> {
    let mut buf_size = 8u32;
    for _ in 0..10 {
        let mut buf = vec![0; buf_size as usize];
        let err_no = match net_type {
            NetworkType::Tcp => unsafe {
                GetExtendedTcpTable(
                    Some(buf.as_mut_ptr() as *mut _),
                    (&mut buf_size) as *mut _,
                    false,
                    family,
                    TCP_TABLE_OWNER_PID_CONNECTIONS,
                    0,
                )
            },
            NetworkType::Udp => unsafe {
                GetExtendedUdpTable(
                    Some(buf.as_mut_ptr() as *mut _),
                    (&mut buf_size) as *mut _,
                    false,
                    family,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            },
        };
        match err_no {
            0 => return Ok(buf),
            ERROR_INSUFFICIENT_BUFFER => continue,
            other => return Err(std::io::Error::from_raw_os_error(other as i32)),
        }
    }
    Err(std::io::ErrorKind::NotFound.into())
}

pub fn get_process_info(pid: i32) -> Option<ProcessInfo> {
    let (ppid, path, name, cmdline) = get_process_info_inner(pid)?;
    let p_name = get_process_info_inner(ppid).map(|(_, _, p_name, _)| p_name);
    Some(ProcessInfo {
        pid,
        ppid,
        path,
        name,
        cmdline,
        parent_name: p_name,
    })
}

fn get_process_info_inner(pid: i32) -> Option<(i32, String, String, String)> {
    match pid {
        0 => return (0, "", ":System Idle Process", ""),
        4 => return (0, "", ":System", ""),
        _ => {}
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    const INFO_SIZE: usize = std::mem::size_of::<PROCESS_BASIC_INFORMATION>();
    let mut proc_basic_info: PROCESS_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mut out_len_unused = 0u32;
    let err_no = unsafe {
        NtQueryInformationProcess(
            handle,
            ProcessBasicInformation,
            proc_basic_info.as_mut_ptr() as *mut _,
            INFO_SIZE as u32,
            &mut out_len_unused as *mut u32,
        )
    };
    if err_no.is_err() {
        let _ = unsafe { CloseHandle(handle) };
        return None;
    }
    let ppid = proc_basic_info.InheritedFromUniqueProcessId as i32;
    let parameters = unsafe { *(*proc_basic_info.PebBaseAddress).ProcessParameters };
    let cmdline = String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(
            parameters.CommandLine.Buffer,
            parameters.CommandLine.Length as usize / 2,
        )
    });
    let path = String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(
            parameters.ImagePathName.Buffer,
            parameters.ImagePathName.Length as usize / 2,
        )
    });
    let name = path.rsplit('\\').next().unwrap_or("").to_owned();
    let _ = unsafe { CloseHandle(handle) };
    Some((ppid, path, name, cmdline))
}

// Search for the data returned by GetExtented*Table.
// Offsets correspond to MIB_TCPROW_OWNER_PID, MIB_TCP6ROW_OWNER_PID etc.
struct RecordSearcher {
    item_size: usize,
    ip: usize,
    ip_size: usize,
    port: usize,
    pid: usize,
    tcp_state: Option<usize>,
}

impl RecordSearcher {
    fn new(addr: &SocketAddr, net_type: NetworkType) -> Self {
        match (addr, net_type) {
            (&SocketAddr::V4(_), NetworkType::Tcp) => Self {
                item_size: 24,
                ip: 4,
                ip_size: 4,
                port: 8,
                pid: 20,
                tcp_state: Some(0),
            },
            (&SocketAddr::V4(_), NetworkType::Udp) => Self {
                item_size: 12,
                port: 4,
                ip: 0,
                ip_size: 4,
                pid: 8,
                tcp_state: None,
            },
            (&SocketAddr::V6(_), NetworkType::Tcp) => Self {
                item_size: 56,
                ip: 0,
                ip_size: 16,
                port: 20,
                pid: 52,
                tcp_state: Some(48),
            },
            (&SocketAddr::V6(_), NetworkType::Udp) => Self {
                item_size: 28,
                ip: 0,
                ip_size: 16,
                port: 20,
                pid: 24,
                tcp_state: None,
            },
        }
    }
}

impl RecordSearcher {
    fn search(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<u32> {
        let record_cnt =
            u32::from_ne_bytes(data.get(0..4).ok_or_else(|| std::io::ErrorKind::NotFound)?);
        for i in 0..record_cnt {
            let record = data
                .get((4 + i * self.item_size)..(4 + i * (self.item_size + 1)))
                .ok_or_else(|| std::io::ErrorKind::NotFound)?;
            // only check established TCP record
            if let Some(tcp_state_offset) = self.tcp_state {
                let tcp_state = u32::from_ne_bytes(record[tcp_state_offset..tcp_state_offset + 4]);
                if tcp_state != MIB_TCP_STATE_ESTAB {
                    continue;
                }
            }
            let src_port =
                u16::from_be(u32::from_ne_bytes(record[self.port..self.port + 4]) as u16);
            if src_port != addr.port() {
                continue;
            }
            let ip = match self.ip_size {
                4 => {
                    let mut ip = [0u8; 4];
                    ip.clone_from_slice(&record[self.ip..self.ip + 4]);
                    IpAddr::from(ip)
                }
                16 => {
                    let mut ip = [0u8; 16];
                    ip.clone_from_slice(&record[self.ip..self.ip + 16]);
                    IpAddr::from(ip)
                }
                _ => unreachable!(),
            };
            // the second clause only happens to 0.0.0.0/[::] UDP
            if ip != addr.ip() && !(addr.ip().is_unspecified() && self.tcp_state.is_none()) {
                continue;
            }
            return Ok(u32::from_ne_bytes(record[self.pid..self.pid + 4]));
        }
        Err(std::io::ErrorKind::NotFound.into())
    }
}
