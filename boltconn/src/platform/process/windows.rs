use windows::{
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_SYN_SENT,
            TCP_TABLE_OWNER_PID_CONNECTIONS, UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6},
        System::Threading::{
            OpenProcess, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        },
    },
};

use crate::platform::process::{NetworkType, ParentProcess, ProcessInfo, ProcessInfoDepth};
use std::{
    mem,
    net::{IpAddr, SocketAddr},
};

/// Owns a process handle, including on early returns from memory reads.
pub(super) struct ProcessHandle(pub HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub fn get_pid(addr: SocketAddr, net_type: NetworkType) -> std::io::Result<i32> {
    let family = match addr {
        SocketAddr::V4(_) => AF_INET,
        SocketAddr::V6(_) => AF_INET6,
    };

    let data = get_table(family, net_type)?;
    let pid = RecordSearcher::new(&addr, net_type).search(&data, addr)?;
    Ok(pid as i32)
}

fn get_table(family: ADDRESS_FAMILY, net_type: NetworkType) -> std::io::Result<Vec<u8>> {
    let mut buf_size = 8u32;
    for _ in 0..10 {
        // IP Helper writes DWORD-aligned table headers and rows.
        let mut buf = vec![0u32; (buf_size as usize).div_ceil(4)];
        let err_no = match net_type {
            NetworkType::Tcp => unsafe {
                GetExtendedTcpTable(
                    Some(buf.as_mut_ptr() as *mut _),
                    (&mut buf_size) as *mut _,
                    false,
                    family.0 as u32,
                    TCP_TABLE_OWNER_PID_CONNECTIONS,
                    0,
                )
            },
            NetworkType::Udp => unsafe {
                GetExtendedUdpTable(
                    Some(buf.as_mut_ptr() as *mut _),
                    (&mut buf_size) as *mut _,
                    false,
                    family.0 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            },
        };
        const ERR_INSUFFICIENT_BUF: u32 = ERROR_INSUFFICIENT_BUFFER.0;
        match err_no {
            0 => return Ok(buf.into_iter().flat_map(u32::to_ne_bytes).collect()),
            ERR_INSUFFICIENT_BUF => continue,
            other => return Err(std::io::Error::from_raw_os_error(other as i32)),
        }
    }
    Err(std::io::ErrorKind::NotFound.into())
}

pub fn get_process_info(pid: i32, depth: ProcessInfoDepth) -> Option<ProcessInfo> {
    let (ppid, path, name, cmdline, cwd) = get_process_info_inner(pid)?;
    let parent = if let Some(next_depth) = depth.next_level().filter(|_| ppid > 0 && ppid != pid) {
        get_process_info(ppid, next_depth)
            .map(|info| ParentProcess::Process(Box::new(info)))
            .unwrap_or(ParentProcess::Ppid(ppid))
    } else if ppid <= 0 || ppid == pid {
        ParentProcess::None
    } else {
        ParentProcess::Ppid(ppid)
    };
    Some(ProcessInfo {
        pid,
        parent,
        path,
        name,
        cmdline,
        cwd,
        tag: super::tag::get_tag_for_pid(pid),
    })
}

fn get_process_info_inner(pid: i32) -> Option<(i32, String, String, String, String)> {
    match pid {
        0 => {
            return Some((
                0,
                "".to_string(),
                ":System Idle Process".to_string(),
                "".to_string(),
                "".to_string(),
            ));
        }
        4 => {
            return Some((
                0,
                "".to_string(),
                ":System".to_string(),
                "".to_string(),
                "".to_string(),
            ));
        }
        _ => {}
    }
    let handle = ProcessHandle(
        unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid as u32,
            )
        }
        .ok()?,
    );
    const INFO_SIZE: usize = std::mem::size_of::<PROCESS_BASIC_INFORMATION>();
    let mut proc_basic_info: PROCESS_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mut out_len_unused = 0u32;
    let err_no = unsafe {
        NtQueryInformationProcess(
            handle.0,
            ProcessBasicInformation,
            &mut proc_basic_info as *mut _ as *mut _,
            INFO_SIZE as u32,
            &mut out_len_unused as *mut u32,
        )
    };
    if err_no.is_err() {
        return None;
    }
    let ppid = proc_basic_info.InheritedFromUniqueProcessId as i32;
    let parameters =
        super::windows_memory::read_parameters(handle.0, proc_basic_info.PebBaseAddress)?;
    let cmdline =
        super::windows_memory::read_string(handle.0, parameters.command_line).unwrap_or_default();
    let path = super::windows_memory::read_string(handle.0, parameters.image).unwrap_or_default();
    let cwd = super::windows_memory::read_string(handle.0, parameters.cwd).unwrap_or_default();
    let name = path.rsplit('\\').next().unwrap_or("UNKNOWN").to_owned();
    Some((ppid, path, name, cmdline, cwd))
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
        if data.len() < 4 {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        let mut possible_udp = None;
        let record_cnt = slice_to_u32(&data[0..4]);
        for i in 0..(record_cnt as usize) {
            let record = data
                .get((4 + i * self.item_size)..(4 + (i + 1) * self.item_size))
                .ok_or(std::io::ErrorKind::NotFound)?;
            // A TUN can observe the initial SYN before the connection is established.
            if let Some(tcp_state_offset) = self.tcp_state {
                let tcp_state = slice_to_u32(&record[tcp_state_offset..tcp_state_offset + 4]);
                if tcp_state != MIB_TCP_STATE_ESTAB.0 as u32
                    && tcp_state != MIB_TCP_STATE_SYN_SENT.0 as u32
                {
                    continue;
                }
            }
            let src_port = u16::from_be(slice_to_u32(&record[self.port..self.port + 4]) as u16);
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
            if ip != addr.ip() {
                // Only a wildcard-bound UDP socket can own traffic from a different
                // local address. A matching port on another concrete address cannot.
                if ip.is_unspecified() && self.tcp_state.is_none() {
                    possible_udp = Some(slice_to_u32(&record[self.pid..self.pid + 4]));
                }
                continue;
            }
            return Ok(slice_to_u32(&record[self.pid..self.pid + 4]));
        }
        if let Some(pid) = possible_udp {
            return Ok(pid);
        }
        Err(std::io::ErrorKind::NotFound.into())
    }
}

fn slice_to_u32(slice: &[u8]) -> u32 {
    u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_live_ipv4_tcp_and_udp_sockets() {
        use std::net::{TcpListener, TcpStream, UdpSocket};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let pid = std::process::id() as i32;
        assert_eq!(
            get_pid(client.local_addr().unwrap(), NetworkType::Tcp).unwrap(),
            pid
        );
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], socket.local_addr().unwrap().port()));
        assert_eq!(get_pid(addr, NetworkType::Udp).unwrap(), pid);
    }

    #[test]
    fn reads_current_process_metadata() {
        let info =
            get_process_info(std::process::id() as i32, ProcessInfoDepth::Limited(1)).unwrap();
        let exe = std::env::current_exe().unwrap();
        assert_eq!(info.name, exe.file_name().unwrap().to_string_lossy());
        assert_eq!(
            std::fs::canonicalize(&info.path).unwrap(),
            exe.canonicalize().unwrap()
        );
        assert_eq!(
            std::fs::canonicalize(&info.cwd).unwrap(),
            std::env::current_dir().unwrap().canonicalize().unwrap()
        );
        assert!(!info.cmdline.is_empty());
        assert!(info.parent_pid() > 0);
    }

    #[test]
    fn reads_native_and_wow64_child_tags() {
        use std::{
            process::{Child, Command, Stdio},
            time::{Duration, Instant},
        };
        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let root = std::env::var("SystemRoot").unwrap();
        for directory in ["System32", "SysWOW64"] {
            let exe = std::path::Path::new(&root)
                .join(directory)
                .join("WindowsPowerShell/v1.0/powershell.exe");
            if !exe.exists() {
                continue;
            }
            let tag = "test-标签";
            let encoded = super::super::tag::validate_and_encode_tag(tag).unwrap();
            let child = ChildGuard(
                Command::new(&exe)
                    .args([
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        "Start-Sleep -Seconds 30",
                    ])
                    .env("BOLTCONN_TAG", encoded)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let info = get_process_info(child.0.id() as i32, ProcessInfoDepth::Limited(0));
                if let Some(info) = info
                    && info.tag.as_deref() == Some(tag)
                {
                    assert!(info.name.eq_ignore_ascii_case("powershell.exe"));
                    assert!(info.cmdline.contains("Start-Sleep"));
                    assert!(!info.cwd.is_empty());
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "failed to read {directory} child tag"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    fn udp_table(rows: &[([u8; 4], u16, u32)]) -> Vec<u8> {
        let mut data = (rows.len() as u32).to_ne_bytes().to_vec();
        for (ip, port, pid) in rows {
            data.extend(ip);
            // dwLocalPort stores the network-order port in the low 16 bits.
            data.extend((port.to_be() as u32).to_ne_bytes());
            data.extend(pid.to_ne_bytes());
        }
        data
    }

    #[test]
    fn udp_lookup_prefers_exact_address_over_wildcard() {
        let addr = "192.0.2.1:1234".parse().unwrap();
        let data = udp_table(&[([0, 0, 0, 0], 1234, 10), ([192, 0, 2, 1], 1234, 20)]);
        assert_eq!(
            RecordSearcher::new(&addr, NetworkType::Udp)
                .search(&data, addr)
                .unwrap(),
            20
        );
    }

    #[test]
    fn udp_lookup_does_not_guess_from_port_on_another_address() {
        let addr = "192.0.2.1:1234".parse().unwrap();
        let data = udp_table(&[([192, 0, 2, 2], 1234, 20)]);
        assert!(
            RecordSearcher::new(&addr, NetworkType::Udp)
                .search(&data, addr)
                .is_err()
        );
        let data = udp_table(&[([0, 0, 0, 0], 1234, 10)]);
        assert_eq!(
            RecordSearcher::new(&addr, NetworkType::Udp)
                .search(&data, addr)
                .unwrap(),
            10
        );
    }

    #[test]
    fn tcp_lookup_includes_connecting_socket() {
        let addr = "192.0.2.1:1234".parse().unwrap();
        let mut data = 1u32.to_ne_bytes().to_vec();
        data.extend((MIB_TCP_STATE_SYN_SENT.0 as u32).to_ne_bytes());
        data.extend([192, 0, 2, 1]);
        data.extend((1234u16.to_be() as u32).to_ne_bytes());
        data.extend([0u8; 8]);
        data.extend(42u32.to_ne_bytes());
        assert_eq!(
            RecordSearcher::new(&addr, NetworkType::Tcp)
                .search(&data, addr)
                .unwrap(),
            42
        );
    }

    #[test]
    fn truncated_table_is_an_error() {
        let addr = "192.0.2.1:1234".parse().unwrap();
        assert!(
            RecordSearcher::new(&addr, NetworkType::Udp)
                .search(&1u32.to_ne_bytes(), addr)
                .is_err()
        );
    }
}
