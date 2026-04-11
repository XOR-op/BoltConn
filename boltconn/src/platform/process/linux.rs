use crate::platform::process::{NetworkType, ParentProcess, ProcessInfo, ProcessInfoDepth};
use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload, constants::*};
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
};
use netlink_sys::Socket;
use netlink_sys::protocols::NETLINK_SOCK_DIAG;
use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::{
    fs::DirEntry,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use std::{io::Result, os::unix::prelude::MetadataExt};

fn get_inode_and_uid(addr: SocketAddr, net_type: NetworkType) -> Result<(u32, u32)> {
    // use sock_diag to get inode and uid
    let mut diag_sock = Socket::new(NETLINK_SOCK_DIAG)?;
    diag_sock.bind_auto()?;
    diag_sock.connect(&netlink_sys::SocketAddr::new(0, 0))?;

    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut packet = NetlinkMessage::new(
        header,
        SockDiagMessage::InetRequest(InetRequest {
            family: AF_INET,
            protocol: match net_type {
                NetworkType::Tcp => IPPROTO_TCP,
                NetworkType::Udp => IPPROTO_UDP,
            },
            extensions: ExtensionFlags::empty(),
            states: StateFlags::all(),
            socket_id: SocketId {
                source_port: addr.port(),
                source_address: addr.ip(),
                destination_port: 0,
                destination_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                interface_id: 0,
                cookie: [0xff; 8],
            },
        })
        .into(),
    );
    packet.finalize();
    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf[..]);
    diag_sock.send(&buf[..], 0)?;

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    while let Ok(size) = diag_sock.recv(&mut &mut receive_buffer[..], 0) {
        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();

            match rx_packet.payload {
                NetlinkPayload::Noop | NetlinkPayload::Ack(_) => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    return Ok((response.header.inode, response.header.uid));
                }
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "sock_diag read")),
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "sock_diag read"))
}

fn read_proc(fd: Result<DirEntry>, name: &str) -> Result<bool> {
    let fd = fd?;
    let meta = fd.metadata()?;
    if meta.is_symlink() {
        let link = std::fs::read_link(fd.path())?;
        if link.to_string_lossy() == name {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Walk `/proc` to find the process that owns the given socket inode.
/// When `uid_filter` is `Some(uid)`, only processes with that UID are checked (fast path).
/// When `None`, all processes are checked (needed for cross-namespace lookups where
/// host/container UIDs may differ due to user namespace remapping).
fn find_pid_by_inode(inode: u32, uid_filter: Option<u32>) -> Result<libc::pid_t> {
    let target_name = format!("socket:[{}]", inode);
    for proc in std::fs::read_dir("/proc")?.flatten() {
        if !proc
            .file_name()
            .to_string_lossy()
            .chars()
            .all(char::is_numeric)
        {
            continue;
        }
        if let Ok(meta) = proc.metadata() {
            if let Some(uid) = uid_filter {
                if !(meta.uid() == uid && meta.is_dir()) {
                    continue;
                }
            } else if !meta.is_dir() {
                continue;
            }
            // read fds to search for socket:[]
            let mut fd_path = proc.path();
            fd_path.push("fd");
            if let Ok(internal) = std::fs::read_dir(fd_path) {
                for fd in internal {
                    if let Ok(true) = read_proc(fd, &target_name) {
                        return Ok(proc
                            .file_name()
                            .to_string_lossy()
                            .chars()
                            .as_str()
                            .parse()
                            .unwrap());
                    }
                }
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "process not found"))
}

// --- Namespace-aware fallback via /proc/<pid>/net parsing ---

/// Parse an IPv4 address from `/proc/net/tcp` hex format.
/// The kernel prints the `__be32` value with `%08X`, which on the host produces
/// a value in native byte order.
fn parse_proc_net_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let raw = u32::from_str_radix(hex, 16).ok()?;
    let octets = raw.to_ne_bytes();
    Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

/// Parse an IPv6 address from `/proc/net/tcp6` hex format.
/// The 32 hex chars are 4 groups of 8 hex chars, each group a `__be32` in native byte order.
fn parse_proc_net_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let group = u32::from_str_radix(&hex[i * 8..(i + 1) * 8], 16).ok()?;
        let bytes = group.to_ne_bytes();
        octets[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    Some(Ipv6Addr::from(octets))
}

/// Search `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` for a socket matching the given address.
/// Returns the socket inode if found.
fn search_proc_net(pid: libc::pid_t, addr: SocketAddr, net_type: NetworkType) -> Option<u32> {
    let (proto, is_v6) = match (&addr, &net_type) {
        (SocketAddr::V4(_), NetworkType::Tcp) => ("tcp", false),
        (SocketAddr::V6(_), NetworkType::Tcp) => ("tcp6", true),
        (SocketAddr::V4(_), NetworkType::Udp) => ("udp", false),
        (SocketAddr::V6(_), NetworkType::Udp) => ("udp6", true),
    };
    let path = format!("/proc/{}/net/{}", pid, proto);
    let content = std::fs::read_to_string(&path).ok()?;

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        // fields[1] is "hex_ip:hex_port"
        let (ip_hex, port_hex) = fields[1].rsplit_once(':')?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;

        if port != addr.port() {
            continue;
        }

        let ip_matches = if is_v6 {
            parse_proc_net_ipv6(ip_hex)
                .map(|ip| IpAddr::V6(ip) == addr.ip())
                .unwrap_or(false)
        } else {
            parse_proc_net_ipv4(ip_hex)
                .map(|ip| IpAddr::V4(ip) == addr.ip())
                .unwrap_or(false)
        };

        if ip_matches {
            // fields[9] is the inode
            return fields[9].parse().ok();
        }
    }
    None
}

struct NamespaceCache {
    /// netns inode → one representative PID in that namespace.
    /// Only one PID is needed because `/proc/<pid>/net/tcp` shows the entire
    /// namespace's socket table regardless of which PID we use.
    namespaces: HashMap<u64, libc::pid_t>,
    host_ns_inode: u64,
    last_refresh: Instant,
}

static NS_CACHE: Mutex<Option<NamespaceCache>> = Mutex::new(None);
const NS_CACHE_TTL: Duration = Duration::from_secs(5);

fn get_host_netns_inode() -> Result<u64> {
    Ok(std::fs::metadata("/proc/self/ns/net")?.ino())
}

/// Scan `/proc/*/ns/net` and build a map of non-host network namespace inodes to a
/// representative PID in each namespace.
fn build_ns_map(host_ns_inode: u64) -> HashMap<u64, libc::pid_t> {
    let mut map = HashMap::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(char::is_numeric) {
            continue;
        }
        let Ok(pid) = name_str.parse::<libc::pid_t>() else {
            continue;
        };
        let ns_path = format!("/proc/{}/ns/net", pid);
        if let Ok(meta) = std::fs::metadata(&ns_path) {
            let ns_ino = meta.ino();
            if ns_ino != host_ns_inode {
                map.entry(ns_ino).or_insert(pid);
            }
        }
    }
    map
}

/// Search for a socket in non-host network namespaces by parsing `/proc/<pid>/net/` files.
/// Uses a cached namespace map, refreshing on miss if the cache is stale.
fn find_inode_in_other_namespaces(addr: SocketAddr, net_type: NetworkType) -> Result<u32> {
    let host_ns_inode = get_host_netns_inode()?;
    let mut cache = NS_CACHE.lock().unwrap();
    let now = Instant::now();

    // Build cache if it doesn't exist or host namespace changed
    let just_built = if cache.is_none() || cache.as_ref().unwrap().host_ns_inode != host_ns_inode {
        let namespaces = build_ns_map(host_ns_inode);
        *cache = Some(NamespaceCache {
            namespaces,
            host_ns_inode,
            last_refresh: now,
        });
        true
    } else {
        false
    };

    // Search cached namespaces
    for &leader_pid in cache.as_ref().unwrap().namespaces.values() {
        if let Some(inode) = search_proc_net(leader_pid, addr, net_type) {
            tracing::trace!(pid = leader_pid, "found socket in non-host namespace");
            return Ok(inode);
        }
    }

    // Not found. If cache wasn't just built and is older than TTL, refresh and search again.
    if !just_built && now.duration_since(cache.as_ref().unwrap().last_refresh) >= NS_CACHE_TTL {
        let namespaces = build_ns_map(host_ns_inode);
        *cache = Some(NamespaceCache {
            namespaces,
            host_ns_inode,
            last_refresh: now,
        });
        for &leader_pid in cache.as_ref().unwrap().namespaces.values() {
            if let Some(inode) = search_proc_net(leader_pid, addr, net_type) {
                tracing::trace!(pid = leader_pid, "found socket in non-host namespace");
                return Ok(inode);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "socket not found in any namespace",
    ))
}

pub fn get_pid(addr: SocketAddr, net_type: NetworkType) -> Result<libc::pid_t> {
    // Fast path: host namespace SOCK_DIAG
    if let Ok((inode, uid)) = get_inode_and_uid(addr, net_type)
        && let Ok(pid) = find_pid_by_inode(inode, Some(uid))
    {
        return Ok(pid);
    }
    // Slow path: search other network namespaces via /proc
    let inode = find_inode_in_other_namespaces(addr, net_type)?;
    find_pid_by_inode(inode, None)
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
    })
}

fn get_process_info_inner(pid: i32) -> Option<(i32, String, String, String, String)> {
    let proc_object = procfs::process::Process::new(pid).ok()?;
    let proc_stat = proc_object.stat().ok()?;
    let exe_link = format!("/proc/{}/exe", pid);
    let path = std::fs::read_link(exe_link)
        .ok()?
        .into_os_string()
        .into_string()
        .unwrap();

    let name = std::fs::read(format!("/proc/{}/comm", pid)).ok()?;

    let mut cmdline = std::fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    // replace '\0' to ' '
    cmdline.iter_mut().for_each(|x| {
        if *x == 0u8 {
            *x = b' '
        }
    });
    // recover trailing '\0'
    *cmdline.last_mut().unwrap() = 0;
    let cmdline = String::from_utf8_lossy(cmdline.as_slice())
        .into_owned()
        .trim_matches(char::from(0))
        .to_string();

    let cwd = std::fs::read_link(format!("/proc/{}/cwd", pid))
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_default();

    Some((
        proc_stat.ppid,
        path.replace('\n', ""),
        String::from_utf8_lossy(name.as_slice())
            .into_owned()
            .replace('\n', ""),
        cmdline,
        cwd,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_net_ipv4() {
        // 127.0.0.1 in host byte order on little-endian: 0100007F
        // On big-endian: 7F000001
        // We test with the native representation
        let addr = Ipv4Addr::new(127, 0, 0, 1);
        let raw = u32::from_ne_bytes(addr.octets());
        let hex = format!("{:08X}", raw);
        assert_eq!(parse_proc_net_ipv4(&hex), Some(addr));

        // 0.0.0.0
        let addr = Ipv4Addr::new(0, 0, 0, 0);
        let raw = u32::from_ne_bytes(addr.octets());
        let hex = format!("{:08X}", raw);
        assert_eq!(parse_proc_net_ipv4(&hex), Some(addr));

        // 172.17.0.2 (typical Docker container IP)
        let addr = Ipv4Addr::new(172, 17, 0, 2);
        let raw = u32::from_ne_bytes(addr.octets());
        let hex = format!("{:08X}", raw);
        assert_eq!(parse_proc_net_ipv4(&hex), Some(addr));
    }

    #[test]
    fn test_parse_proc_net_ipv6() {
        // ::1 (loopback)
        let addr = Ipv6Addr::LOCALHOST;
        let octets = addr.octets();
        let mut hex = String::new();
        for i in 0..4 {
            let mut group_bytes = [0u8; 4];
            group_bytes.copy_from_slice(&octets[i * 4..i * 4 + 4]);
            let group = u32::from_ne_bytes(group_bytes);
            hex.push_str(&format!("{:08X}", group));
        }
        assert_eq!(parse_proc_net_ipv6(&hex), Some(addr));

        // Invalid length
        assert_eq!(parse_proc_net_ipv6("0000"), None);
        assert_eq!(parse_proc_net_ipv6(""), None);
    }

    #[test]
    fn test_search_proc_net_line_parsing() {
        // Simulate a /proc/net/tcp line and verify our field extraction logic
        let line = "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert!(fields.len() >= 10);
        assert_eq!(fields[1], "0100007F:0035");
        assert_eq!(fields[9], "12345");

        let (ip_hex, port_hex) = fields[1].rsplit_once(':').unwrap();
        assert_eq!(ip_hex, "0100007F");
        assert_eq!(port_hex, "0035");
        assert_eq!(u16::from_str_radix(port_hex, 16).unwrap(), 53);
    }
}
