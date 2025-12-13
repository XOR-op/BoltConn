use crate::platform::process::{NetworkType, ProcessInfo};
use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload, constants::*};
use netlink_packet_sock_diag::{
    SockDiagMessage,
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
};
use netlink_sys::Socket;
use netlink_sys::protocols::NETLINK_SOCK_DIAG;
use std::io;
use std::{
    fs::DirEntry,
    net::{IpAddr, Ipv4Addr, SocketAddr},
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

pub fn get_pid(addr: SocketAddr, net_type: NetworkType) -> Result<libc::pid_t> {
    let (inode, uid) = get_inode_and_uid(addr, net_type)?;
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
            if !(meta.uid() == uid && meta.is_dir()) {
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
    Err(io::Error::new(io::ErrorKind::NotFound, "sock_diag read"))
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

    Some((
        proc_stat.ppid,
        path.replace('\n', ""),
        String::from_utf8_lossy(name.as_slice())
            .into_owned()
            .replace('\n', ""),
        cmdline,
    ))
}
