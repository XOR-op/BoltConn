use crate::dispatch::{InboundExtra, InboundInfo, InboundManager};
use crate::network::dns::Dns;
use crate::proxy::error::TransportError;
use crate::proxy::{Dispatcher, NetworkAddr};
use fast_socks5::util::target_addr::{TargetAddr, read_address};
use fast_socks5::{ReplyError, SocksError, consts, read_exact};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use super::{SessionManager, SocksUdpInbound};

pub struct Socks5Inbound {
    sock_addr: SocketAddr,
    server: TcpListener,
    inbound_mgr: Arc<InboundManager>,
    dispatcher: Arc<Dispatcher>,
    session_mgr: Arc<SessionManager>,
    dns: Arc<Dns>,
}

impl Socks5Inbound {
    pub async fn new(
        sock_addr: SocketAddr,
        inbound_mgr: InboundManager,
        dispatcher: Arc<Dispatcher>,
        session_mgr: Arc<SessionManager>,
        dns: Arc<Dns>,
    ) -> io::Result<Self> {
        let server = TcpListener::bind(sock_addr).await?;
        Ok(Self {
            sock_addr,
            server,
            inbound_mgr: Arc::new(inbound_mgr),
            dispatcher,
            session_mgr,
            dns,
        })
    }

    pub async fn run(self) {
        tracing::info!("[Socks5] Listen proxy at {}, running...", self.sock_addr);
        loop {
            match self.server.accept().await {
                Ok((socket, src_addr)) => {
                    let disp = self.dispatcher.clone();
                    let inbound_mgr = self.inbound_mgr.clone();
                    let session_mgr = self.session_mgr.clone();
                    let dns = self.dns.clone();
                    tokio::spawn(Self::serve_connection(
                        socket,
                        inbound_mgr,
                        src_addr,
                        disp,
                        session_mgr,
                        dns,
                    ));
                }
                Err(err) => {
                    tracing::error!("Socks5 inbound failed to accept: {}", err);
                    return;
                }
            }
        }
    }

    pub(super) async fn serve_connection(
        mut socks_stream: TcpStream,
        inbound_mgr: Arc<InboundManager>,
        src_addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
        session_mgr: Arc<SessionManager>,
        dns: Arc<Dns>,
    ) -> Result<(), TransportError> {
        let inbound_extra = Self::process_auth(&mut socks_stream, &inbound_mgr).await?;
        let [version, cmd, _rsv, address_type] = read_exact!(socks_stream, [0u8; 4])?;

        if version != consts::SOCKS5_VERSION {
            Err(SocksError::UnsupportedSocksVersion(version))?;
        }

        let target_addr = match read_address(&mut socks_stream, address_type)
            .await
            .map_err(|_| TransportError::Socks5Extra("Read connect address failed"))?
        {
            TargetAddr::Ip(sa) => NetworkAddr::Raw(sa),
            TargetAddr::Domain(domain_name, port) => {
                // Many clients will say they send domain name even if they actually send IP address.
                // We ignore their flags and parse it manually anyway.
                match IpAddr::from_str(&domain_name) {
                    Ok(ip) => NetworkAddr::Raw(SocketAddr::new(ip, port)),
                    Err(_) => NetworkAddr::DomainName { domain_name, port },
                }
            }
        };

        // perform proxying
        match cmd {
            consts::SOCKS5_CMD_TCP_CONNECT => {
                socks_stream
                    .write_all(&Self::new_reply(
                        &ReplyError::Succeeded,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
                    ))
                    .await?;
                let _ = dispatcher
                    .submit_tcp(
                        InboundInfo::Socks5(inbound_extra),
                        src_addr,
                        target_addr,
                        Arc::new(AtomicU8::new(2)),
                        socks_stream,
                    )
                    .await;
            }
            consts::SOCKS5_CMD_UDP_ASSOCIATE => {
                let stream_local_addr = socks_stream.local_addr()?;
                let peer_sock = UdpSocket::bind(SocketAddr::new(stream_local_addr.ip(), 0)).await?;
                let reply_addr = peer_sock.local_addr()?;
                socks_stream
                    .write_all(&Self::new_reply(&ReplyError::Succeeded, reply_addr))
                    .await?;
                let indicator = Arc::new(AtomicBool::new(true));
                let id2 = indicator.clone();
                tokio::spawn(async move {
                    // connected TCP to ensure tunnel alive
                    let mut b = [0u8; 1];
                    while id2.load(Ordering::Relaxed) {
                        if let Ok(n) = socks_stream.try_read(&mut b) {
                            if n == 0 {
                                break;
                            }
                        } else {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                    }
                    id2.store(false, Ordering::Relaxed);
                });
                let outbound = SocksUdpInbound::new(
                    Arc::new(peer_sock),
                    src_addr,
                    inbound_extra,
                    dispatcher,
                    session_mgr,
                    dns,
                    indicator,
                );
                tokio::spawn(async move { outbound.run().await });
            }
            _ => Err(TransportError::Socks5(SocksError::ReplyError(
                ReplyError::CommandNotSupported,
            )))?,
        };
        Ok(())
    }

    async fn process_auth(
        socket: &mut TcpStream,
        mgr: &InboundManager,
    ) -> Result<InboundExtra, TransportError> {
        let [version, method_len] = read_exact!(socket, [0u8; 2])?;
        if version != consts::SOCKS5_VERSION {
            Err(SocksError::UnsupportedSocksVersion(version))?;
        }
        let methods = read_exact!(socket, vec![0u8; method_len as usize])?;
        let supported = if mgr.has_auth() {
            consts::SOCKS5_AUTH_METHOD_PASSWORD
        } else {
            consts::SOCKS5_AUTH_METHOD_NONE
        };
        // parse methods
        if !methods.contains(&supported) {
            socket
                .write_all(&[
                    consts::SOCKS5_VERSION,
                    consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE,
                ])
                .await?;
            Err(SocksError::AuthMethodUnacceptable(methods))?;
        } else {
            socket
                .write_all(&[consts::SOCKS5_VERSION, supported])
                .await?;
        }
        if !mgr.has_auth() {
            Ok(mgr.default_extra())
        } else {
            let [version, user_len] = read_exact!(socket, [0u8; 2])?;
            if version != 0x01 {
                Self::response_auth_error(socket).await?;
                Err(SocksError::UnsupportedSocksVersion(version))?;
            }
            if user_len < 1 {
                Self::response_auth_error(socket).await?;
                Err(SocksError::AuthenticationFailed(
                    "username.len == 0".to_string(),
                ))?;
            }
            let username = read_exact!(socket, vec![0u8; user_len as usize])?;

            let [pass_len] = read_exact!(socket, [0u8; 1])?;
            if pass_len < 1 {
                Self::response_auth_error(socket).await?;
                Err(SocksError::AuthenticationFailed(
                    "password.len == 0".to_string(),
                ))?;
            }
            let password = read_exact!(socket, vec![0u8; pass_len as usize])?;

            let parsed_usr = String::from_utf8(username)
                .map_err(|_| TransportError::Socks5Extra("not UTF-8 encoded username"))?;
            let parsed_pwd = String::from_utf8(password)
                .map_err(|_| TransportError::Socks5Extra("not UTF-8 encoded password"))?;
            if let Some(extra) = mgr.authenticate(&parsed_usr, &parsed_pwd) {
                socket
                    .write_all(&[1, consts::SOCKS5_REPLY_SUCCEEDED])
                    .await?;
                Ok(extra)
            } else {
                Self::response_auth_error(socket).await?;
                Err(SocksError::AuthenticationRejected(
                    "Authentication mismatched".to_string(),
                ))?
            }
        }
    }

    async fn response_auth_error(socket: &mut TcpStream) -> Result<(), TransportError> {
        socket
            .write_all(&[1, consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE])
            .await?;
        Ok(())
    }

    fn new_reply(error: &ReplyError, sock_addr: SocketAddr) -> Vec<u8> {
        let (addr_type, mut ip_oct, mut port) = match sock_addr {
            SocketAddr::V4(sock) => (
                consts::SOCKS5_ADDR_TYPE_IPV4,
                sock.ip().octets().to_vec(),
                sock.port().to_be_bytes().to_vec(),
            ),
            SocketAddr::V6(sock) => (
                consts::SOCKS5_ADDR_TYPE_IPV6,
                sock.ip().octets().to_vec(),
                sock.port().to_be_bytes().to_vec(),
            ),
        };

        let mut reply = vec![
            consts::SOCKS5_VERSION,
            error.as_u8(), // transform the error into byte code
            0x00,          // reserved
            addr_type,     // address type (ipv4, v6, domain)
        ];
        reply.append(&mut ip_oct);
        reply.append(&mut port);

        reply
    }
}
