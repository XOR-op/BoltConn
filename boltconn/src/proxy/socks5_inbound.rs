use crate::proxy::Dispatcher;
use fast_socks5::util::target_addr::read_address;
use fast_socks5::{consts, read_exact, ReplyError, SocksError};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub struct Socks5Inbound {
    port: u16,
    server: TcpListener,
    auth: Option<(String, String)>,
    dispatcher: Arc<Dispatcher>,
}

impl Socks5Inbound {
    pub async fn new(
        port: u16,
        auth: Option<(String, String)>,
        dispatcher: Arc<Dispatcher>,
    ) -> io::Result<Self> {
        let server =
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)).await?;
        Ok(Self {
            port,
            server,
            auth,
            dispatcher,
        })
    }

    pub async fn run(self) {
        tracing::info!(
            "[Socks5] Listen proxy at 127.0.0.1:{}, running...",
            self.port
        );
        while let Ok((socket, src_addr)) = self.server.accept().await {
            let disp = self.dispatcher.clone();
            let auth = self.auth.clone();
            tokio::spawn(Self::serve_connection(socket, auth, src_addr, disp));
        }
    }

    async fn serve_connection(
        mut socks_stream: TcpStream,
        auth: Option<(String, String)>,
        src_addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
    ) -> anyhow::Result<()> {
        Self::process_auth(&mut socks_stream, auth).await?;
        let [version, cmd, _rsv, address_type] = read_exact!(socks_stream, [0u8; 4])?;

        if version != consts::SOCKS5_VERSION {
            Err(SocksError::UnsupportedSocksVersion(version))?;
        }

        let target_addr = read_address(&mut socks_stream, address_type).await?;

        // perform proxying
        match cmd {
            consts::SOCKS5_CMD_TCP_CONNECT => {
                socks_stream
                    .write_all(&Self::new_reply(
                        &ReplyError::Succeeded,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
                    ))
                    .await?;
                dispatcher
                    .submit_tun_tcp(
                        src_addr,
                        target_addr.into(),
                        Arc::new(AtomicU8::new(2)),
                        socks_stream,
                    )
                    .await;
            }
            consts::SOCKS5_CMD_UDP_ASSOCIATE => {
                let peer_sock =
                    UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
                        .await?;
                let reply_addr = peer_sock.local_addr()?;
                socks_stream
                    .write_all(&Self::new_reply(&ReplyError::Succeeded, reply_addr))
                    .await?;
                let indicator = Arc::new(AtomicBool::new(true));
                let id2 = indicator.clone();
                tokio::spawn(async move {
                    // connected TCP to ensure tunnel alive
                    while id2.load(Ordering::Relaxed) {
                        if socks_stream.writable().await.is_ok() {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        } else {
                            break;
                        }
                    }
                    id2.store(false, Ordering::Relaxed);
                });
                dispatcher
                    .submit_socks_udp_pkt(src_addr, target_addr.into(), indicator, peer_sock)
                    .await;
            }
            _ => Err(ReplyError::CommandNotSupported)?,
        };
        Ok(())
    }

    async fn process_auth(
        socket: &mut TcpStream,
        auth: Option<(String, String)>,
    ) -> Result<(), SocksError> {
        let [version, method_len] = read_exact!(socket, [0u8; 2])?;
        if version != consts::SOCKS5_VERSION {
            return Err(SocksError::UnsupportedSocksVersion(version));
        }
        let methods = read_exact!(socket, vec![0u8; method_len as usize])?;
        let supported = if auth.is_some() {
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
            return Err(SocksError::AuthMethodUnacceptable(methods));
        } else {
            socket
                .write_all(&[consts::SOCKS5_VERSION, supported])
                .await?;
        }
        if let Some((usr, pwd)) = auth {
            let [version, user_len] = read_exact!(socket, [0u8; 2])?;
            if version != consts::SOCKS5_VERSION {
                return Err(SocksError::UnsupportedSocksVersion(version));
            }
            if user_len < 1 {
                return Err(SocksError::AuthenticationFailed(
                    "username.len == 0".to_string(),
                ));
            }
            let username = read_exact!(socket, vec![0u8; user_len as usize])?;

            let [pass_len] = read_exact!(socket, [0u8; 1])?;
            if pass_len < 1 {
                return Err(SocksError::AuthenticationFailed(
                    "password.len == 0".to_string(),
                ));
            }
            let password = read_exact!(socket, vec![0u8; pass_len as usize])?;

            if String::from_utf8(username).map(|u| u == usr) == Ok(true)
                && String::from_utf8(password).map(|p| p == pwd) == Ok(true)
            {
                socket
                    .write_all(&[1, consts::SOCKS5_REPLY_SUCCEEDED])
                    .await?;
            } else {
                socket
                    .write_all(&[1, consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE])
                    .await?;
                return Err(SocksError::AuthenticationRejected(
                    "Authentication mismatched".to_string(),
                ));
            }
        }
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
