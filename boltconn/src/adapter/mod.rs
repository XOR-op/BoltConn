use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

mod direct;
mod socks5;
mod tun_adapter;

use crate::common::buf_pool::{PktBufHandle, PktBufPool};
use crate::common::duplex_chan::DuplexChan;
use crate::session::NetworkAddr;
pub use direct::*;
pub use socks5::*;
pub use tun_adapter::*;

pub struct TcpStatus {
    src: SocketAddr,
    dst: NetworkAddr,
    available: Arc<AtomicU8>,
}

impl TcpStatus {
    pub fn new(src: SocketAddr, dst: NetworkAddr, available: Arc<AtomicU8>) -> Self {
        Self {
            src,
            dst,
            available,
        }
    }
}

pub struct Connector {
    pub tx: mpsc::Sender<PktBufHandle>,
    pub rx: mpsc::Receiver<PktBufHandle>,
}

impl Connector {
    pub fn new(tx: mpsc::Sender<PktBufHandle>, rx: mpsc::Receiver<PktBufHandle>) -> Self {
        Self { tx, rx }
    }

    pub fn new_pair(size: usize) -> (Self, Self) {
        let (utx, urx) = mpsc::channel(size);
        let (dtx, drx) = mpsc::channel(size);
        (Connector::new(utx, drx), Connector::new(dtx, urx))
    }
}

pub enum OutboundType {
    Direct,
    Socks5,
    Http,
    Wireguard,
    Openvpn,
    Shadowsocks,
    Trojan,
}

pub trait OutBound: Send + Sync {
    /// Run with tokio::spawn.
    fn spawn(&self, inbound: Connector) -> JoinHandle<io::Result<()>>;

    /// Run with tokio::spawn, returning handle and a duplex channel
    fn spawn_with_chan(&self) -> (DuplexChan, JoinHandle<io::Result<()>>);
}

async fn established_tcp<T>(inbound: Connector, outbound: T, allocator: PktBufPool)
where
    T: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
    let (mut out_read, mut out_write) = tokio::io::split(outbound);
    let allocator2 = allocator.clone();
    let Connector { tx, mut rx } = inbound;
    // recv from inbound and send to outbound
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(buf) => {
                    if let Err(err) = out_write.write_all(buf.as_ready()).await {
                        tracing::warn!("write to outbound failed: {}", err);
                        allocator2.release(buf);
                        break;
                    } else {
                        allocator2.release(buf);
                    }
                }
                None => {
                    break;
                }
            }
        }
    });
    // recv from outbound and send to inbound
    loop {
        let mut buf = allocator.obtain().await;
        match buf.read(&mut out_read).await {
            Ok(0) => {
                break;
            }
            Ok(_) => {
                if let Err(err) = tx.send(buf).await {
                    tracing::warn!("write to inbound failed: {}", err);
                    break;
                }
            }
            Err(err) => {
                tracing::warn!("[Direct] encounter error: {}", err);
                break;
            }
        }
    }
}
