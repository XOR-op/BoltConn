use crate::network::bind_to_device;
use crate::outbound::TcpConnection;
use io::Result;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

pub struct DirectOutbound {
    iface_name: String,
    conn: TcpConnection,
}

impl DirectOutbound {
    const BUF_SIZE: usize = 65536;

    pub fn new(
        iface_name: &str,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        available: Arc<AtomicBool>,
    ) -> Self {
        Self {
            iface_name: iface_name.into(),
            conn: TcpConnection::new(src_addr, dst_addr, available),
        }
    }

    pub async fn run(&mut self, inbound: TcpStream) -> Result<()> {
        let inbound_indicator = self.conn.available.clone();
        let outbound = match self.conn.dst {
            SocketAddr::V4(v4) => {
                let socket = TcpSocket::new_v4()?;
                bind_to_device(socket.as_raw_fd(), self.iface_name.as_str())?;
                socket.connect(self.conn.dst).await?
            }
            SocketAddr::V6(v6) => {
                let socket = TcpSocket::new_v6()?;
                bind_to_device(socket.as_raw_fd(), self.iface_name.as_str())?;
                socket.connect(self.conn.dst).await?
            }
        };
        let (mut in_read, mut in_write) = inbound.into_split();
        let (mut out_read, mut out_write) = outbound.into_split();
        // recv from inbound and send to outbound
        tokio::spawn(async move {
            let mut buf = [0u8; Self::BUF_SIZE];
            loop {
                if let Ok(size) = in_read.read(&mut buf).await {
                    if let Err(_) = out_write.write_all(&buf[..size]).await {
                        break;
                    }
                } else {
                    break;
                }
            }
        });
        // recv from outbound and send to inbound
        let mut buf = [0u8; Self::BUF_SIZE];
        loop {
            if let Ok(size) = out_read.read(&mut buf).await {
                if let Err(_) = in_write.write_all(&buf[..size]).await {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(())
    }
}
