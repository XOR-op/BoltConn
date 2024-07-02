use crate::proxy::error::TransportError;
use crate::proxy::NetworkAddr;
use crate::transport::UdpSocketAdapter;
use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{tcp, TcpStream};
use tokio::sync::Mutex;

pub(super) struct UdpOverTcpAdapter {
    reader: Mutex<tcp::OwnedReadHalf>,
    writer: Mutex<tcp::OwnedWriteHalf>,
    address: SocketAddr,
}

impl UdpOverTcpAdapter {
    pub fn new(stream: TcpStream, address: SocketAddr) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let (read_half, write_half) = stream.into_split();
        Ok(Self {
            reader: Mutex::new(read_half),
            writer: Mutex::new(write_half),
            address,
        })
    }
}

#[async_trait]
impl UdpSocketAdapter for UdpOverTcpAdapter {
    async fn send_to(&self, data: &[u8], _addr: NetworkAddr) -> Result<(), TransportError> {
        let len = u16::try_from(data.len())
            .map_err(|_| TransportError::Internal("UDP-over-TCP exceeded u16::size"))?
            .to_be_bytes();
        let mut socket = self.writer.lock().await;
        socket.write_all(&len).await?;
        socket.write_all(data).await?;
        Ok(())
    }

    async fn recv_from(&self, data: &mut [u8]) -> Result<(usize, NetworkAddr), TransportError> {
        let mut socket = self.reader.lock().await;
        let mut len_buf = [0u8; 2];
        socket.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if data.len() < len {
            return Err(TransportError::Internal("UDP-over-TCP buffer too small"));
        }
        socket.read_exact(&mut data[0..len]).await?;
        Ok((len, NetworkAddr::Raw(self.address)))
    }
}
