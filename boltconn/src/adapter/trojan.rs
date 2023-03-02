use crate::adapter::{
    established_tcp, established_udp, lookup, Connector, TcpOutBound, UdpOutBound, UdpSocketAdapter,
};
use crate::common::async_ws_stream::AsyncWsStream;
use crate::common::buf_pool::PktBufPool;
use crate::common::duplex_chan::DuplexChan;
use crate::common::{as_io_err, io_err};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::trojan::{
    make_tls_config, TrojanAddr, TrojanCmd, TrojanConfig, TrojanReqInner, TrojanRequest,
    TrojanUdpSocket,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use http::{StatusCode, Uri};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ServerName;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::client_async;

#[derive(Clone)]
pub struct TrojanOutbound {
    iface_name: String,
    dst: NetworkAddr,
    allocator: PktBufPool,
    dns: Arc<Dns>,
    config: TrojanConfig,
}

impl TrojanOutbound {
    pub fn new(
        iface_name: &str,
        dst: NetworkAddr,
        allocator: PktBufPool,
        dns: Arc<Dns>,
        config: TrojanConfig,
    ) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
            allocator,
            dns,
            config,
        }
    }

    async fn run_tcp(
        self,
        mut inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> io::Result<()> {
        let mut stream = self.connect_proxy().await?;
        if let Some(ref uri) = self.config.websocket_path {
            let mut stream = self
                .with_websocket(stream, uri.as_str())
                .await
                .map_err(|e| io_err(e.to_string().as_str()))?;
            self.first_packet(&mut inbound, &mut stream).await?;
            established_tcp(inbound, stream, self.allocator, abort_handle).await;
        } else {
            self.first_packet(&mut inbound, &mut stream).await?;
            established_tcp(inbound, stream, self.allocator, abort_handle).await;
        }
        Ok(())
    }

    async fn run_udp(
        self,
        mut inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> io::Result<()> {
        let mut stream = self.connect_proxy().await?;
        if let Some(ref uri) = self.config.websocket_path {
            let mut stream = self
                .with_websocket(stream, uri.as_str())
                .await
                .map_err(|e| io_err(e.to_string().as_str()))?;
            self.first_packet(&mut inbound, &mut stream).await?;
            let udp_socket = TrojanUdpSocket::bind(stream);
            let adapter = TrojanUdpAdapter {
                socket: Arc::new(udp_socket),
                dest: self.dst,
            };
            established_udp(inbound, adapter, self.allocator, abort_handle).await;
        } else {
            self.first_packet(&mut inbound, &mut stream).await?;
            let udp_socket = TrojanUdpSocket::bind(stream);
            let adapter = TrojanUdpAdapter {
                socket: Arc::new(udp_socket),
                dest: self.dst,
            };
            established_udp(inbound, adapter, self.allocator, abort_handle).await;
        }
        Ok(())
    }

    async fn first_packet<S: AsyncWrite + Unpin>(
        &self,
        inbound: &mut Connector,
        stream: &mut S,
    ) -> io::Result<()> {
        let first_packet = inbound.rx.recv().await.ok_or_else(|| io_err("No resp"))?;
        let trojan_req = TrojanRequest {
            password: self.config.password.clone(),
            request: TrojanReqInner {
                cmd: TrojanCmd::Connect,
                addr: TrojanAddr::from(self.dst.clone()),
            },
            payload: first_packet,
        };
        let res = stream.write_all(trojan_req.serialize().as_slice()).await;
        self.allocator.release(trojan_req.payload);
        res?;
        Ok(())
    }

    async fn connect_proxy(&self) -> io::Result<TlsStream<TcpStream>> {
        let server_addr = lookup(self.dns.as_ref(), &self.config.server_addr).await?;
        let server_name = ServerName::try_from(self.config.sni.as_str()).map_err(as_io_err)?;
        let tcp_conn = Egress::new(&self.iface_name)
            .tcp_stream(server_addr)
            .await?;
        let tls_conn = TlsConnector::from(make_tls_config(self.config.skip_cert_verify));
        let stream = tls_conn.connect(server_name, tcp_conn).await?;
        Ok(stream)
    }

    async fn with_websocket<S: AsyncRead + AsyncWrite + Unpin + Send + Sync>(
        &self,
        stream: S,
        path: &str,
    ) -> Result<AsyncWsStream<S>> {
        let uri = Uri::builder()
            .scheme("wss")
            .authority(self.config.sni.as_str())
            .path_and_query(path)
            .build()?;
        let (stream, resp) = client_async(uri, stream).await?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(anyhow!("Bad status:{}", resp.status()));
        }
        Ok(AsyncWsStream::new(stream))
    }
}

impl TcpOutBound for TrojanOutbound {
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().run_tcp(inbound, abort_handle))
    }

    fn spawn_tcp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<io::Result<()>>) {
        let (inner, outer) = Connector::new_pair(10);
        (
            DuplexChan::new(self.allocator.clone(), inner),
            tokio::spawn(self.clone().run_tcp(outer, abort_handle)),
        )
    }
}

impl UdpOutBound for TrojanOutbound {
    fn spawn_udp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(self.clone().run_udp(inbound, abort_handle))
    }

    fn spawn_udp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<io::Result<()>>) {
        let (inner, outer) = Connector::new_pair(10);
        (
            DuplexChan::new(self.allocator.clone(), inner),
            tokio::spawn(self.clone().run_udp(outer, abort_handle)),
        )
    }
}

struct TrojanUdpAdapter<S: AsyncRead + AsyncWrite> {
    socket: Arc<TrojanUdpSocket<S>>,
    dest: NetworkAddr,
}

impl<S> Clone for TrojanUdpAdapter<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn clone(&self) -> Self {
        Self {
            socket: self.socket.clone(),
            dest: self.dest.clone(),
        }
    }
}

impl<S> TrojanUdpAdapter<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn test(&self) -> TrojanUdpAdapter<S> {
        self.clone()
    }
}

#[async_trait]
impl<S> UdpSocketAdapter for TrojanUdpAdapter<S>
where
    S: AsyncRead + AsyncWrite + Send,
{
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.socket.send_to(data, self.dest.clone()).await?;
        Ok(())
    }

    async fn recv(&self, data: &mut [u8]) -> Result<(usize, bool)> {
        let (size, addr) = self.socket.recv_from(data).await?;
        Ok((size, addr == self.dest))
    }
}
