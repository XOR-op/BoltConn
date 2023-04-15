use crate::adapter::{
    empty_handle, established_tcp, established_udp, lookup, AddrConnector, Connector, OutboundType,
    TcpOutBound, UdpOutBound,
};
use crate::common::async_ws_stream::AsyncWsStream;

use crate::common::{as_io_err, io_err, OutboundTrait};
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::trojan::{
    encapsule_udp_packet, make_tls_config, TrojanAddr, TrojanCmd, TrojanConfig, TrojanReqInner,
    TrojanRequest, TrojanUdpSocket,
};
use crate::transport::UdpSocketAdapter;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::{StatusCode, Uri};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ServerName;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::client_async;

#[derive(Clone)]
pub struct TrojanOutbound {
    iface_name: String,
    dst: NetworkAddr,
    dns: Arc<Dns>,
    config: TrojanConfig,
}

impl TrojanOutbound {
    pub fn new(iface_name: &str, dst: NetworkAddr, dns: Arc<Dns>, config: TrojanConfig) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
            dns,
            config,
        }
    }

    async fn run_tcp<S>(
        self,
        mut inbound: Connector,
        outbound: S,
        abort_handle: ConnAbortHandle,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let mut stream = self.connect_proxy(outbound).await?;
        let first_packet = inbound.rx.recv().await.ok_or_else(|| io_err("No resp"))?;
        if let Some(ref uri) = self.config.websocket_path {
            let mut stream = self
                .with_websocket(stream, uri.as_str())
                .await
                .map_err(|e| io_err(e.to_string().as_str()))?;
            self.first_packet(first_packet, TrojanCmd::Connect, &mut stream)
                .await?;
            established_tcp(inbound, stream, abort_handle).await;
        } else {
            self.first_packet(first_packet, TrojanCmd::Connect, &mut stream)
                .await?;
            established_tcp(inbound, stream, abort_handle).await;
        }
        Ok(())
    }

    async fn run_udp<S>(
        self,
        mut inbound: AddrConnector,
        outbound: S,
        abort_handle: ConnAbortHandle,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let mut stream = self.connect_proxy(outbound).await?;
        let (data, dst) = inbound.rx.recv().await.ok_or_else(|| io_err("No resp"))?;
        let first_packet = Bytes::from(encapsule_udp_packet(data.as_ref(), dst));
        if let Some(ref uri) = self.config.websocket_path {
            let mut stream = self
                .with_websocket(stream, uri.as_str())
                .await
                .map_err(|e| io_err(e.to_string().as_str()))?;
            self.first_packet(first_packet, TrojanCmd::Associate, &mut stream)
                .await?;
            let udp_socket = TrojanUdpSocket::bind(stream);
            let adapter = TrojanUdpAdapter {
                socket: Arc::new(udp_socket),
            };
            established_udp(inbound, adapter, abort_handle).await;
        } else {
            self.first_packet(first_packet, TrojanCmd::Associate, &mut stream)
                .await?;
            let udp_socket = TrojanUdpSocket::bind(stream);
            let adapter = TrojanUdpAdapter {
                socket: Arc::new(udp_socket),
            };
            established_udp(inbound, adapter, abort_handle).await;
        }
        Ok(())
    }

    async fn first_packet<S: AsyncWrite + Unpin>(
        &self,
        first_packet: Bytes,
        cmd: TrojanCmd,
        stream: &mut S,
    ) -> io::Result<()> {
        let trojan_req = TrojanRequest {
            password: self.config.password.clone(),
            request: TrojanReqInner {
                cmd,
                addr: TrojanAddr::from(self.dst.clone()),
            },
            payload: first_packet,
        };
        let res = stream.write_all(trojan_req.serialize().as_slice()).await;
        res?;
        Ok(())
    }

    async fn connect_proxy<S>(&self, outbound: S) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let server_name = ServerName::try_from(self.config.sni.as_str()).map_err(as_io_err)?;
        let tls_conn = TlsConnector::from(make_tls_config(self.config.skip_cert_verify));
        let stream = tls_conn.connect(server_name, outbound).await?;
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
        let self_clone = self.clone();
        tokio::spawn(async move {
            let server_addr =
                lookup(self_clone.dns.as_ref(), &self_clone.config.server_addr).await?;
            let tcp_conn = Egress::new(&self_clone.iface_name)
                .tcp_stream(server_addr)
                .await?;
            self_clone.run_tcp(inbound, tcp_conn, abort_handle).await
        })
    }

    fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn OutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        if tcp_outbound.is_none() || udp_outbound.is_some() {
            tracing::error!("Invalid Trojan UDP outbound ancestor");
            return empty_handle();
        }
        tokio::spawn(
            self.clone()
                .run_tcp(inbound, tcp_outbound.unwrap(), abort_handle),
        )
    }
}

impl UdpOutBound for TrojanOutbound {
    fn outbound_type(&self) -> OutboundType {
        OutboundType::Trojan
    }

    fn spawn_udp(
        &self,
        inbound: AddrConnector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let server_addr =
                lookup(self_clone.dns.as_ref(), &self_clone.config.server_addr).await?;
            let tcp_conn = Egress::new(&self_clone.iface_name)
                .tcp_stream(server_addr)
                .await?;
            self_clone.run_udp(inbound, tcp_conn, abort_handle).await
        })
    }

    fn spawn_udp_with_outbound(
        &self,
        inbound: AddrConnector,
        tcp_outbound: Option<Box<dyn OutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        if tcp_outbound.is_none() || udp_outbound.is_some() {
            tracing::error!("Invalid Trojan UDP outbound ancestor");
            return empty_handle();
        }
        let tcp_outbound = tcp_outbound.unwrap();
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone
                .run_udp(inbound, tcp_outbound, abort_handle)
                .await
        })
    }
}

struct TrojanUdpAdapter<S: AsyncRead + AsyncWrite> {
    socket: Arc<TrojanUdpSocket<S>>,
}

impl<S> Clone for TrojanUdpAdapter<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn clone(&self) -> Self {
        Self {
            socket: self.socket.clone(),
        }
    }
}

#[async_trait]
impl<S> UdpSocketAdapter for TrojanUdpAdapter<S>
where
    S: AsyncRead + AsyncWrite + Send,
{
    async fn send_to(&self, data: &[u8], addr: NetworkAddr) -> anyhow::Result<()> {
        self.socket.send_to(data, addr).await?;
        Ok(())
    }

    async fn recv_from(&self, data: &mut [u8]) -> anyhow::Result<(usize, NetworkAddr)> {
        let (size, addr) = self.socket.recv_from(data).await?;
        Ok((size, addr))
    }
}
