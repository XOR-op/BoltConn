use crate::adapter::{
    empty_handle, established_tcp, lookup, AddrConnector, Connector, Outbound, OutboundType,
};

use crate::common::{io_err, StreamOutboundTrait};
use crate::config::AuthData;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::error::TransportError;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use crate::transport::UdpSocketAdapter;
use async_trait::async_trait;
use base64::Engine;
use httparse::Response;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub(crate) server_addr: NetworkAddr,
    pub(crate) auth: Option<AuthData>,
}

#[derive(Clone)]
pub struct HttpOutbound {
    name: String,
    iface_name: String,
    dst: NetworkAddr,
    dns: Arc<Dns>,
    config: HttpConfig,
}

impl HttpOutbound {
    pub fn new(
        name: &str,
        iface_name: &str,
        dst: NetworkAddr,
        dns: Arc<Dns>,
        config: HttpConfig,
    ) -> Self {
        Self {
            name: name.to_string(),
            iface_name: iface_name.to_string(),
            dst,
            dns,
            config,
        }
    }

    async fn run_tcp<S>(
        self,
        inbound: Connector,
        mut outbound: S,
        abort_handle: ConnAbortHandle,
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // construct request
        let mut req = format!(
            "CONNECT {0} HTTP/1.1\r\n\
            Host: {0}\r\n\
            Proxy-Connection: Keep-Alive\r\n",
            self.dst
        );
        if let Some(auth) = self.config.auth {
            let b64encoder = base64::engine::general_purpose::STANDARD;
            let encoded = b64encoder.encode(format!("{}:{}", auth.username, auth.password));
            req += format!("Proxy-Authorization: basic {encoded}\r\n").as_str();
        }
        req += "\r\n";

        outbound.write_all(req.as_bytes()).await?;
        outbound.flush().await?;

        // get response
        let mut buf_reader = BufReader::new(outbound);
        let mut resp = String::new();
        while !resp.ends_with("\r\n\r\n") {
            if buf_reader.read_line(&mut resp).await? == 0 {
                return Err(TransportError::Http("EOF"));
            }
            if resp.len() > 4096 {
                return Err(TransportError::Http("Response too long"));
            }
        }
        let mut buf = [httparse::EMPTY_HEADER; 16];
        let mut resp_struct = Response::new(buf.as_mut());
        resp_struct
            .parse(resp.as_bytes())
            .map_err(|_| TransportError::Http("Parsing failed"))?;
        if let Some(200) = resp_struct.code {
            let tcp_stream = buf_reader.into_inner();
            established_tcp(self.name, inbound, tcp_stream, abort_handle).await;
            Ok(())
        } else {
            Err(TransportError::Io(io_err(
                format!("Http Connect Failed: {:?}", resp_struct.code).as_str(),
            )))
        }
    }
}

#[async_trait]
impl Outbound for HttpOutbound {
    fn id(&self) -> String {
        self.name.clone()
    }

    fn outbound_type(&self) -> OutboundType {
        OutboundType::Http
    }

    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<Result<(), TransportError>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let server_addr =
                lookup(self_clone.dns.as_ref(), &self_clone.config.server_addr).await?;
            let tcp_stream = Egress::new(&self_clone.iface_name)
                .tcp_stream(server_addr)
                .await?;
            self_clone.run_tcp(inbound, tcp_stream, abort_handle).await
        })
    }

    async fn spawn_tcp_with_outbound(
        &self,
        inbound: Connector,
        tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        abort_handle: ConnAbortHandle,
    ) -> Result<bool, TransportError> {
        if tcp_outbound.is_none() || udp_outbound.is_some() {
            tracing::error!("Invalid HTTP proxy tcp spawn");
            return Err(TransportError::Internal("Invalid outbound"));
        }
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone
                .run_tcp(inbound, tcp_outbound.unwrap(), abort_handle)
                .await
                .map_err(|e| io_err(e.to_string().as_str()))
        });
        Ok(true)
    }

    fn spawn_udp(
        &self,
        _inbound: AddrConnector,
        _abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> JoinHandle<Result<(), TransportError>> {
        tracing::error!("spawn_udp() should not be called with HttpOutbound");
        empty_handle()
    }

    async fn spawn_udp_with_outbound(
        &self,
        _inbound: AddrConnector,
        _tcp_outbound: Option<Box<dyn StreamOutboundTrait>>,
        _udp_outbound: Option<Box<dyn UdpSocketAdapter>>,
        _abort_handle: ConnAbortHandle,
        _tunnel_only: bool,
    ) -> Result<bool, TransportError> {
        tracing::error!("spawn_udp_with_outbound() should not be called with HttpOutbound");
        Err(TransportError::Internal("Invalid outbound"))
    }
}
