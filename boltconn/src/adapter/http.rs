use crate::adapter::{established_tcp, lookup, Connector, TcpOutBound};
use crate::common::buf_pool::PktBufPool;
use crate::common::duplex_chan::DuplexChan;
use crate::common::io_err;
use crate::network::dns::Dns;
use crate::network::egress::Egress;
use crate::proxy::{ConnAbortHandle, NetworkAddr};
use base64::Engine;
use httparse::Response;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub(crate) server_addr: NetworkAddr,
    pub(crate) auth: Option<(String, String)>,
}

#[derive(Clone)]
pub struct HttpOutbound {
    iface_name: String,
    dst: NetworkAddr,
    allocator: PktBufPool,
    dns: Arc<Dns>,
    config: HttpConfig,
}

impl HttpOutbound {
    pub fn new(
        iface_name: &str,
        dst: NetworkAddr,
        allocator: PktBufPool,
        dns: Arc<Dns>,
        config: HttpConfig,
    ) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            dst,
            allocator,
            dns,
            config,
        }
    }

    async fn run_tcp(self, inbound: Connector, abort_handle: ConnAbortHandle) -> io::Result<()> {
        let server_addr = lookup(self.dns.as_ref(), &self.config.server_addr).await?;
        let mut tcp_stream = Egress::new(&self.iface_name)
            .tcp_stream(server_addr)
            .await?;
        // construct request
        let mut req = format!(
            "CONNECT {0} HTTP/1.1\r\n\
            Host: {0}\r\n\
            Proxy-Connection: Keep-Alive\r\n",
            self.dst
        );
        if let Some((user, pswd)) = self.config.auth {
            let b64encoder = base64::engine::general_purpose::STANDARD;
            let encoded = b64encoder.encode(format!("{user}:{pswd}"));
            req += format!("Proxy-Authorization: basic {encoded}\r\n").as_str();
        }
        req += "\r\n";

        tcp_stream.write_all(req.as_bytes()).await?;
        tcp_stream.flush().await?;

        // get response
        let mut buf_reader = BufReader::new(tcp_stream);
        let mut resp = String::new();
        while !resp.ends_with("\r\n\r\n") {
            if buf_reader.read_line(&mut resp).await? == 0 {
                return Err(io_err("EOF"));
            }
            if resp.len() > 4096 {
                return Err(io_err("Too long resp"));
            }
        }
        let mut buf = [httparse::EMPTY_HEADER; 16];
        let mut resp_struct = Response::new(buf.as_mut());
        resp_struct
            .parse(resp.as_bytes())
            .map_err(|_| io_err("Parse response failed"))?;
        if let Some(200) = resp_struct.code {
            let tcp_stream = buf_reader.into_inner();
            established_tcp(inbound, tcp_stream, self.allocator, abort_handle).await;
            Ok(())
        } else {
            Err(io_err(
                format!("Http Connect Failed: {:?}", resp_struct.code).as_str(),
            ))
        }
    }
}

impl TcpOutBound for HttpOutbound {
    fn spawn_tcp(
        &self,
        inbound: Connector,
        abort_handle: ConnAbortHandle,
    ) -> JoinHandle<io::Result<()>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone
                .run_tcp(inbound, abort_handle)
                .await
                .map_err(|e| io_err(e.to_string().as_str()))
        })
    }

    fn spawn_tcp_with_chan(
        &self,
        abort_handle: ConnAbortHandle,
    ) -> (DuplexChan, JoinHandle<io::Result<()>>) {
        let (inner, outer) = Connector::new_pair(10);
        let self_clone = self.clone();
        (
            DuplexChan::new(self.allocator.clone(), inner),
            tokio::spawn(async move {
                self_clone
                    .run_tcp(outer, abort_handle)
                    .await
                    .map_err(|e| io_err(e.to_string().as_str()))
            }),
        )
    }
}
