use crate::adapter::OutBound;
use crate::common::duplex_chan::DuplexChan;
use crate::sniff::modifier::{Logger, Modifier, Nooper};
use hyper::client::conn;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::io;
use std::sync::Arc;

pub struct HttpSniffer {
    inbound: DuplexChan,
    modifier: Arc<dyn Modifier>,
    creator: Box<dyn OutBound>,
}

impl HttpSniffer {
    pub fn new(inbound: DuplexChan, creator: Box<dyn OutBound>) -> Self {
        Self {
            inbound,
            modifier: Arc::new(Nooper::default()),
            creator,
        }
    }

    async fn proxy(
        outbound: DuplexChan,
        modifier: Arc<dyn Modifier>,
        mut req: Request<Body>,
    ) -> hyper::Result<Response<Body>> {
        let (mut sender, connection) = conn::Builder::new().handshake(outbound).await?;
        modifier.modify_request(&mut req);
        tokio::spawn(async move { connection.await });
        let mut resp = sender.send_request(req).await?;
        modifier.modify_response(&mut resp);
        Ok(resp)
    }

    pub async fn run(self) -> io::Result<()> {
        let service = service_fn(|req| {
            let (conn, _) = self.creator.spawn_with_chan();
            Self::proxy(conn, self.modifier.clone(), req)
        });
        if let Err(http_err) = Http::new().serve_connection(self.inbound, service).await {
            tracing::warn!("Sniff err {}", http_err);
        }
        Ok(())
    }
}
