use crate::common::duplex_chan::DuplexChan;
use hyper::client::conn;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct HttpMocker<F>
where
    F: Fn() -> DuplexChan + 'static,
{
    inbound: DuplexChan,
    creator: F,
}

impl<F> HttpMocker<F>
where
    F: Fn() -> DuplexChan + 'static,
{
    pub fn new(inbound: DuplexChan, creator: F) -> Self {
        Self { inbound, creator }
    }

    async fn proxy(outbound: DuplexChan, req: Request<Body>) -> hyper::Result<Response<Body>> {
        println!("{:?}", req);
        let (mut sender, connection) = conn::Builder::new().handshake(outbound).await?;
        tokio::spawn(async move { connection.await });
        let resp = sender.send_request(req).await?;
        println!("{:?}", resp);
        Ok(resp)
    }

    pub async fn run(self) -> io::Result<()> {
        let service = service_fn(|req| {
            let conn = (self.creator)();
            Self::proxy(conn, req)
        });
        if let Err(http_err) = Http::new().serve_connection(self.inbound, service).await {
            tracing::warn!("Sniff err {}", http_err);
        }
        Ok(())
    }
}
