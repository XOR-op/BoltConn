use tokio::io::DuplexStream;
use hyper::server::conn::Http;

pub struct SniffMockServer {
    inbound: DuplexStream,

}

impl SniffMockServer {
    pub fn new(server_side: DuplexStream) -> Self {
        Self {
            inbound: server_side
        }
    }

    // pub fn run(self, service: hyper::service) {
        // if let Err(http_err) = Http::new().serve_connection(self.inbound, service) {
        //     tracing::warn!("Sniff err {}",http_err);
        // }
    // }
}
