use crate::common::duplex_chan::DuplexChan;
use crate::common::io_err;
use crate::sniff::modifier::{Logger, Modifier};
use hyper::client::conn;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore, ServerConfig,
    ServerName,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct HttpsSniffer<F>
where
    F: Fn() -> DuplexChan + 'static,
{
    cert: Vec<Certificate>,
    priv_key: PrivateKey,
    server_name: String,
    inbound: DuplexChan,
    modifier: Arc<dyn Modifier>,
    creator: F,
}

impl<F> HttpsSniffer<F>
where
    F: Fn() -> DuplexChan + 'static,
{
    pub fn new(
        cert: Vec<Certificate>,
        priv_key: PrivateKey,
        server_name: String,
        inbound: DuplexChan,
        creator: F,
    ) -> Self {
        Self {
            cert,
            priv_key,
            server_name,
            inbound,
            modifier: Arc::new(Logger::default()),
            creator,
        }
    }

    async fn proxy<T>(
        client_tls: TlsConnector,
        server_name: ServerName,
        outbound: T,
        modifier: Arc<dyn Modifier>,
        mut req: Request<Body>,
    ) -> io::Result<Response<Body>>
    where
        T: AsyncRead + AsyncWrite + 'static + Send + Unpin,
    {
        let outbound = client_tls.connect(server_name, outbound).await?;
        let (mut sender, connection) = conn::Builder::new()
            .handshake(outbound)
            .await
            .map_err(|e| io_err(e.to_string().as_str()))?;
        modifier.modify_request(&mut req);
        tokio::spawn(async move { connection.await });
        let mut resp = sender
            .send_request(req)
            .await
            .map_err(|e| io_err(e.to_string().as_str()))?;
        modifier.modify_response(&mut resp);
        Ok(resp)
    }

    pub async fn run(self) -> io::Result<()> {
        // tls server
        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(self.cert, self.priv_key)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // tls client
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
            |ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            },
        ));
        let client_cfg = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        let client_tls = TlsConnector::from(Arc::new(client_cfg));
        let server_name = ServerName::try_from(self.server_name.as_str())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        let service = service_fn(|req| {
            let conn = (self.creator)();
            Self::proxy(
                client_tls.clone(),
                server_name.clone(),
                conn,
                self.modifier.clone(),
                req,
            )
        });

        // start running
        let mut inbound = acceptor.accept(self.inbound).await?;
        if let Err(http_err) = Http::new().serve_connection(inbound, service).await {
            tracing::warn!("Sniff err {}", http_err);
        }
        Ok(())
    }
}
