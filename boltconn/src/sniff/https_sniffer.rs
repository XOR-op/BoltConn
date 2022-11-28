use crate::adapter::OutBound;
use crate::common::duplex_chan::DuplexChan;
use crate::common::id_gen::IdGenerator;
use crate::common::io_err;
use crate::proxy::StatisticsInfo;
use crate::sniff::modifier::{Logger, Modifier, Nooper};
use crate::sniff::ModifierContext;
use hyper::client::conn;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::io;
use std::sync::{Arc, RwLock};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore, ServerConfig,
    ServerName,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct HttpsSniffer {
    cert: Vec<Certificate>,
    priv_key: PrivateKey,
    server_name: String,
    inbound: DuplexChan,
    modifier: Arc<dyn Modifier>,
    creator: Box<dyn OutBound>,
    conn_info: Arc<RwLock<StatisticsInfo>>,
}

impl HttpsSniffer {
    pub fn new(
        cert: Vec<Certificate>,
        priv_key: PrivateKey,
        server_name: String,
        inbound: DuplexChan,
        modifier: Arc<dyn Modifier>,
        creator: Box<dyn OutBound>,
        conn_info: Arc<RwLock<StatisticsInfo>>,
    ) -> Self {
        Self {
            cert,
            priv_key,
            server_name,
            inbound,
            modifier,
            creator,
            conn_info,
        }
    }

    async fn proxy(
        client_tls: TlsConnector,
        server_name: ServerName,
        outbound: DuplexChan,
        modifier: Arc<dyn Modifier>,
        req: Request<Body>,
        ctx: ModifierContext,
    ) -> anyhow::Result<Response<Body>> {
        let req = modifier.modify_request(req, &ctx).await?;
        let outbound = client_tls.connect(server_name, outbound).await?;
        let (mut sender, connection) = conn::Builder::new().handshake(outbound).await?;
        tokio::spawn(async move { connection.await });
        let mut resp = sender.send_request(req).await?;
        let resp = modifier.modify_response(resp, &ctx).await?;
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
        let id_gen = IdGenerator::default();
        let service = service_fn(|req| {
            let (conn, _) = self.creator.spawn_with_chan();
            Self::proxy(
                client_tls.clone(),
                server_name.clone(),
                conn,
                self.modifier.clone(),
                req,
                ModifierContext {
                    tag: id_gen.get(),
                    conn_info: self.conn_info.clone(),
                },
            )
        });

        // start running
        let inbound = acceptor.accept(self.inbound).await?;
        if let Err(http_err) = Http::new().serve_connection(inbound, service).await {
            tracing::warn!("Sniff err {}", http_err);
        }
        Ok(())
    }
}
