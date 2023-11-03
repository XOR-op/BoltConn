use crate::adapter::{Connector, Outbound};
use crate::common::create_tls_connector;
use crate::common::duplex_chan::DuplexChan;
use crate::common::id_gen::IdGenerator;
use crate::intercept::modifier::Modifier;
use crate::intercept::{sign_site_cert, ModifierContext};
use crate::proxy::{ConnAbortHandle, ConnContext};
use hyper::client::conn;
use hyper::client::conn::SendRequest;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use rcgen::Certificate as CaCertificate;
use std::io;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct HttpsIntercept {
    cert: Vec<Certificate>,
    priv_key: PrivateKey,
    server_name: String,
    inbound: DuplexChan,
    modifier: Arc<dyn Modifier>,
    creator: Arc<dyn Outbound>,
    conn_info: Arc<ConnContext>,
}

impl HttpsIntercept {
    pub fn new(
        ca_cert: &CaCertificate,
        server_name: String,
        inbound: DuplexChan,
        modifier: Arc<dyn Modifier>,
        creator: Box<dyn Outbound>,
        conn_info: Arc<ConnContext>,
    ) -> anyhow::Result<Self> {
        let (cert, priv_key) = sign_site_cert(server_name.as_str(), ca_cert)?;
        Ok(Self {
            cert,
            priv_key,
            server_name,
            inbound,
            modifier,
            creator: Arc::from(creator),
            conn_info,
        })
    }

    async fn proxy(
        sender: Arc<Mutex<Option<SendRequest<Body>>>>,
        client_tls: TlsConnector,
        server_name: ServerName,
        creator: Arc<dyn Outbound>,
        modifier: Arc<dyn Modifier>,
        req: Request<Body>,
        ctx: ModifierContext,
    ) -> anyhow::Result<Response<Body>> {
        let (req, fake_resp) = modifier.modify_request(req, &ctx).await?;
        if let Some(resp) = fake_resp {
            return Ok(resp);
        }
        let resp_future = {
            let mut sender = sender.lock().await;
            if sender.is_none() {
                *sender = Some({
                    let abort_handle = ConnAbortHandle::new();
                    abort_handle.fulfill(vec![]);
                    let (inbound, outbound) = Connector::new_pair(10);
                    let _handle = creator.spawn_tcp(inbound, abort_handle.clone());
                    let outbound = client_tls
                        .connect(server_name, DuplexChan::new(outbound))
                        .await?;
                    let (sender, connection) = conn::Builder::new().handshake(outbound).await?;
                    tokio::spawn(connection);
                    sender
                });
            };
            sender.as_mut().unwrap().send_request(req)
        };

        let resp = resp_future.await?;
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
        let client_tls = create_tls_connector();
        let server_name = ServerName::try_from(self.server_name.as_str())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let id_gen = IdGenerator::default();
        let sender = Arc::new(Mutex::new(None));
        let service = service_fn(|req| {
            // since sniffer is the middle part, async tasks should be cancelled properly
            Self::proxy(
                sender.clone(),
                client_tls.clone(),
                server_name.clone(),
                self.creator.clone(),
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
        if let Err(http_err) = Http::new()
            .http1_only(true)
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve_connection(inbound, service)
            .await
        {
            tracing::warn!("Sniff err {}", http_err);
        }
        Ok(())
    }
}
