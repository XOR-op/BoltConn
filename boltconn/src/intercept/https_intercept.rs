use crate::adapter::{Connector, Outbound};
use crate::common::client_hello::get_overrider;
use crate::common::create_tls_connector;
use crate::common::duplex_chan::DuplexChan;
use crate::common::utils::IdGenerator;
use crate::intercept::modifier::Modifier;
use crate::intercept::{sign_site_cert, HyperBody, ModifierContext};
use crate::proxy::error::InterceptError;
use crate::proxy::{ConnAbortHandle, ConnContext};
use hyper::client::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::Certificate as CaCertificate;
use std::io;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct HttpsIntercept {
    cert: Vec<CertificateDer<'static>>,
    priv_key: PrivateKeyDer<'static>,
    server_name: String,
    inbound: DuplexChan,
    modifier: Arc<dyn Modifier>,
    creator: Arc<dyn Outbound>,
    conn_info: Arc<ConnContext>,
    parrot_fingerprint: bool,
}

impl HttpsIntercept {
    pub fn new(
        ca_cert: &CaCertificate,
        server_name: String,
        inbound: DuplexChan,
        modifier: Arc<dyn Modifier>,
        creator: Box<dyn Outbound>,
        conn_info: Arc<ConnContext>,
        parrot_fingerprint: bool,
    ) -> Result<Self, InterceptError> {
        let (cert, priv_key) = sign_site_cert(server_name.as_str(), ca_cert)?;
        Ok(Self {
            cert,
            priv_key,
            server_name,
            inbound,
            modifier,
            creator: Arc::from(creator),
            conn_info,
            parrot_fingerprint,
        })
    }

    async fn proxy(
        sender: Arc<Mutex<Option<http2::SendRequest<HyperBody>>>>,
        client_tls: TlsConnector,
        server_name: ServerName<'static>,
        creator: Arc<dyn Outbound>,
        modifier: Arc<dyn Modifier>,
        req: Request<HyperBody>,
        ctx: ModifierContext,
    ) -> Result<Response<HyperBody>, InterceptError> {
        let (req, fake_resp) = modifier.modify_request(req, &ctx).await?;
        if let Some(resp) = fake_resp {
            return Ok(resp);
        }
        let resp_future = {
            let mut sender = sender.lock().await;
            if sender.is_none() {
                *sender = Some({
                    let (inbound, outbound) = Connector::new_pair(10);
                    let _handle = creator.spawn_tcp(inbound, ConnAbortHandle::placeholder());
                    let outbound = client_tls
                        .connect(server_name, DuplexChan::new(outbound))
                        .await
                        .map_err(InterceptError::TlsConnect)?;
                    let (sender, connection) =
                        http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                            .handshake(TokioIo::new(outbound))
                            .await
                            .map_err(InterceptError::Handshake)?;
                    tokio::spawn(connection);
                    sender
                });
            };
            sender.as_mut().unwrap().send_request(req)
        };

        let (parts, resp_body) = resp_future
            .await
            .map_err(InterceptError::WaitResponse)?
            .into_parts();
        let resp = modifier
            .modify_response(Response::from_parts(parts, HyperBody::new(resp_body)), &ctx)
            .await?;
        Ok(resp)
    }

    pub async fn run(self) -> io::Result<()> {
        // tls server
        let mut tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.cert, self.priv_key)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // tls client
        let client_tls = create_tls_connector(if self.parrot_fingerprint {
            Some(get_overrider())
        } else {
            None
        });
        let server_name = ServerName::try_from(self.server_name.as_str())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
            .to_owned();
        let id_gen = IdGenerator::default();
        let sender = Arc::new(Mutex::new(None));
        let service = service_fn(|req| {
            // since sniffer is the middle part, async tasks should be cancelled properly
            let (parts, body) = req.into_parts();
            let fut = Self::proxy(
                sender.clone(),
                client_tls.clone(),
                server_name.clone(),
                self.creator.clone(),
                self.modifier.clone(),
                Request::from_parts(parts, HyperBody::new(body)),
                ModifierContext {
                    tag: id_gen.get(),
                    conn_info: self.conn_info.clone(),
                },
            );
            async move {
                match fut.await {
                    Ok(resp) => Ok(resp),
                    Err(err) => {
                        tracing::warn!("https interception failed: {}", err);
                        Err(err)
                    }
                }
            }
        });

        // start running
        let inbound = acceptor.accept(self.inbound).await?;
        if let Err(http_err) =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(TokioIo::new(inbound), service)
                .await
        {
            tracing::warn!("https interception failed to serve: {}", http_err);
        }
        Ok(())
    }
}
