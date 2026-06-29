use std::path::Path;
use std::sync::Arc;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};

/// How a server's TLS certificate is validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertVerify {
    /// Verify the certificate against the system root store.
    Verify,
    /// Skip certificate verification entirely.
    SkipVerify,
    /// Accept the server only if it presents this exact certificate.
    Pinned(CertificateDer<'static>),
}

#[derive(Debug)]
pub enum CertError {
    /// The certificate file could not be located or read.
    Read,
    /// The PEM data did not contain a valid certificate.
    Parse,
    /// The PEM data contained no certificate.
    Empty,
}

/// Load a certificate to pin from either inline PEM or a file path.
///
/// `src` is treated as inline PEM when it contains a PEM header. Otherwise it is
/// resolved as a file path via [`crate::config::safe_join_path`], which keeps the
/// path confined to the config directory (preventing traversal outside it).
pub fn load_pinned_cert(
    config_path: &Path,
    src: &str,
) -> Result<CertificateDer<'static>, CertError> {
    let pem = if src.contains("-----BEGIN") {
        src.to_string()
    } else {
        let path = crate::config::safe_join_path(config_path, src).map_err(|_| CertError::Read)?;
        std::fs::read_to_string(path).map_err(|_| CertError::Read)?
    };
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .ok_or(CertError::Empty)?
        .map_err(|_| CertError::Parse)
}

/// Build a rustls client config matching the given verification policy.
pub fn make_tls_config(cert_verify: &CertVerify) -> Arc<ClientConfig> {
    match cert_verify {
        CertVerify::Verify => {
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
            Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(root_cert_store)
                    .with_no_client_auth(),
            )
        }
        CertVerify::SkipVerify => {
            let mut config = ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertVerification {}));
            Arc::new(config)
        }
        CertVerify::Pinned(cert) => {
            let mut config = ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(PinnedCertVerification { cert: cert.clone() }));
            Arc::new(config)
        }
    }
}

#[derive(Debug)]
struct NoCertVerification {}

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_verify_schemes()
    }
}

#[derive(Debug)]
struct PinnedCertVerification {
    cert: CertificateDer<'static>,
}

impl ServerCertVerifier for PinnedCertVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if end_entity.as_ref() == self.cert.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General("pinned certificate mismatch".to_string()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_verify_schemes()
    }
}

fn supported_verify_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_SHA1_Legacy,
        SignatureScheme::RSA_PKCS1_SHA1,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{Certificate, CertificateParams};

    /// Generate a self-signed certificate, returned as PEM. rcgen produces a
    /// fresh (non-deterministic) signature on each serialization, so callers
    /// must derive the DER from this exact PEM rather than re-serializing.
    fn generate_cert_pem(common_name: &str) -> String {
        Certificate::from_params(CertificateParams::new(vec![common_name.to_string()]))
            .unwrap()
            .serialize_pem()
            .unwrap()
    }

    /// The DER bytes embedded in a PEM certificate.
    fn der_of(pem: &str) -> Vec<u8> {
        rustls_pemfile::certs(&mut pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .as_ref()
            .to_vec()
    }

    #[test]
    fn load_pinned_cert_from_inline_pem() {
        let pem = generate_cert_pem("example.com");
        // The config base path is irrelevant for inline PEM.
        let loaded = load_pinned_cert(Path::new("/does/not/exist"), &pem).unwrap();
        assert_eq!(loaded.as_ref(), der_of(&pem).as_slice());
    }

    #[test]
    fn load_pinned_cert_from_file_path() {
        let pem = generate_cert_pem("example.com");
        let dir = std::env::temp_dir();
        let file_name = format!("boltconn_cert_test_{}.pem", std::process::id());
        let path = dir.join(&file_name);
        std::fs::write(&path, pem.as_bytes()).unwrap();

        // `src` is resolved relative to the config base directory.
        let loaded = load_pinned_cert(&dir, &file_name).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded.as_ref(), der_of(&pem).as_slice());
    }

    #[test]
    fn load_pinned_cert_rejects_invalid_pem() {
        assert!(load_pinned_cert(Path::new("."), "not a certificate").is_err());
    }

    #[test]
    fn pinned_verifier_matches_only_the_pinned_cert() {
        let pem = generate_cert_pem("example.com");
        let pinned = load_pinned_cert(Path::new("."), &pem).unwrap();
        let verifier = PinnedCertVerification {
            cert: pinned.clone(),
        };

        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::now();

        // The exact certificate the server presents is accepted, regardless of
        // any CA chain.
        assert!(
            verifier
                .verify_server_cert(&pinned, &[], &server_name, &[], now)
                .is_ok()
        );

        // A different certificate (e.g. an attacker's) is rejected.
        let other = CertificateDer::from(der_of(&generate_cert_pem("example.com")));
        assert!(
            verifier
                .verify_server_cert(&other, &[], &server_name, &[], now)
                .is_err()
        );
    }
}
