mod header_rewrite;
mod http_mitm;
mod https_mitm;
mod mitm_modifier;
mod modifier;
mod url_rewrite;

pub use http_mitm::HttpMitm;
pub use https_mitm::HttpsMitm;
pub use mitm_modifier::*;
pub use modifier::*;
use rcgen::{
    date_time_ymd, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyUsagePurpose,
};
use tokio_rustls::rustls::{Certificate as RustlsCertificate, PrivateKey as RustlsPrivateKey};
pub use url_rewrite::*;

fn sign_site_cert(
    common_name: &str,
    ca_cert: &Certificate,
) -> anyhow::Result<(Vec<RustlsCertificate>, RustlsPrivateKey)> {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, common_name.to_string());
    distinguished_name.push(DnType::OrganizationName, "BoltConn-MITM");
    distinguished_name.push(DnType::CountryName, "US");

    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.is_ca = IsCa::NoCa;
    params.not_before = date_time_ymd(2022, 1, 1);
    params.not_after = date_time_ymd(2037, 12, 31);

    // sign with CA and transform to rustls format
    let cert = Certificate::from_params(params)?;
    let cert_crt = cert.serialize_pem_with_signer(ca_cert)?;
    let private_key = cert.serialize_private_key_pem();
    let res_cert = RustlsCertificate(rustls_pemfile::certs(&mut cert_crt.as_bytes())?.remove(0));
    let res_key = RustlsPrivateKey(
        rustls_pemfile::pkcs8_private_keys(&mut private_key.as_bytes())?.remove(0),
    );
    Ok((vec![res_cert], res_key))
}
