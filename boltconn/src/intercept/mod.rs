mod header_engine;
mod http_intercept;
mod https_intercept;
mod intercept_manager;
mod intercept_modifier;
mod modifier;
mod script_engine;
mod url_engine;

use chrono::Datelike;
pub use header_engine::*;
pub use http_intercept::HttpIntercept;
pub use https_intercept::HttpsIntercept;
pub use intercept_manager::*;
pub use intercept_modifier::*;
pub use modifier::*;
use rcgen::{
    date_time_ymd, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    KeyUsagePurpose, SanType,
};
use regex::Regex;
pub use script_engine::*;
use std::ops::{Add, Sub};
use std::str::FromStr;
use tokio_rustls::rustls::pki_types::{
    CertificateDer as RustlsCertificate, PrivateKeyDer as RustlsPrivateKey,
};
pub use url_engine::*;

fn sign_site_cert(
    common_name: &str,
    ca_cert: &Certificate,
) -> anyhow::Result<(Vec<RustlsCertificate<'static>>, RustlsPrivateKey<'static>)> {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, common_name.to_string());
    distinguished_name.push(DnType::OrganizationName, "BoltConn-MITM");
    distinguished_name.push(DnType::CountryName, "US");

    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.is_ca = IsCa::NoCa;
    let date = chrono::offset::Utc::now().date_naive();
    let start = date.sub(chrono::Months::new(5));
    let end = date.add(chrono::Months::new(6));

    params.not_before = date_time_ymd(start.year(), start.month() as u8, start.day() as u8);
    params.not_after = date_time_ymd(end.year(), end.month() as u8, end.day() as u8);
    params.subject_alt_names = vec![SanType::DnsName(common_name.to_string())];

    // sign with CA and transform to rustls format
    let cert = Certificate::from_params(params)?;
    let cert_crt = cert.serialize_pem_with_signer(ca_cert)?;
    let private_key = cert.serialize_private_key_pem();
    let res_cert = rustls_pemfile::certs(&mut cert_crt.as_bytes())
        .next()
        .ok_or(anyhow::anyhow!("No generated cert available"))??;
    let res_key = RustlsPrivateKey::Pkcs8(
        rustls_pemfile::pkcs8_private_keys(&mut private_key.as_bytes())
            .next()
            .ok_or(anyhow::anyhow!("No generated privkey available"))??,
    );
    Ok((vec![res_cert], res_key))
}

#[derive(Clone, Debug)]
enum ReplacedChunk {
    Literal(String),
    Captured(u8),
}

impl ReplacedChunk {
    pub fn parse_chunks(regex: &Regex, source: &str) -> Option<Vec<Self>> {
        let pattern = Regex::new(r"\$\d+").unwrap();
        // test num ref validity
        for caps in pattern.captures_iter(source) {
            for idx in caps.iter().flatten() {
                match get_id(idx.as_str()) {
                    Ok(idx) if idx < regex.captures_len() as u8 => {}
                    _ => return None,
                }
            }
        }
        // ok, construct
        let mut chunks = vec![];
        let mut last = 0;
        for ma in pattern.find_iter(source) {
            if last != ma.start() {
                chunks.push(ReplacedChunk::Literal(source[last..ma.start()].to_string()));
            }
            chunks.push(ReplacedChunk::Captured(get_id(ma.as_str()).unwrap()));
            last = ma.end();
        }
        if last < source.len() {
            chunks.push(ReplacedChunk::Literal(source[last..].to_string()));
        }
        Some(chunks)
    }
}

#[derive(Clone, Debug)]
pub(super) struct Replacement {
    reg: Regex,
    chunks: Vec<ReplacedChunk>,
}

impl Replacement {
    pub fn new(regex: Regex, target: &str) -> Option<Self> {
        ReplacedChunk::parse_chunks(&regex, target).map(|v| Self {
            reg: regex,
            chunks: v,
        })
    }

    pub fn rewrite(&self, data: &str) -> Option<String> {
        if let Some(caps) = &self.reg.captures(data) {
            let mut res = String::new();
            for item in &self.chunks {
                match item {
                    ReplacedChunk::Literal(s) => res += s.as_str(),
                    ReplacedChunk::Captured(id) => {
                        if let Some(content) = caps.get(*id as usize) {
                            res += content.as_str()
                        } else {
                            // do nothing, "" as intended
                        }
                    }
                }
            }
            Some(res)
        } else {
            None
        }
    }
}

fn get_id(s: &str) -> Result<u8, core::num::ParseIntError> {
    u8::from_str(s.chars().skip(1).collect::<String>().as_str())
}
