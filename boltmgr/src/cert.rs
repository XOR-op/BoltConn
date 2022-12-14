use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    KeyUsagePurpose,
};
use std::fs;
use std::path::Path;

pub fn generate_cert<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    // generate ca only now
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "Catalyst-MITM");
    distinguished_name.push(DnType::OrganizationName, "Catalyst-MITM");
    distinguished_name.push(DnType::CountryName, "US");
    distinguished_name.push(DnType::LocalityName, "US");

    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = Certificate::from_params(params)?;
    let cert_crt = cert.serialize_pem().unwrap();
    let private_key = cert.serialize_private_key_pem();
    fs::write(path.as_ref().join("crt.pem"), cert_crt)?;
    fs::write(path.as_ref().join("key.pem"), private_key)?;
    println!("Successfully generated certificate and private key.");
    Ok(())
}
