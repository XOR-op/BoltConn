use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    KeyUsagePurpose,
};
use std::fs;

fn main() {
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
    let cert = Certificate::from_params(params).expect("Failed to generate certificate");
    let cert_crt = cert.serialize_pem().unwrap();
    let private_key = cert.serialize_private_key_pem();
    if let Err(err) = fs::write("_private/ca/crt.pem", cert_crt) {
        eprintln!("Fail to write cert: {}", err);
    }
    if let Err(err) = fs::write("_private/ca/key.pem", private_key) {
        eprintln!("Fail to write private key: {}", err);
    }
    println!("Generated certificate and private key.")
}
