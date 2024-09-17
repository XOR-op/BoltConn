use crate::platform::UserInfo;
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    IsCa, KeyUsagePurpose,
};
use std::fs;
use std::path::{Path, PathBuf};

fn safe_write(path: PathBuf, content: &str) -> anyhow::Result<()> {
    fs::write(path.as_path(), content)?;
    UserInfo::root().chown(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&path, perm)?;
    }
    Ok(())
}

pub fn generate_cert<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    // generate ca only now
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "*");
    distinguished_name.push(DnType::OrganizationName, "BoltConn-MITM");
    distinguished_name.push(DnType::CountryName, "US");

    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = date_time_ymd(2022, 1, 1);
    params.not_after = date_time_ymd(2037, 12, 31);
    let cert = Certificate::from_params(params)?;
    let cert_crt = cert.serialize_pem().unwrap();
    let private_key = cert.serialize_private_key_pem();
    safe_write(path.as_ref().join("crt.pem"), &cert_crt)?;
    safe_write(path.as_ref().join("key.pem"), &private_key)?;
    println!("Successfully generated certificate and private key.");
    Ok(())
}
