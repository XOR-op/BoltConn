use ja_tools::JAOverride;
use ja_tools::builder::JAOverrideBuilder;
use ja_tools::rustls_vendor::client::client_hello::CompressCertificateOptions;
use ja_tools::rustls_vendor::internal::msgs::enums::ExtensionType;
use ja_tools::rustls_vendor::internal::msgs::handshake::{ClientExtension, ProtocolName};
use ja_tools::rustls_vendor::{ProtocolVersion, SignatureScheme};
use std::sync::{Arc, OnceLock};

fn override_config() -> JAOverride {
    let ja3_full = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-10-5-43-65281-35-16-11-13-23-17513-27-18-45-0-65037,29-23-24,0";
    let mut builder = JAOverrideBuilder::default();
    builder
        .with_grease(true)
        .with_signature_algorithms(vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA512,
        ])
        .with_tls_versions(vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2])
        .with_alpn(vec![
            ProtocolName::from("h2".as_bytes().to_vec()),
            ProtocolName::from("http/1.1".as_bytes().to_vec()),
        ])
        .with_shuffle_extension(true)
        .with_compress_certificate(CompressCertificateOptions::Brotli);
    builder.unknown_extensions.insert(
        17513,
        ClientExtension::unknown(ExtensionType::Unknown(17513), [0x0, 0x3, 0x2, 68, 32]),
    );
    builder
        .unknown_extensions
        .insert(65037, ja_tools::extensions::grease_ech());
    builder.with_ja3_full(ja3_full).unwrap()
}

static OVERRIDER: OnceLock<Arc<JAOverride>> = OnceLock::new();

pub fn get_overrider() -> Arc<JAOverride> {
    OVERRIDER
        .get_or_init(|| Arc::new(override_config()))
        .clone()
}
