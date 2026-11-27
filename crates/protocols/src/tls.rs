use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use vpnctl_core::{CoreError, RenderCtx, Result};

pub fn tls_server_name(secrets: &HashMap<String, String>) -> Option<&str> {
    secrets
        .get("tls.server_name")
        .map(|s| s.trim())
        .filter(|s| crate::vless_reality::is_valid_reality_sni(s))
}

pub(crate) fn quic_client_tls(ctx: &RenderCtx<'_>) -> Value {
    let mut tls = json!({"enabled": true, "insecure": false, "alpn": ["h3"]});
    if let Some(sni) = tls_server_name(ctx.secrets) {
        tls["server_name"] = json!(sni);
    }
    if let Some(bytes) =
        sha256_hex(ctx, "observed.tls.cert_public_key_sha256").and_then(|pin| hex::decode(pin).ok())
    {
        tls["certificate_public_key_sha256"] = json!([STANDARD.encode(bytes)]);
    }
    tls
}

pub(crate) fn sha256_hex<'a>(ctx: &RenderCtx<'a>, key: &str) -> Option<&'a str> {
    ctx.secrets
        .get(key)
        .map(String::as_str)
        .filter(|pin| pin.len() == 64 && pin.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub(crate) fn validate_tls_identity(domain: &str, certificate: &str, key: &str) -> Result<()> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::server::ParsedCertificate;

    let invalid_pair = || {
        CoreError::Render(
            "TrustTunnel needs a valid PEM certificate chain and matching unencrypted private key"
                .into(),
        )
    };
    if !certificate.starts_with("-----BEGIN CERTIFICATE-----")
        || !certificate.ends_with("-----END CERTIFICATE-----")
        || !["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]
            .iter()
            .any(|kind| {
                key.starts_with(&format!("-----BEGIN {kind}-----"))
                    && key.ends_with(&format!("-----END {kind}-----"))
            })
        || key.matches("-----BEGIN ").count() != 1
    {
        return Err(invalid_pair());
    }
    let chain = CertificateDer::pem_slice_iter(certificate.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| invalid_pair())?;
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).map_err(|_| invalid_pair())?;
    let provider = rustls::crypto::ring::default_provider();
    let pair =
        rustls::sign::CertifiedKey::from_der(chain, key, &provider).map_err(|_| invalid_pair())?;
    pair.keys_match().map_err(|_| invalid_pair())?;
    let leaf = ParsedCertificate::try_from(pair.end_entity_cert().map_err(|_| invalid_pair())?)
        .map_err(|_| invalid_pair())?;
    let name = ServerName::try_from(domain).map_err(|_| invalid_pair())?;
    rustls::client::verify_server_name(&leaf, &name).map_err(|_| {
        CoreError::Render("The TrustTunnel certificate must cover the custom TLS hostname".into())
    })
}
