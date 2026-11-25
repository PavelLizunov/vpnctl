use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use vpnctl_core::RenderCtx;

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

fn sha256_hex<'a>(ctx: &RenderCtx<'a>, key: &str) -> Option<&'a str> {
    ctx.secrets
        .get(key)
        .map(String::as_str)
        .filter(|pin| pin.len() == 64 && pin.bytes().all(|byte| byte.is_ascii_hexdigit()))
}
