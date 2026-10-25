use crate::encoding::{FRAGMENT, USERINFO as PASSWORD};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

#[derive(Debug, Default)]
pub struct Shadowsocks2022;

impl Shadowsocks2022 {
    pub fn new() -> Self {
        Self
    }
}

const DEFAULT_METHOD: &str = "2022-blake3-aes-128-gcm";

const VALID_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

fn key_bytes(method: &str) -> Result<usize> {
    match method {
        "2022-blake3-aes-128-gcm" => Ok(16),
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => Ok(32),
        _ => Err(CoreError::Render(format!(
            "shadowsocks-2022 method '{method}' not supported (valid: {:?})",
            VALID_METHODS
        ))),
    }
}

fn checked_credentials<'a>(ctx: &'a RenderCtx<'_>) -> Result<(&'a str, &'a str)> {
    let psk = ctx.require("ss2022.psk")?;
    let method = ctx.or_default("ss2022.method", DEFAULT_METHOD);
    let required = key_bytes(method)?;
    let decoded = B64.decode(psk).map_err(|_| {
        CoreError::Render(format!(
            "ss2022.psk must be standard padded base64 encoding {required} bytes for {method}"
        ))
    })?;
    if decoded.len() != required {
        return Err(CoreError::Render(format!(
            "ss2022.psk must decode to {required} bytes for {method}, got {} bytes; configure a matching PSK before deploying",
            decoded.len()
        )));
    }
    Ok((method, psk))
}

pub const SS_2022_PORT: u16 = 8388;

impl Protocol for Shadowsocks2022 {
    fn id(&self) -> ProtocolId {
        ProtocolId("shadowsocks-2022".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", SS_2022_PORT), ("udp", SS_2022_PORT)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        vpnctl_core::DpiRisk::Weak
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        vec![vpnctl_core::ServerSecretSpec::Base64Key {
            key: "ss2022.psk",
            key_bytes: 16,
        }]
    }

    fn server_secret_specs_for(
        &self,
        secrets: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<vpnctl_core::ServerSecretSpec>> {
        let method = secrets
            .get("ss2022.method")
            .map(String::as_str)
            .unwrap_or(DEFAULT_METHOD);
        Ok(vec![vpnctl_core::ServerSecretSpec::Base64Key {
            key: "ss2022.psk",
            key_bytes: key_bytes(method)?,
        }])
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, _users: &[User]) -> Result<serde_json::Value> {
        let (method, psk) = checked_credentials(ctx)?;

        Ok(json!({
            "type": "shadowsocks",
            "tag": "ss22-in",
            "listen": "::",
            "listen_port": SS_2022_PORT,
            "method": method,
            "password": psk,
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, _user: &User) -> Result<serde_json::Value> {
        let (method, psk) = checked_credentials(ctx)?;
        Ok(json!({
            "type": "shadowsocks",
            "tag": "ss22-out",
            "server": ctx.server.address,
            "server_port": SS_2022_PORT,
            "method": method,
            "password": psk,
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let (method, psk) = checked_credentials(ctx)?;
        let pw_enc = utf8_percent_encode(psk, PASSWORD);
        let method_enc = utf8_percent_encode(method, PASSWORD);
        let tag_enc = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!(
            "ss://{method_enc}:{pw_enc}@{addr}:{port}/#{tag_enc}",
            method_enc = method_enc,
            pw_enc = pw_enc,
            addr = host_for_url(&ctx.server.address),
            port = SS_2022_PORT,
            tag_enc = tag_enc,
        ))
    }
}
