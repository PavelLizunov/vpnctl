use crate::encoding::{FRAGMENT, USERINFO as PASSWORD};
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

    fn server_inbound(&self, ctx: &RenderCtx<'_>, _users: &[User]) -> Result<serde_json::Value> {
        let psk = ctx.require("ss2022.psk")?;

        let method = ctx.or_default("ss2022.method", DEFAULT_METHOD);
        if !VALID_METHODS.contains(&method) {
            return Err(CoreError::Render(format!(
                "shadowsocks-2022 method '{method}' not supported (valid: {:?})",
                VALID_METHODS
            )));
        }

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
        let psk = ctx.require("ss2022.psk")?;
        let method = ctx.or_default("ss2022.method", DEFAULT_METHOD);
        if !VALID_METHODS.contains(&method) {
            return Err(CoreError::Render(format!(
                "shadowsocks-2022 method '{method}' not supported (valid: {:?})",
                VALID_METHODS
            )));
        }
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
        let psk = ctx.require("ss2022.psk")?;
        let method = ctx.or_default("ss2022.method", DEFAULT_METHOD);
        if !VALID_METHODS.contains(&method) {
            return Err(CoreError::Render(format!(
                "shadowsocks-2022 method '{method}' not supported (valid: {:?})",
                VALID_METHODS
            )));
        }
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
