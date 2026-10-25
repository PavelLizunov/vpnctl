use crate::encoding::{FRAGMENT, USERINFO as PASSWORD};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use sha2::Sha256;
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
    multi_user(ctx)?;
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

fn multi_user(ctx: &RenderCtx<'_>) -> Result<bool> {
    match ctx.or_default("ss2022.mode", "shared") {
        "shared" => Ok(false),
        "multi-user" => {
            let method = ctx.or_default("ss2022.method", DEFAULT_METHOD);
            key_bytes(method)?;
            if method == "2022-blake3-chacha20-poly1305" {
                return Err(CoreError::Render(
                    "SS2022 per-user keys require 2022-blake3-aes-128-gcm or 2022-blake3-aes-256-gcm; chacha20 does not support EIH".into(),
                ));
            }
            Ok(true)
        }
        _ => Err(CoreError::Render(
            "ss2022.mode must be shared or multi-user".into(),
        )),
    }
}

/// Key of the placeholder user rendered when no user is granted: an empty
/// list makes sing-box fall back to single-user mode and accept the bare
/// server PSK (every old shared link) again.
const NO_USERS_PSK: &str = "ss2022.no_users_psk";

fn user_psk(method: &str, psk: &str, user: &User) -> Result<String> {
    let key = B64
        .decode(psk)
        .map_err(|_| CoreError::Render("invalid ss2022.psk base64".into()))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|_| CoreError::Render("invalid ss2022.psk HMAC key".into()))?;
    mac.update(b"vpnctl-ss2022-user\0");
    mac.update(user.uuid.as_bytes());
    Ok(B64.encode(&mac.finalize().into_bytes()[..key_bytes(method)?]))
}

fn client_password(ctx: &RenderCtx<'_>, method: &str, psk: &str, user: &User) -> Result<String> {
    if multi_user(ctx)? {
        Ok(format!("{psk}:{}", user_psk(method, psk, user)?))
    } else {
        Ok(psk.to_string())
    }
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

    fn validate_server(&self, ctx: &RenderCtx<'_>) -> Result<()> {
        multi_user(ctx).map(|_| ())
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
        let mut specs = vec![vpnctl_core::ServerSecretSpec::Base64Key {
            key: "ss2022.psk",
            key_bytes: key_bytes(method)?,
        }];
        if secrets.get("ss2022.mode").map(String::as_str) == Some("multi-user") {
            // Never derived from the server PSK: every client holds that one.
            specs.push(vpnctl_core::ServerSecretSpec::Base64Key {
                key: NO_USERS_PSK,
                key_bytes: key_bytes(method)?,
            });
        }
        Ok(specs)
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let (method, psk) = checked_credentials(ctx)?;

        let mut inbound = json!({
            "type": "shadowsocks",
            "tag": "ss22-in",
            "listen": "::",
            "listen_port": SS_2022_PORT,
            "method": method,
            "password": psk,
        });
        if multi_user(ctx)? {
            let users = users
                .iter()
                .map(|user| {
                    Ok(json!({
                        "name": user.id.0,
                        "password": user_psk(method, psk, user)?,
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            let users = if users.is_empty() {
                vec![json!({
                    "name": "vpnctl-no-users",
                    "password": ctx.require(NO_USERS_PSK)?,
                })]
            } else {
                users
            };
            inbound["users"] = json!(users);
        }
        Ok(inbound)
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let (method, psk) = checked_credentials(ctx)?;
        Ok(json!({
            "type": "shadowsocks",
            "tag": "ss22-out",
            "server": ctx.server.address,
            "server_port": SS_2022_PORT,
            "method": method,
            "password": client_password(ctx, method, psk, user)?,
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let (method, psk) = checked_credentials(ctx)?;
        let password = client_password(ctx, method, psk, user)?;
        let pw_enc = utf8_percent_encode(&password, PASSWORD);
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
