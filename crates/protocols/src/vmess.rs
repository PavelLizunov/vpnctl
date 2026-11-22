use std::collections::{HashMap, HashSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use vpnctl_core::{
    CoreError, DpiRisk, Protocol, ProtocolId, RenderCtx, Result, ServerSecretSpec, User,
};

const DEFAULT_PORT: u16 = 443;
const WS_PATH: &str = "/vmess";
const SECURITY: &str = "aes-128-gcm";
const ALPN: &str = "http/1.1";

#[derive(Debug, Default)]
pub struct Vmess;

struct Endpoint<'a> {
    domain: &'a str,
    port: u16,
}

impl Protocol for Vmess {
    fn id(&self) -> ProtocolId {
        ProtocolId("vmess".into())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", DEFAULT_PORT)]
    }

    fn effective_listen_ports(
        &self,
        secrets: &HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        listen_port(secrets)
            .map(|port| vec![("tcp", port)])
            .unwrap_or_default()
    }

    fn server_secret_specs(&self) -> Vec<ServerSecretSpec> {
        vec![
            ServerSecretSpec::Required {
                key: "vmess.domain",
            },
            ServerSecretSpec::Required {
                key: "vmess.certificate",
            },
            ServerSecretSpec::Required { key: "vmess.key" },
        ]
    }

    fn validate_server(&self, ctx: &RenderCtx<'_>) -> Result<()> {
        let endpoint = endpoint(ctx)?;
        if endpoint.port == ctx.server.ssh_port {
            return Err(CoreError::Render("VMess port conflicts with SSH".into()));
        }
        tls_material(ctx).map(|_| ())
    }

    fn dpi_risk(&self) -> DpiRisk {
        DpiRisk::Moderate
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<Value> {
        let endpoint = endpoint(ctx)?;
        let (certificate, key) = tls_material(ctx)?;
        let mut uuids = HashSet::new();
        let users: Vec<_> = users
            .iter()
            .filter(|user| {
                validate_user(user).is_ok() && uuids.insert(user.uuid.to_ascii_lowercase())
            })
            .map(|user| json!({ "name": user.id.0, "uuid": user.uuid, "alterId": 0 }))
            .collect();
        Ok(json!({
            "type": "vmess",
            "tag": "vmess-in",
            "listen": "::",
            "listen_port": endpoint.port,
            "users": users,
            "tls": {
                "enabled": true,
                "alpn": [ALPN],
                "certificate": certificate.lines().collect::<Vec<_>>(),
                "key": key.lines().collect::<Vec<_>>(),
            },
            "transport": { "type": "ws", "path": WS_PATH },
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<Value> {
        validate_user(user)?;
        let endpoint = endpoint(ctx)?;
        Ok(json!({
            "type": "vmess",
            "tag": "vmess-out",
            "server": endpoint.domain,
            "server_port": endpoint.port,
            "uuid": user.uuid,
            "security": SECURITY,
            "alter_id": 0,
            "tls": { "enabled": true, "server_name": endpoint.domain, "alpn": [ALPN] },
            "transport": { "type": "ws", "path": WS_PATH, "headers": { "Host": endpoint.domain } },
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        validate_user(user)?;
        let endpoint = endpoint(ctx)?;
        let profile = json!({
            "v": "2",
            "ps": format!("{} VMess ~{}", ctx.server.id.0, user.id.0),
            "add": endpoint.domain,
            "port": endpoint.port.to_string(),
            "id": user.uuid,
            "aid": "0",
            "scy": SECURITY,
            "net": "ws",
            "type": "none",
            "host": endpoint.domain,
            "path": WS_PATH,
            "tls": "tls",
            "sni": endpoint.domain,
            "alpn": ALPN,
        });
        Ok(format!("vmess://{}", STANDARD.encode(profile.to_string())))
    }
}

fn endpoint<'a>(ctx: &'a RenderCtx<'_>) -> Result<Endpoint<'a>> {
    let domain = ctx.require("vmess.domain")?;
    if domain.len() > 253
        || !domain.contains('.')
        || domain.parse::<std::net::IpAddr>().is_ok()
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(CoreError::Render(
            "vmess.domain must be a DNS hostname".into(),
        ));
    }
    Ok(Endpoint {
        domain,
        port: listen_port(ctx.secrets)?,
    })
}

fn listen_port(secrets: &HashMap<String, String>) -> Result<u16> {
    match secrets.get("vmess.listen_port") {
        None => Ok(DEFAULT_PORT),
        Some(value) => value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| CoreError::Render("vmess.listen_port must be in 1..=65535".into())),
    }
}

fn tls_material<'a>(ctx: &'a RenderCtx<'_>) -> Result<(&'a str, &'a str)> {
    let certificate = ctx.require("vmess.certificate")?.trim();
    let key = ctx.require("vmess.key")?.trim();
    if !certificate.starts_with("-----BEGIN CERTIFICATE-----")
        || !certificate.ends_with("-----END CERTIFICATE-----")
    {
        return Err(CoreError::Render(
            "VMess needs a PEM certificate chain".into(),
        ));
    }
    let key_kind = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]
        .iter()
        .any(|kind| {
            key.starts_with(&format!("-----BEGIN {kind}-----"))
                && key.ends_with(&format!("-----END {kind}-----"))
        });
    if !key_kind {
        return Err(CoreError::Render(
            "VMess needs an unencrypted PEM private key".into(),
        ));
    }
    Ok((certificate, key))
}

fn validate_user(user: &User) -> Result<()> {
    if user.disabled {
        return Err(CoreError::Render(
            "disabled users cannot receive VMess configurations".into(),
        ));
    }
    if !vpnctl_crypto::is_valid_uuid(&user.uuid) {
        return Err(CoreError::Render("VMess user has an invalid UUID".into()));
    }
    Ok(())
}
