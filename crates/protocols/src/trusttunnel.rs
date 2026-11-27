use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, DpiRisk, Protocol, ProtocolId, RenderCtx, Result, User};

use crate::encoding::FRAGMENT;
use crate::tls::{sha256_hex, tls_server_name, validate_tls_identity};
use crate::username_password::{inbound_users, listen_port, setting, userinfo, validate_user};
use crate::vless_reality::{is_valid_reality_handshake_server, is_valid_reality_sni};

pub const TRUSTTUNNEL_PORT: u16 = 8444;
const SNI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'.').remove(b'-');
const PIN_KEY: &str = "observed.tls.cert_public_key_sha256";

#[derive(Debug, Default)]
pub struct TrustTunnel;

struct Settings {
    port: u16,
    quic: bool,
    client_quic: bool,
    udp: bool,
}

impl Settings {
    fn parse(secrets: &HashMap<String, String>) -> Result<Self> {
        let flag = |key, default| {
            setting(secrets, key, default, &["true", "false"]).map(|value| value == "true")
        };
        let settings = Self {
            port: listen_port(secrets, "trusttunnel.listen_port", TRUSTTUNNEL_PORT)?,
            quic: flag("trusttunnel.quic", "true")?,
            client_quic: flag("trusttunnel.client_quic", "false")?,
            udp: flag("trusttunnel.udp", "true")?,
        };
        if settings.client_quic && !settings.quic {
            return Err(CoreError::Render(
                "TrustTunnel client QUIC requires the HTTP/3 listener".into(),
            ));
        }
        Ok(settings)
    }

    fn for_server(ctx: &RenderCtx<'_>) -> Result<Self> {
        let settings = Self::parse(ctx.secrets)?;
        if settings.port == ctx.server.ssh_port {
            return Err(CoreError::Render(
                "TrustTunnel TCP port conflicts with SSH".into(),
            ));
        }
        Ok(settings)
    }
}

enum TlsMaterial<'a> {
    Managed {
        sni: &'a str,
    },
    Custom {
        domain: &'a str,
        certificate: &'a str,
        key: &'a str,
    },
}

impl<'a> TlsMaterial<'a> {
    fn for_server(ctx: &'a RenderCtx<'_>) -> Result<Self> {
        let secrets = ctx.secrets;
        let custom = [
            "trusttunnel.domain",
            "trusttunnel.certificate",
            "trusttunnel.key",
        ];
        if custom.iter().any(|key| secrets.contains_key(*key)) {
            let [domain, certificate, key] = custom.map(|key| ctx.require(key).map(str::trim));
            let (domain, certificate, key) = (domain?, certificate?, key?);
            if !domain.contains('.') || !is_valid_reality_sni(domain) {
                return Err(CoreError::Render(
                    "trusttunnel.domain must be a DNS hostname".into(),
                ));
            }
            validate_tls_identity(domain, certificate, key)?;
            return Ok(Self::Custom {
                domain,
                certificate,
                key,
            });
        }

        let sni = secrets
            .get("trusttunnel.sni")
            .map(|sni| sni.trim())
            .or_else(|| tls_server_name(secrets))
            .unwrap_or(&ctx.server.address);
        if !is_valid_reality_handshake_server(sni) {
            return Err(CoreError::Render(
                "TrustTunnel TLS server name must be a DNS hostname or IP address".into(),
            ));
        }
        Ok(Self::Managed { sni })
    }

    fn inbound(&self, ctx: &RenderCtx<'_>) -> Value {
        match self {
            Self::Managed { .. } => json!({
                "enabled": true,
                "certificate_path": ctx.or_default("tuic.cert_path", "/etc/sing-box/cert.pem"),
                "key_path": ctx.or_default("tuic.key_path", "/etc/sing-box/key.pem"),
            }),
            Self::Custom {
                certificate, key, ..
            } => json!({
                "enabled": true,
                "certificate": certificate.lines().collect::<Vec<_>>(),
                "key": key.lines().collect::<Vec<_>>(),
            }),
        }
    }

    fn endpoint(&self, ctx: &'a RenderCtx<'_>) -> Result<(&'a str, &'a str, Option<&'a str>)> {
        match *self {
            Self::Custom { domain, .. } => Ok((domain, domain, None)),
            Self::Managed { sni } => {
                let pin = sha256_hex(ctx, PIN_KEY).ok_or_else(|| CoreError::Render(
                    "TrustTunnel requires an observed SHA-256 public-key pin for the managed TLS certificate".into(),
                ))?;
                Ok((&ctx.server.address, sni, Some(pin)))
            }
        }
    }
}

impl Protocol for TrustTunnel {
    fn id(&self) -> ProtocolId {
        ProtocolId("trusttunnel".into())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", TRUSTTUNNEL_PORT), ("udp", TRUSTTUNNEL_PORT)]
    }

    fn effective_listen_ports(
        &self,
        secrets: &HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        let Ok(settings) = Settings::parse(secrets) else {
            return Vec::new();
        };
        if settings.quic {
            vec![("tcp", settings.port), ("udp", settings.port)]
        } else {
            vec![("tcp", settings.port)]
        }
    }

    fn validate_server(&self, ctx: &RenderCtx<'_>) -> Result<()> {
        Settings::for_server(ctx)?;
        TlsMaterial::for_server(ctx).map(|_| ())
    }

    fn dpi_risk(&self) -> DpiRisk {
        DpiRisk::Strong
    }

    fn requires_inbound_users(&self) -> bool {
        true
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        false
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<Value> {
        let settings = Settings::for_server(ctx)?;
        let tls = TlsMaterial::for_server(ctx)?.inbound(ctx);
        Ok(json!({
            "type": "trusttunnel",
            "tag": "trusttunnel-in",
            "listen": "::",
            "listen_port": settings.port,
            "quic": settings.quic,
            "udp": settings.udp,
            "users": inbound_users(users, "TrustTunnel", false),
            "tls": tls,
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<Value> {
        validate_user(user, "TrustTunnel", false)?;
        let settings = Settings::for_server(ctx)?;
        let (server, sni, pin) = TlsMaterial::for_server(ctx)?.endpoint(ctx)?;
        let mut tls = json!({"enabled": true, "server_name": sni});
        if let Some(pin) = pin {
            let bytes = hex::decode(pin).map_err(|_| {
                CoreError::Render(
                    "TrustTunnel managed certificate has an invalid SHA-256 public-key pin".into(),
                )
            })?;
            tls["certificate_public_key_sha256"] = json!([STANDARD.encode(bytes)]);
        }
        Ok(json!({
            "type": "trusttunnel",
            "tag": "trusttunnel-out",
            "server": server,
            "server_port": settings.port,
            "username": user.id.0,
            "password": user.uuid,
            "udp": settings.udp,
            "quic": settings.client_quic,
            "health_check": true,
            "tls": tls,
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        validate_user(user, "TrustTunnel", false)?;
        let settings = Settings::for_server(ctx)?;
        let (server, sni, pin) = TlsMaterial::for_server(ctx)?.endpoint(ctx)?;
        let userinfo = userinfo(user);
        let host = host_for_url(server);
        let sni = utf8_percent_encode(sni, SNI_COMPONENT);
        let pin_param = pin.map_or_else(String::new, |pin| {
            format!("&pk_sha256={}", pin.to_ascii_lowercase())
        });
        let fragment = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!(
            "trusttunnel://{userinfo}@{host}:{}?sni={sni}&quic={}&udp={}{pin_param}#{fragment}",
            settings.port,
            u8::from(settings.client_quic),
            u8::from(settings.udp),
        ))
    }
}
