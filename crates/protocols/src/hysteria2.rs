use crate::encoding::{FRAGMENT, QUERY, USERINFO};
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

#[derive(Debug, Default)]
pub struct Hysteria2;

impl Hysteria2 {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for Hysteria2 {
    fn id(&self) -> ProtocolId {
        ProtocolId("hysteria2".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("udp", 8444)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        vpnctl_core::DpiRisk::Weak
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        vec![vpnctl_core::ServerSecretSpec::Password {
            key: "hysteria2.obfs.password",
            entropy_bytes: 24,
        }]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let cert_path = ctx.or_default("tuic.cert_path", "/etc/sing-box/cert.pem");
        let key_path = ctx.or_default("tuic.key_path", "/etc/sing-box/key.pem");

        let users_json: Vec<_> = users
            .iter()
            .filter_map(|u| {
                u.tuic_password
                    .as_ref()
                    .map(|pw| json!({ "name": u.id.0, "password": pw }))
            })
            .collect();

        let mut inbound = json!({
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "::",
            "listen_port": 8444,
            "users": users_json,
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": cert_path,
                "key_path": key_path,
            }
        });

        if let Some(server_url) = ctx
            .secrets
            .get("hysteria2.realm.server_url")
            .filter(|s| !s.trim().is_empty())
        {
            let realm_id = ctx
                .secrets
                .get("hysteria2.realm.realm_id")
                .map(String::as_str)
                .unwrap_or(&ctx.server.id.0);
            let token = ctx
                .secrets
                .get("hysteria2.realm.token")
                .map(String::as_str)
                .unwrap_or("");
            let stun_servers: Vec<&str> = ctx
                .secrets
                .get("hysteria2.realm.stun_servers")
                .map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|piece| !piece.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if let Some(map) = inbound.as_object_mut() {
                map.insert(
                    "realm".to_string(),
                    json!({
                        "server_url": server_url,
                        "realm_id": realm_id,
                        "token": token,
                        "stun_servers": stun_servers,
                    }),
                );
            }
        }

        if let Some(obfs_pw) = obfs_password(ctx)
            && let Some(map) = inbound.as_object_mut()
        {
            map.insert(
                "obfs".to_string(),
                json!({ "type": "salamander", "password": obfs_pw }),
            );
        }

        Ok(inbound)
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a Hysteria2 client config",
                user.id.0
            ))
        })?;
        let mut out = json!({
            "type": "hysteria2",
            "tag": "hy2-out",
            "server": ctx.server.address,
            "server_port": 8444,
            "password": pw,
            "tls": { "enabled": true, "insecure": true, "alpn": ["h3"] }
        });
        if let Some(obfs_pw) = obfs_password(ctx)
            && let Some(map) = out.as_object_mut()
        {
            map.insert(
                "obfs".to_string(),
                json!({ "type": "salamander", "password": obfs_pw }),
            );
        }
        Ok(out)
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let raw_pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a Hysteria2 link",
                user.id.0
            ))
        })?;
        let pw = utf8_percent_encode(raw_pw, USERINFO);
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        let obfs_suffix = match obfs_password(ctx) {
            Some(opw) => {
                let opw_enc = utf8_percent_encode(opw, QUERY);
                format!("&obfs=salamander&obfs-password={opw_enc}")
            }
            None => String::new(),
        };
        let pin_suffix = ctx
            .secrets
            .get("tls.cert_sha256")
            .map(|pin| format!("&pinSHA256={pin}"))
            .unwrap_or_default();
        Ok(format!(
            "hysteria2://{pw}@{host}:8444/?sni={sni}&insecure=1{obfs_suffix}{pin_suffix}#{name}",
            pw = pw,
            host = host_for_url(&ctx.server.address),
            sni = ctx.server.address,
            name = name,
            obfs_suffix = obfs_suffix,
        ))
    }
}

fn obfs_password<'a>(ctx: &'a RenderCtx<'a>) -> Option<&'a str> {
    ctx.secrets
        .get("hysteria2.obfs.password")
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
}
