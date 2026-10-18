use crate::encoding::{DOMAIN_ILLEGAL, VLESS_FRAGMENT as FRAGMENT};
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

pub const DEFAULT_FRONT_PORT: u16 = 8443;

const WS_UTLS_FP: &str = "chrome";

#[derive(Debug, Default)]
pub struct VlessWs;

impl VlessWs {
    pub fn new() -> Self {
        Self
    }
}

fn checked_domain<'a>(ctx: &'a RenderCtx<'_>) -> Result<&'a str> {
    let domain = ctx.require("vlessws.domain")?;
    if domain.is_empty() || domain.contains(DOMAIN_ILLEGAL) {
        return Err(CoreError::Render(format!(
            "vlessws.domain contains illegal characters or is empty: {domain:?}"
        )));
    }
    Ok(domain)
}

fn checked_path<'a>(ctx: &'a RenderCtx<'_>) -> Result<&'a str> {
    let path = ctx.require("vlessws.path")?;
    if path.is_empty()
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(CoreError::Render(format!(
            "vlessws.path must be a non-empty [A-Za-z0-9_-] string (url-safe-base64 \
             minted by bootstrap); got {path:?}"
        )));
    }
    Ok(path)
}

fn front_port(ctx: &RenderCtx<'_>) -> u16 {
    front_port_from_secrets(ctx.secrets)
}

fn front_port_from_secrets(secrets: &std::collections::HashMap<String, String>) -> u16 {
    secrets
        .get("vlessws.listen_port")
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|&p| p != 0)
        .unwrap_or(DEFAULT_FRONT_PORT)
}

impl Protocol for VlessWs {
    fn id(&self) -> ProtocolId {
        ProtocolId("vless-ws".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[]
    }

    fn effective_listen_ports(
        &self,
        secrets: &std::collections::HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        vec![("tcp", front_port_from_secrets(secrets))]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        vpnctl_core::DpiRisk::Strong
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        vec![vpnctl_core::ServerSecretSpec::Password {
            key: "vlessws.path",
            entropy_bytes: 16,
        }]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let domain = checked_domain(ctx)?;
        let acme_email = ctx.or_default("vlessws.acme_email", "");
        let path = checked_path(ctx)?;
        let port = front_port(ctx);

        let users_json: Vec<_> = users
            .iter()
            .map(|u| json!({ "uuid": u.uuid, "name": u.id.0 }))
            .collect();

        Ok(json!({
            "domain": domain,
            "acme_email": acme_email,
            "front_port": port,
            "path": format!("/{path}"),
            "users": users_json,
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let domain = checked_domain(ctx)?;
        let path = checked_path(ctx)?;
        let port = front_port(ctx);
        Ok(json!({
            "type": "vless",
            "tag": "vless-ws-out",
            "server": domain,
            "server_port": port,
            "uuid": user.uuid,
            "tls": {
                "enabled": true,
                "server_name": domain,
                "utls": { "enabled": true, "fingerprint": WS_UTLS_FP }
            },
            "transport": {
                "type": "ws",
                "path": format!("/{path}"),
                "headers": { "Host": domain }
            }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let domain = checked_domain(ctx)?;
        let path = checked_path(ctx)?;
        let port = front_port(ctx);
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!(
            "vless://{uuid}@{addr}:{port}?encryption=none&type=ws&security=tls&sni={sni}&host={host}&path=%2F{path}&fp={fp}#{name}",
            uuid = user.uuid,
            addr = host_for_url(domain),
            port = port,
            sni = domain,
            host = domain,
            path = path,
            fp = WS_UTLS_FP,
            name = name,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use vpnctl_core::{DpiRisk, Server, ServerId, UserId};

    fn server() -> Server {
        Server {
            id: ServerId("de".into()),
            address: "104.194.156.93".into(),
            ssh_port: 2222,
            ssh_user: "root".into(),
            kernels: vec![],
            enabled_protocols: vec![ProtocolId("vless-ws".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn secrets() -> HashMap<String, String> {
        let mut s = HashMap::new();
        s.insert("vlessws.domain".into(), "de.ninitux.top".into());
        s.insert("vlessws.acme_email".into(), "admin@ninitux.top".into());
        s.insert("vlessws.path".into(), "Ab3x9Zq2Kp7Lm".into());
        s
    }

    fn user(name: &str, uuid: &str) -> User {
        User {
            id: UserId(name.into()),
            uuid: uuid.into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    #[test]
    fn id_and_no_static_port_and_strong() {
        let p = VlessWs::new();
        assert_eq!(p.id(), ProtocolId("vless-ws".into()));
        assert!(p.listen_ports().is_empty());
        assert_eq!(p.dpi_risk(), DpiRisk::Strong);
        assert!(p.appears_in_sing_box_sub());
    }

    #[test]
    fn secret_spec_declares_minted_path() {
        let specs = VlessWs::new().server_secret_specs();
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0],
            vpnctl_core::ServerSecretSpec::Password {
                key: "vlessws.path",
                entropy_bytes: 16,
            }
        );
    }

    #[test]
    fn server_inbound_envelope_shape() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let users = [
            user("alice", "11111111-1111-4111-8111-111111111111"),
            user("bob", "22222222-2222-4222-8222-222222222222"),
        ];
        let env = VlessWs::new().server_inbound(&ctx, &users).unwrap();
        assert_eq!(env["domain"], "de.ninitux.top");
        assert_eq!(env["acme_email"], "admin@ninitux.top");
        assert_eq!(env["front_port"], 8443);
        assert_eq!(env["path"], "/Ab3x9Zq2Kp7Lm");
        let arr = env["users"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["uuid"], "11111111-1111-4111-8111-111111111111");
        assert_eq!(arr[0]["name"], "alice");
    }

    #[test]
    fn front_port_override() {
        let s = server();
        let mut sec = secrets();
        sec.insert("vlessws.listen_port".into(), "2087".into());
        let ctx = RenderCtx::new(&s, &sec);
        let env = VlessWs::new().server_inbound(&ctx, &[]).unwrap();
        assert_eq!(env["front_port"], 2087);
        sec.insert("vlessws.listen_port".into(), "0".into());
        let ctx0 = RenderCtx::new(&s, &sec);
        assert_eq!(
            VlessWs::new().server_inbound(&ctx0, &[]).unwrap()["front_port"],
            8443
        );
    }

    #[test]
    fn effective_listen_ports_tracks_front_port() {
        let p = VlessWs::new();
        let sec = secrets();
        assert_eq!(p.effective_listen_ports(&sec), vec![("tcp", 8443)]);
        let mut sec2 = secrets();
        sec2.insert("vlessws.listen_port".into(), "2087".into());
        assert_eq!(p.effective_listen_ports(&sec2), vec![("tcp", 2087)]);
        for bad in ["0", "", "junk", "-1", "65536"] {
            let mut s = secrets();
            s.insert("vlessws.listen_port".into(), bad.into());
            assert_eq!(
                p.effective_listen_ports(&s),
                vec![("tcp", 8443)],
                "bad override {bad:?}"
            );
        }
        let srv = server();
        let ctx = RenderCtx::new(&srv, &sec2);
        let env = p.server_inbound(&ctx, &[]).unwrap();
        assert_eq!(
            env["front_port"].as_u64().unwrap() as u16,
            p.effective_listen_ports(&sec2)[0].1
        );
    }

    #[test]
    fn client_config_is_vless_ws_tls_no_flow_no_reality() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let cfg = VlessWs::new()
            .client_config(&ctx, &user("alice", "u-1"))
            .unwrap();
        assert_eq!(cfg["type"], "vless");
        assert_eq!(cfg["server"], "de.ninitux.top");
        assert_ne!(cfg["server"], "104.194.156.93");
        assert_eq!(cfg["server_port"], 8443);
        assert_eq!(cfg["uuid"], "u-1");
        assert!(cfg.get("flow").is_none());
        assert!(cfg["tls"].get("reality").is_none());
        assert_eq!(cfg["tls"]["server_name"], "de.ninitux.top");
        assert_eq!(cfg["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(cfg["transport"]["type"], "ws");
        assert_eq!(cfg["transport"]["path"], "/Ab3x9Zq2Kp7Lm");
        assert_eq!(cfg["transport"]["headers"]["Host"], "de.ninitux.top");
    }

    #[test]
    fn share_link_format() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let link = VlessWs::new()
            .share_link(&ctx, &user("alice", "u-1"))
            .unwrap();
        assert_eq!(
            link,
            "vless://u-1@de.ninitux.top:8443?encryption=none&type=ws&security=tls&sni=de.ninitux.top&host=de.ninitux.top&path=%2FAb3x9Zq2Kp7Lm&fp=chrome#alice"
        );
    }

    #[test]
    fn share_link_path_matches_client_transport_path() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let p = VlessWs::new();
        let env = p.server_inbound(&ctx, &[]).unwrap();
        let cfg = p.client_config(&ctx, &user("a", "u")).unwrap();
        assert_eq!(env["path"], cfg["transport"]["path"]);
        let link = p.share_link(&ctx, &user("a", "u")).unwrap();
        assert!(link.contains("path=%2FAb3x9Zq2Kp7Lm"));
    }

    #[test]
    fn missing_domain_errors() {
        let s = server();
        let mut sec = secrets();
        sec.remove("vlessws.domain");
        let ctx = RenderCtx::new(&s, &sec);
        assert!(VlessWs::new().server_inbound(&ctx, &[]).is_err());
        assert!(VlessWs::new().share_link(&ctx, &user("a", "u")).is_err());
    }

    #[test]
    fn missing_or_bad_path_errors() {
        let s = server();
        let mut sec = secrets();
        sec.remove("vlessws.path");
        let ctx = RenderCtx::new(&s, &sec);
        assert!(VlessWs::new().share_link(&ctx, &user("a", "u")).is_err());
        let mut sec2 = secrets();
        sec2.insert("vlessws.path".into(), "ab/cd".into());
        let ctx2 = RenderCtx::new(&s, &sec2);
        assert!(
            VlessWs::new()
                .client_config(&ctx2, &user("a", "u"))
                .is_err()
        );
    }

    #[test]
    fn rejects_injection_domain() {
        let s = server();
        let mut sec = secrets();
        sec.insert(
            "vlessws.domain".into(),
            "evil.com\nvless://forged@1.2.3.4:443?x".into(),
        );
        let ctx = RenderCtx::new(&s, &sec);
        let p = VlessWs::new();
        assert!(p.share_link(&ctx, &user("a", "u")).is_err());
        assert!(p.client_config(&ctx, &user("a", "u")).is_err());
        assert!(p.server_inbound(&ctx, &[]).is_err());
    }

    #[test]
    fn share_link_byte_stable() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let p = VlessWs::new();
        let a = p.share_link(&ctx, &user("alice", "u-1")).unwrap();
        let b = p.share_link(&ctx, &user("alice", "u-1")).unwrap();
        assert_eq!(a, b);
    }
}
