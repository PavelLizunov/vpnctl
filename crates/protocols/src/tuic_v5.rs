use serde_json::json;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

#[derive(Debug, Default)]
pub struct TuicV5;

impl TuicV5 {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for TuicV5 {
    fn id(&self) -> ProtocolId {
        ProtocolId("tuic-v5".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("udp", 8443)]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let cert_path = ctx.or_default("tuic.cert_path", "/etc/sing-box/cert.pem");
        let key_path = ctx.or_default("tuic.key_path", "/etc/sing-box/key.pem");

        let users_json: Vec<_> = users
            .iter()
            .filter_map(|u| {
                u.tuic_password
                    .as_ref()
                    .map(|pw| json!({ "uuid": u.uuid, "name": u.id.0, "password": pw }))
            })
            .collect();

        Ok(json!({
            "type": "tuic",
            "tag": "tuic-in",
            "listen": "::",
            "listen_port": 8443,
            "congestion_control": "bbr",
            "users": users_json,
            "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": cert_path,
                "key_path": key_path,
            }
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a TUIC client config",
                user.id.0
            ))
        })?;
        Ok(json!({
            "type": "tuic",
            "tag": "tuic-out",
            "server": ctx.server.address,
            "server_port": 8443,
            "uuid": user.uuid,
            "password": pw,
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "tls": crate::tls::quic_client_tls(ctx)
        }))
    }

    fn share_link(&self, _ctx: &RenderCtx<'_>, _user: &User) -> Result<String> {
        Err(CoreError::ShareLinkUnavailable(
            "use the pinned TUIC sing-box or Mihomo subscription".into(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use vpnctl_core::{Server, ServerId, UserId};

    fn server() -> Server {
        Server {
            id: ServerId("node-1".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn user(name: &str, pw: Option<&str>) -> User {
        User {
            id: UserId(name.into()),
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            tuic_password: pw.map(str::to_string),
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    #[test]
    fn server_inbound_skips_users_without_tuic_password() {
        let s = server();
        let sec = HashMap::new();
        let ctx = RenderCtx::new(&s, &sec);
        let users = [
            user("alice", Some("pw-alice")),
            user("nopw", None),
            user("bob", Some("pw-bob")),
        ];
        let v = TuicV5::new().server_inbound(&ctx, &users).unwrap();
        let arr = v
            .get("users")
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert_eq!(arr.len(), 2, "user without tuic_password must be omitted");
        let names: Vec<&str> = arr
            .iter()
            .filter_map(|u| u.get("name").and_then(serde_json::Value::as_str))
            .collect();
        assert_eq!(names, vec!["alice", "bob"]);
    }

    #[test]
    fn client_config_happy_path() {
        let s = server();
        let sec = HashMap::new();
        let ctx = RenderCtx::new(&s, &sec);
        let u = user("alice", Some("pw-alice"));
        let v = TuicV5::new().client_config(&ctx, &u).unwrap();
        assert_eq!(
            v.get("type").and_then(serde_json::Value::as_str),
            Some("tuic")
        );
        assert_eq!(
            v.get("tag").and_then(serde_json::Value::as_str),
            Some("tuic-out")
        );
        assert_eq!(
            v.get("server").and_then(serde_json::Value::as_str),
            Some("203.0.113.7")
        );
        assert_eq!(
            v.get("server_port").and_then(serde_json::Value::as_u64),
            Some(8443)
        );
        assert_eq!(
            v.get("uuid").and_then(serde_json::Value::as_str),
            Some("00000000-0000-0000-0000-000000000001")
        );
        assert_eq!(
            v.get("password").and_then(serde_json::Value::as_str),
            Some("pw-alice")
        );
    }

    #[test]
    fn client_config_missing_password_returns_render_error() {
        let s = server();
        let sec = HashMap::new();
        let ctx = RenderCtx::new(&s, &sec);
        let u = user("alice", None);
        let err = TuicV5::new().client_config(&ctx, &u).unwrap_err();
        match err {
            CoreError::Render(msg) => {
                assert!(msg.contains("alice"));
                assert!(msg.contains("tuic_password"));
            }
            other => panic!("expected CoreError::Render, got {other:?}"),
        }
    }

    #[test]
    fn share_link_is_unavailable() {
        let s = server();
        let sec = HashMap::new();
        let ctx = RenderCtx::new(&s, &sec);
        let u = user("alice", None);
        let err = TuicV5::new().share_link(&ctx, &u).unwrap_err();
        assert!(matches!(err, CoreError::ShareLinkUnavailable(_)));
    }
}
