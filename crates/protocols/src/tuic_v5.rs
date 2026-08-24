use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

/// Userinfo-safe set: everything that has a structural meaning in
/// `<userinfo>@<host>` of an authority component (RFC 3986 §3.2.1).
/// `%` is included so values already containing `%` don't produce
/// malformed percent-encoding when re-encoded downstream.
const USERINFO: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'@')
    .add(b'/')
    .add(b':')
    .add(b'\\')
    .add(b'[')
    .add(b']');

const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?');

/// TUIC v5 на UDP:8443. Self-signed cert — на клиенте `insecure: true`
/// (UUID+password — настоящая аутентификация, TLS чисто для шифрования).
///
/// **Stateless**: пути к сертификатам приходят через [`RenderCtx::secrets`].
///
/// Конвенция ключей:
///
/// - `tuic.cert_path` (optional, default `/etc/sing-box/cert.pem`)
/// - `tuic.key_path`  (optional, default `/etc/sing-box/key.pem`)
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
            "tls": { "enabled": true, "insecure": true, "alpn": ["h3"] }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let raw_pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a TUIC link",
                user.id.0
            ))
        })?;
        // Both UUID and password sit inside the userinfo segment, where `:`,
        // `@`, `/`, and space would corrupt parsing. Name sits in the fragment.
        let uuid = utf8_percent_encode(&user.uuid, USERINFO);
        let pw = utf8_percent_encode(raw_pw, USERINFO);
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!(
            "tuic://{uuid}:{pw}@{addr}:8443?congestion_control=bbr&alpn=h3&allow_insecure=1#{name}",
            uuid = uuid,
            pw = pw,
            addr = host_for_url(&ctx.server.address),
            name = name,
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
    fn share_link_missing_password_returns_render_error() {
        let s = server();
        let sec = HashMap::new();
        let ctx = RenderCtx::new(&s, &sec);
        let u = user("alice", None);
        let err = TuicV5::new().share_link(&ctx, &u).unwrap_err();
        match err {
            CoreError::Render(msg) => {
                assert!(msg.contains("alice"));
                assert!(msg.contains("tuic_password"));
            }
            other => panic!("expected CoreError::Render, got {other:?}"),
        }
    }

    #[test]
    fn share_link_percent_encodes_percent_sign_in_password_and_name() {
        let s = server();
        let sec = HashMap::new();
        let ctx = RenderCtx::new(&s, &sec);
        let u = user("alice%100", Some("secret%20pass"));
        let link = TuicV5::new().share_link(&ctx, &u).unwrap();
        assert!(
            link.contains(":secret%2520pass@"),
            "percent sign in password must be escaped to %25; got: {link}"
        );
        assert!(
            link.ends_with("#alice%25100"),
            "percent sign in name fragment must be escaped to %25; got: {link}"
        );
    }

    #[test]
    fn share_link_percent_encodes_reserved_userinfo_and_fragment_chars() {
        let s = server();
        let sec = HashMap::new();
        let ctx = RenderCtx::new(&s, &sec);
        let mut u = user("user#name?test <tag>", Some("p@ss:w/d\\test?#%"));
        u.uuid = "00000000-0000-0000-0000-000000000001%test".into();
        let link = TuicV5::new().share_link(&ctx, &u).unwrap();
        assert!(
            link.contains("00000000-0000-0000-0000-000000000001%25test:"),
            "uuid with percent must be escaped; got: {link}"
        );
        assert!(
            link.contains(":p%40ss%3Aw%2Fd%5Ctest%3F%23%25@"),
            "userinfo characters must be escaped; got: {link}"
        );
        assert!(
            link.ends_with("#user%23name%3Ftest%20%3Ctag%3E"),
            "fragment characters must be escaped; got: {link}"
        );
    }
}
