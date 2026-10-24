use crate::encoding::{DOMAIN_ILLEGAL, FRAGMENT, USERINFO};
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

#[derive(Debug, Default)]
pub struct Naive;

impl Naive {
    pub fn new() -> Self {
        Self
    }
}

pub const NAIVE_PORT: u16 = 443;

fn checked_domain<'a>(ctx: &'a RenderCtx<'_>) -> Result<&'a str> {
    let domain = ctx.require("naive.domain")?;
    if domain.trim().is_empty() || domain.contains(DOMAIN_ILLEGAL) {
        return Err(CoreError::Render(format!(
            "naive.domain contains illegal characters or is empty: {domain:?}"
        )));
    }
    Ok(domain)
}

impl Protocol for Naive {
    fn id(&self) -> ProtocolId {
        ProtocolId("naive".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", NAIVE_PORT)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        vpnctl_core::DpiRisk::Strong
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        Vec::new()
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let domain = checked_domain(ctx)?;
        let acme_email = ctx.or_default("naive.acme_email", "");

        let auth: Vec<_> = users
            .iter()
            .filter_map(|u| {
                u.tuic_password
                    .as_ref()
                    .map(|pw| json!({ "username": u.id.0, "password": pw }))
            })
            .collect();

        Ok(json!({
            "domain": domain,
            "acme_email": acme_email,
            "auth": auth,
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let domain = checked_domain(ctx)?;
        let pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a naive client config",
                user.id.0
            ))
        })?;
        Ok(json!({
            "type": "naive",
            "tag": "naive-out",
            "server": domain,
            "server_port": NAIVE_PORT,
            "username": user.id.0,
            "password": pw,
            // No `utls`: sing-box's naive outbound rejects it ("uTLS is not
            // supported on naive outbound") and the whole config fails to load.
            "tls": {
                "enabled": true,
                "server_name": domain
            }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let domain = checked_domain(ctx)?;
        let raw_pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a naive link",
                user.id.0
            ))
        })?;
        let user_enc = utf8_percent_encode(&user.id.0, USERINFO);
        let pw = utf8_percent_encode(raw_pw, USERINFO);
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!(
            "naive+https://{user_enc}:{pw}@{domain}#{name}",
            user_enc = user_enc,
            pw = pw,
            domain = domain,
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
            id: ServerId("naive-node-1".into()),
            address: "203.0.113.9".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![],
            enabled_protocols: vec![ProtocolId("naive".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn secrets() -> HashMap<String, String> {
        let mut s = HashMap::new();
        s.insert("naive.domain".into(), "cdn.example.com".into());
        s.insert("naive.acme_email".into(), "admin@example.com".into());
        s
    }

    fn user(name: &str, pw: Option<&str>) -> User {
        User {
            id: UserId(name.into()),
            uuid: format!("uuid-{name}"),
            tuic_password: pw.map(str::to_string),
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    #[test]
    fn id_listen_port_and_dpi_tier() {
        let n = Naive::new();
        assert_eq!(n.id(), ProtocolId("naive".into()));
        assert_eq!(n.listen_ports(), &[("tcp", 443)]);
        assert_eq!(n.dpi_risk(), DpiRisk::Strong);
    }

    #[test]
    fn server_inbound_envelope_carries_domain_and_per_user_auth() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let users = [user("alice", Some("pw-a")), user("bob", Some("pw-b"))];
        let env = Naive::new().server_inbound(&ctx, &users).unwrap();
        assert_eq!(env["domain"], "cdn.example.com");
        assert_eq!(env["acme_email"], "admin@example.com");
        let auth = env["auth"].as_array().unwrap();
        assert_eq!(auth.len(), 2);
        assert_eq!(auth[0]["username"], "alice");
        assert_eq!(auth[0]["password"], "pw-a");
    }

    #[test]
    fn server_inbound_skips_users_without_password() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let users = [user("alice", Some("pw-a")), user("nopass", None)];
        let env = Naive::new().server_inbound(&ctx, &users).unwrap();
        assert_eq!(env["auth"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn server_inbound_missing_domain_is_missing_secret() {
        let s = server();
        let sec = HashMap::new();
        let ctx = RenderCtx::new(&s, &sec);
        let err = Naive::new()
            .server_inbound(&ctx, &[user("a", Some("p"))])
            .unwrap_err();
        match err {
            CoreError::MissingSecret { key, .. } => assert_eq!(key, "naive.domain"),
            other => panic!("expected MissingSecret, got {other:?}"),
        }
    }

    #[test]
    fn client_config_targets_domain_without_utls() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let cfg = Naive::new()
            .client_config(&ctx, &user("alice", Some("pw-a")))
            .unwrap();
        assert_eq!(cfg["type"], "naive");
        assert_eq!(cfg["server"], "cdn.example.com");
        assert_ne!(cfg["server"], "203.0.113.9");
        assert_eq!(cfg["server_port"], 443);
        assert_eq!(cfg["username"], "alice");
        assert_eq!(cfg["password"], "pw-a");
        assert_eq!(cfg["tls"]["server_name"], "cdn.example.com");
        assert_eq!(
            cfg["tls"],
            serde_json::json!({ "enabled": true, "server_name": "cdn.example.com" }),
            "naive TLS must carry no utls block — sing-box refuses it"
        );
    }

    #[test]
    fn client_config_missing_password_is_render_error() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let err = Naive::new()
            .client_config(&ctx, &user("alice", None))
            .unwrap_err();
        match err {
            CoreError::Render(m) => assert!(m.contains("tuic_password"), "msg: {m}"),
            other => panic!("expected Render, got {other:?}"),
        }
    }

    #[test]
    fn share_link_naive_https_form() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let link = Naive::new()
            .share_link(&ctx, &user("alice", Some("pw-a")))
            .unwrap();
        assert_eq!(link, "naive+https://alice:pw-a@cdn.example.com#alice");
    }

    #[test]
    fn share_link_percent_encodes_reserved_chars_in_password() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let link = Naive::new()
            .share_link(&ctx, &user("alice", Some("p@ss:w/d")))
            .unwrap();
        assert!(link.contains("p%40ss%3Aw%2Fd"), "link: {link}");
    }

    #[test]
    fn share_link_missing_password_is_render_error() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let err = Naive::new()
            .share_link(&ctx, &user("alice", None))
            .unwrap_err();
        assert!(matches!(err, CoreError::Render(_)));
    }

    #[test]
    fn client_artefacts_reject_newline_injection_domain() {
        let s = server();
        let mut sec = HashMap::new();
        sec.insert(
            "naive.domain".into(),
            "evil.com\nvless://forged@1.2.3.4:443?x".into(),
        );
        let ctx = RenderCtx::new(&s, &sec);
        let n = Naive::new();
        assert!(
            n.share_link(&ctx, &user("alice", Some("pw"))).is_err(),
            "share_link must reject an injection domain"
        );
        assert!(
            n.client_config(&ctx, &user("alice", Some("pw"))).is_err(),
            "client_config must reject the same domain"
        );
    }

    #[test]
    fn artefacts_reject_empty_and_whitespace_domain_across_inbound_client_link() {
        let s = server();
        let n = Naive::new();
        let u = user("alice", Some("pw"));
        for bad_domain in ["", "   ", "\t", "\n", " \t \n "] {
            let mut sec = HashMap::new();
            sec.insert("naive.domain".into(), bad_domain.to_string());
            let ctx = RenderCtx::new(&s, &sec);

            let in_err = n
                .server_inbound(&ctx, std::slice::from_ref(&u))
                .unwrap_err();
            assert!(
                matches!(in_err, CoreError::Render(_)),
                "server_inbound must return Render error for domain {bad_domain:?}, got {in_err:?}"
            );

            let cfg_err = n.client_config(&ctx, &u).unwrap_err();
            assert!(
                matches!(cfg_err, CoreError::Render(_)),
                "client_config must return Render error for domain {bad_domain:?}, got {cfg_err:?}"
            );

            let link_err = n.share_link(&ctx, &u).unwrap_err();
            assert!(
                matches!(link_err, CoreError::Render(_)),
                "share_link must return Render error for domain {bad_domain:?}, got {link_err:?}"
            );
        }
    }

    #[test]
    fn server_inbound_rejects_illegal_domain() {
        let s = server();
        let n = Naive::new();
        let u = user("alice", Some("pw"));
        for bad in [
            "a b.com",
            "x.com/path",
            "x.com@evil",
            "x.com?q",
            "x.com#f",
            "x.com\ny.com",
        ] {
            let mut sec = HashMap::new();
            sec.insert("naive.domain".into(), bad.to_string());
            let ctx = RenderCtx::new(&s, &sec);
            assert!(
                n.server_inbound(&ctx, std::slice::from_ref(&u)).is_err(),
                "server_inbound must reject domain {bad:?}"
            );
        }
    }
}
