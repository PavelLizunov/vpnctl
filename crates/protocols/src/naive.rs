use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

/// Naive — Chromium-fingerprint-mimicking proxy served by a **Caddy +
/// forwardproxy** kernel (NOT sing-box). Unauthenticated visitors get a
/// real masquerade website (HTTP 200); authenticated clients are
/// proxied. This is the strongest active-probe resistance of any
/// protocol in this crate: an active probe sees a genuine, serving web
/// server — not a `400`, not a self-signed cert with no HTML behind it
/// (cf. `Trojan`'s `Weak` tier), not bare QUIC.
///
/// # Kernel pairing
///
/// The wire format is "HTTP/2 CONNECT with naive padding over real-cert
/// TLS, with a real-website fallback". sing-box's `naive` INBOUND cannot
/// serve the fallback site (it `400`s every non-proxy request), so this
/// Protocol is served by the [`Caddy`] kernel instead. Exactly like
/// `WireGuard` ↔ `AmneziaWg`: `server_inbound` returns a STABLE JSON
/// ENVELOPE (per-user auth list + domain/email), which the Caddy kernel
/// deserialises and assembles into a Caddyfile.
///
/// [`Caddy`]: https://docs.rs/vpnctl-kernels
///
/// # Per-user secret
///
/// Reuses `User.tuic_password` as the HTTP Basic proxy password
/// (username = `User.id`), exactly like Trojan / AnyTLS / Hysteria2.
/// No migration needed — this preserves the kernel/protocol
/// orthogonality invariant (touches only `protocols` + `kernels` + two
/// registry lines). A dedicated `naive_password` column is a deliberate
/// later phase (see docs/NAIVE_CADDY_PLAN.md §2).
///
/// # Server params (via [`RenderCtx::secrets`])
///
/// - `naive.domain` (REQUIRED) — the real domain whose Let's Encrypt
///   cert Caddy's built-in ACME mints. The client connects HERE, never
///   to the raw server IP, so the cert validates and the SNI is a real
///   hostname.
/// - `naive.acme_email` (optional) — ACME account contact email.
///
/// **Stateless**, like every other Protocol in this crate.
#[derive(Debug, Default)]
pub struct Naive;

impl Naive {
    pub fn new() -> Self {
        Self
    }
}

/// Listen port. Public so the admin drift detector recognises the
/// inbound on a probe. Caddy-naive wants 443 (indistinguishable from
/// normal HTTPS), so a naive node MUST NOT also run a 443 sing-box
/// protocol (VLESS+REALITY / Trojan). Operator policy for now — the
/// cross-kernel port-conflict preflight that will enforce it is pending
/// (see docs/NAIVE_CADDY_PLAN.md §3).
pub const NAIVE_PORT: u16 = 443;

/// Userinfo-safe set for the `<user>:<pass>` segment of the share link.
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

impl Protocol for Naive {
    fn id(&self) -> ProtocolId {
        ProtocolId("naive".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", NAIVE_PORT)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // Caddy `forwardproxy` with `probe_resistance` + `file_server`
        // serves a REAL website (HTTP 200) to unauthenticated probes,
        // while the Chromium-network-stack naive client makes proxied
        // traffic byte-indistinguishable from a Chrome user browsing
        // that site. No fixed wire signature, no self-signed tell.
        vpnctl_core::DpiRisk::Strong
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        // `naive.domain` / `naive.acme_email` are operator-supplied
        // server PARAMS (not random-mintable), so nothing to declare
        // here; the per-user proxy password reuses `tuic_password`,
        // already minted by every user-add path. Bootstrap therefore
        // needs nothing naive-specific.
        Vec::new()
    }

    /// STABLE ENVELOPE consumed by the `caddy` kernel — NOT a sing-box
    /// inbound. Shape (the contract the kernel deserialises):
    ///
    /// ```json
    /// { "domain": "cdn.example.com",
    ///   "acme_email": "admin@example.com",
    ///   "auth": [ { "username": "alice", "password": "…" }, … ] }
    /// ```
    ///
    /// Users without a `tuic_password` are skipped (same policy as
    /// Trojan/TUIC) so a half-provisioned user can't emit an empty
    /// credential line into the Caddyfile.
    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let domain = ctx.require("naive.domain")?;
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
        let domain = ctx.require("naive.domain")?;
        let pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a naive client config",
                user.id.0
            ))
        })?;
        // sing-box `naive` outbound. `server`/`server_name` are the
        // DOMAIN (real LE cert), never the raw IP. `utls=chrome` shapes
        // the ClientHello like a real Chrome; the native naive binary
        // is byte-perfect on the H2 layer too, but the sing-box outbound
        // is the single-stack default (see module header trade-off).
        Ok(json!({
            "type": "naive",
            "tag": "naive-out",
            "server": domain,
            "server_port": NAIVE_PORT,
            "username": user.id.0,
            "password": pw,
            "tls": {
                "enabled": true,
                "server_name": domain,
                "utls": { "enabled": true, "fingerprint": "chrome" }
            }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let domain = ctx.require("naive.domain")?;
        let raw_pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a naive link",
                user.id.0
            ))
        })?;
        // naive client URL form (klzgrad naive + many sing-box GUIs):
        //   naive+https://<user>:<pass>@<domain>#<tag>
        // Both user and pass sit in the userinfo segment.
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
    fn client_config_targets_domain_with_utls_chrome() {
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let cfg = Naive::new()
            .client_config(&ctx, &user("alice", Some("pw-a")))
            .unwrap();
        assert_eq!(cfg["type"], "naive");
        // server is the DOMAIN, never the raw IP (real LE cert / SNI).
        assert_eq!(cfg["server"], "cdn.example.com");
        assert_ne!(cfg["server"], "203.0.113.9");
        assert_eq!(cfg["server_port"], 443);
        assert_eq!(cfg["username"], "alice");
        assert_eq!(cfg["password"], "pw-a");
        assert_eq!(cfg["tls"]["server_name"], "cdn.example.com");
        assert_eq!(cfg["tls"]["utls"]["fingerprint"], "chrome");
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
        // `@`, `:`, `/` in the userinfo segment must be percent-encoded
        // so the authority parses correctly.
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
}
