//! VLESS + WebSocket + TLS (DIRECT, no CDN) — served by the `caddy` kernel.
//!
//! ## Why this protocol
//!
//! RU TSPU (2026) blocks VLESS+REALITY at the connection/volume level
//! regardless of SNI, and throttles ALL Cloudflare-proxied traffic to
//! ~16 KB/connection (so CDN-fronting / WARP are dead ends for RU). The
//! proven-working posture is a DIRECT real-domain TLS proxy — our `naive`
//! already lives this way on `cdn.ninitux.top` (direct A-record, Let's
//! Encrypt, NO CDN). VLESS+ws is the one transport that is BOTH
//! direct-domain-DPI-resistant AND client-universal: it imports on
//! v2rayNG / v2RayTun / Happ / sing-box, unlike hysteria2/tuic which the
//! v2ray-core family can't parse. See `plans/vless-ws-direct.md`.
//!
//! ## Kernel pairing — caddy front + loopback sing-box ws backend
//!
//! Served by the `caddy` kernel (NOT a public sing-box :443). Caddy
//! terminates a real Let's-Encrypt cert on a per-node alt port, serves a
//! decoy site at `/`, and `reverse_proxy`s ONE secret path to a PLAINTEXT
//! sing-box VLESS+ws inbound on `127.0.0.1`. The caddy kernel OWNS BOTH
//! units (Caddyfile + loopback sing-box) via the `BUNDLE_DELIMITER` +
//! second-systemd-unit pattern `dns_tunnel` already runs in prod — there
//! is NO cross-kernel API and we don't invent one.
//!
//! Like `naive`, [`Protocol::server_inbound`] returns a STABLE JSON
//! ENVELOPE the caddy kernel deserialises (domain, acme_email, the front
//! port, the secret ws path, and the per-user uuid list for the loopback
//! inbound). The protocol never knows it's caddy; the kernel never
//! hard-codes per-user identity.
//!
//! ## Port coexistence
//!
//! [`listen_ports`](Protocol::listen_ports) returns `&[]` (no STATIC
//! port), but [`effective_listen_ports`](Protocol::effective_listen_ports)
//! resolves the real front port (default 8443) from secrets — so the
//! cross-protocol port-conflict guard and the drift table DO see it: a
//! node can run `vless-ws` ALONGSIDE VLESS+REALITY on :443 (different
//! ports, guard validates), while reality being moved onto the SAME port
//! via `vless.listen_port` is rejected pre-SSH instead of crash-looping
//! caddy or sing-box at runtime (cdn incident follow-up, PR #139 review).
//!
//! ## Server params (via [`RenderCtx::secrets`])
//!
//! - `vlessws.domain`      (REQUIRED) — the real subdomain whose LE cert
//!   caddy mints (e.g. `de.ninitux.top`). The client connects HERE, never
//!   to the raw IP, so the cert validates and the SNI is a real hostname.
//! - `vlessws.listen_port` (optional, default [`DEFAULT_FRONT_PORT`]) —
//!   the public TLS port caddy serves on. NOT 443 (REALITY owns that); an
//!   alt-HTTPS port (8443 / 2087) that reads as a legit site.
//! - `vlessws.acme_email`  (optional) — ACME account contact email.
//! - `vlessws.path`        (AUTO-MINTED) — high-entropy secret ws path,
//!   declared in [`server_secret_specs`](Protocol::server_secret_specs)
//!   so the declarative bootstrap mints it (no bootstrap change needed).
//!
//! Per-user identity reuses `User.uuid` (the SAME uuid the user carries
//! for VLESS-REALITY — effective per-server uuid already resolved upstream
//! in `users_for_server` / `user_with_per_server_uuid`).
//!
//! **Stateless**, like every other Protocol in this crate.

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

/// Default public TLS port caddy serves the ws site on when
/// `vlessws.listen_port` is unset. **NOT 443** — VLESS+REALITY owns :443
/// on de/is, and 3x-ui owns it on nl. 8443 is a Cloudflare-published
/// "alt-HTTPS" port, so HTTPS there reads as a legit CF-fronted site
/// rather than an anomaly.
pub const DEFAULT_FRONT_PORT: u16 = 8443;

/// uTLS ClientHello fingerprint the client mimics for the (real,
/// non-REALITY) TLS handshake to caddy. `chrome` matches what `naive`
/// uses (`naive.rs`) and `naive` is field-proven in RU — for a real
/// Let's-Encrypt cert there is no REALITY "steal" to fingerprint, so the
/// REALITY-specific `fp=chrome` blocking does not apply here. Kept a
/// single constant so it can flip fleet-wide (like `REALITY_UTLS_FP` did
/// on 2026-06-16) if TSPU ever starts fingerprinting the ws ClientHello.
const WS_UTLS_FP: &str = "chrome";

/// Set of bytes percent-encoded in the `#<name>` URL fragment (RFC 3986):
/// everything that controls URL parsing plus space/`#`/`?` which would
/// truncate or open a new component. Mirrors `vless_reality.rs`.
const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?')
    .add(b'/')
    .add(b'@')
    .add(b':');

/// Characters that must never appear in a `vlessws.domain` woven into a
/// CLIENT artefact (share-link) or the Caddyfile. `\n`/`\r`/tab would
/// forge extra lines into the newline-joined `/api/v1/app/config` base64
/// blob (line injection) and the URI-structural chars (` /?#@\` etc.)
/// would corrupt the `vless://…` link. A real hostname contains none.
/// Mirrors `naive.rs::DOMAIN_ILLEGAL`; the caddy KERNEL guards the server
/// side, this guards the client side.
const DOMAIN_ILLEGAL: &[char] = &['\n', '\r', '\t', ' ', '/', '?', '#', '@', '\\', '{', '}'];

#[derive(Debug, Default)]
pub struct VlessWs;

impl VlessWs {
    pub fn new() -> Self {
        Self
    }
}

/// `RenderCtx::require("vlessws.domain")` + reject [`DOMAIN_ILLEGAL`].
/// Single source of truth for "a domain safe to put in a client artefact"
/// (share_link + client_config). Mirrors `naive::checked_domain`.
fn checked_domain<'a>(ctx: &'a RenderCtx<'_>) -> Result<&'a str> {
    let domain = ctx.require("vlessws.domain")?;
    if domain.is_empty() || domain.contains(DOMAIN_ILLEGAL) {
        return Err(CoreError::Render(format!(
            "vlessws.domain contains illegal characters or is empty: {domain:?}"
        )));
    }
    Ok(domain)
}

/// `RenderCtx::require("vlessws.path")` + reject anything outside the
/// URL-path-safe `[A-Za-z0-9_-]` charset. The secret is bootstrap-minted
/// as url-safe base64 (so always matches), but a hand-set value carrying
/// `/`, `?`, `#`, whitespace or a control char would (a) break the
/// Caddyfile `path` matcher / sing-box `transport.path` agreement and
/// (b) corrupt the `path=%2F…` share-link query — so fail closed.
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

/// Resolve the front (public TLS) port from `vlessws.listen_port`,
/// defaulting to [`DEFAULT_FRONT_PORT`]. An invalid / zero value falls
/// back to the default so a typo never silently drops the inbound to
/// port 0 (mirrors `vless_reality.rs`'s `vless.listen_port` handling).
fn front_port(ctx: &RenderCtx<'_>) -> u16 {
    front_port_from_secrets(ctx.secrets)
}

/// Secrets-only variant of [`front_port`] for consumers that have the
/// server's secret map but no full [`RenderCtx`] — the cross-protocol
/// port-conflict guard, the firewall step and the admin drift table
/// (`effective_listen_ports`). MUST stay the single source of truth for
/// "which public port caddy binds on this node": with the default 8443
/// this protocol COLLIDES with a reality moved to 8443 via
/// `vless.listen_port` (the cdn-incident remedy), and with 2087 with any
/// other tenant of that port — the guard has to see it either way.
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
        // NO static port: the front port is per-server configurable
        // (`vlessws.listen_port`, default 8443), so a compile-time
        // declaration would be wrong more often than right. Context-aware
        // consumers (guard / firewall / drift) call
        // `effective_listen_ports` instead, which resolves the real port.
        &[]
    }

    fn effective_listen_ports(
        &self,
        secrets: &std::collections::HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        // The public TLS port caddy binds on this node. Declaring it is
        // what lets the cross-protocol guard reject a reality moved onto
        // the SAME port via `vless.listen_port` (default front port 8443
        // == reality's canonical escape port — the exact cdn-incident
        // remedy would otherwise recreate the outage one port over).
        vec![("tcp", front_port_from_secrets(secrets))]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // Real Let's-Encrypt cert on a real subdomain + a genuine decoy
        // website served at `/` by caddy (an active probe gets HTTP 200
        // from a real site, the secret ws path is hidden), with a
        // Chrome-shaped uTLS ClientHello. Same active-probe posture as
        // `naive` → Strong.
        vpnctl_core::DpiRisk::Strong
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        // The secret ws path — declared so the declarative bootstrap mints
        // it (url-safe base64, like every other Password spec). `domain`,
        // `acme_email` and `listen_port` are operator-supplied PARAMS (not
        // random-mintable), so nothing to declare for them; per-user
        // identity reuses `User.uuid` (already minted by every user-add
        // path). 16 bytes → ~22 chars of url-safe base64.
        vec![vpnctl_core::ServerSecretSpec::Password {
            key: "vlessws.path",
            entropy_bytes: 16,
        }]
    }

    /// STABLE ENVELOPE consumed by the `caddy` kernel — NOT a sing-box
    /// inbound. Shape (the contract the kernel deserialises):
    ///
    /// ```json
    /// { "domain": "de.ninitux.top",
    ///   "acme_email": "admin@ninitux.top",
    ///   "front_port": 8443,
    ///   "path": "/<secret>",
    ///   "users": [ { "uuid": "…", "name": "alice" }, … ] }
    /// ```
    ///
    /// The kernel composes the Caddyfile (decoy + `reverse_proxy <path> →
    /// 127.0.0.1:<backend>`) AND the loopback sing-box ws inbound from
    /// this. `users` carries every granted+enabled user's effective uuid
    /// (`User.uuid` is already the per-server effective value here).
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
        // sing-box VLESS outbound over a ws transport with REAL TLS (caddy
        // terminates it). NO `flow` — XTLS-Vision is incompatible with a
        // ws transport (it hunts for a raw-TLS record boundary). NO
        // `reality`. `Host` header == SNI == domain so caddy routes by the
        // real hostname.
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
        // Standard VLESS+ws+TLS share-link understood by v2rayNG /
        // v2RayTun / Happ / sing-box. `type=ws` + `security=tls` (NOT
        // reality), `host` == `sni` == domain, `path=%2F<secret>` (the
        // leading slash percent-encoded so it stays inside the query
        // value). No `flow` (ws). `path` is `[A-Za-z0-9_-]` (checked) so
        // it needs no further query-encoding.
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
        // No static port → coexists with REALITY on :443.
        assert!(p.listen_ports().is_empty());
        assert_eq!(p.dpi_risk(), DpiRisk::Strong);
        // It IS a normal sing-box vless+ws outbound → stays in the sub.
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
        // a 0 / garbage value falls back to the default
        sec.insert("vlessws.listen_port".into(), "0".into());
        let ctx0 = RenderCtx::new(&s, &sec);
        assert_eq!(
            VlessWs::new().server_inbound(&ctx0, &[]).unwrap()["front_port"],
            8443
        );
    }

    /// `effective_listen_ports` must track the SAME front port the
    /// envelope renders — default, override, and the 0/garbage fallback —
    /// so the guard/drift/firewall see what caddy actually binds
    /// (PR #139 review finding 1: without this, a reality moved to the
    /// default front port 8443 recreated the cdn outage one port over).
    #[test]
    fn effective_listen_ports_tracks_front_port() {
        let p = VlessWs::new();
        // default
        let sec = secrets();
        assert_eq!(p.effective_listen_ports(&sec), vec![("tcp", 8443)]);
        // override
        let mut sec2 = secrets();
        sec2.insert("vlessws.listen_port".into(), "2087".into());
        assert_eq!(p.effective_listen_ports(&sec2), vec![("tcp", 2087)]);
        // 0 / garbage → default, exactly like the envelope
        for bad in ["0", "", "junk", "-1", "65536"] {
            let mut s = secrets();
            s.insert("vlessws.listen_port".into(), bad.into());
            assert_eq!(
                p.effective_listen_ports(&s),
                vec![("tcp", 8443)],
                "bad override {bad:?}"
            );
        }
        // and it agrees with the rendered envelope
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
        assert_eq!(cfg["server"], "de.ninitux.top"); // domain, never raw IP
        assert_ne!(cfg["server"], "104.194.156.93");
        assert_eq!(cfg["server_port"], 8443);
        assert_eq!(cfg["uuid"], "u-1");
        // NO flow (ws), NO reality block.
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
        // The caddy route, sing-box transport.path, and the share-link
        // path MUST agree. Both derive from the same `vlessws.path` secret
        // → `/<secret>` in configs, `%2F<secret>` in the link query.
        let s = server();
        let sec = secrets();
        let ctx = RenderCtx::new(&s, &sec);
        let p = VlessWs::new();
        let env = p.server_inbound(&ctx, &[]).unwrap();
        let cfg = p.client_config(&ctx, &user("a", "u")).unwrap();
        assert_eq!(env["path"], cfg["transport"]["path"]); // "/Ab3x9Zq2Kp7Lm"
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
        // missing path
        let mut sec = secrets();
        sec.remove("vlessws.path");
        let ctx = RenderCtx::new(&s, &sec);
        assert!(VlessWs::new().share_link(&ctx, &user("a", "u")).is_err());
        // path with a slash (would break the route/transport agreement)
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
