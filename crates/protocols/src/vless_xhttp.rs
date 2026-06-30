//! VLESS + REALITY + xhttp — served by the `xray` kernel (Xray-core).
//!
//! ## Why this exists
//!
//! sing-box has NO server-side xhttp inbound — only sing-box-lx's
//! CLIENT-side outbound supports it (see `option/v2ray_xhttp.go` in that
//! fork). Xray-core is the only daemon that serves xhttp server-side, so
//! this protocol is paired with the standalone `xray` kernel rather than
//! `sing-box`. See plans/xray-xhttp.md for the full design rationale.
//!
//! ## Port
//!
//! 9443/TCP, standalone — grep-verified unclaimed by any other protocol
//! in this codebase, and distinct from both 443 (sing-box vless+reality)
//! and 8443 (double-claimed on the `is` pilot node: caddy/vless-ws TCP +
//! sing-box tuic-v5 UDP). A static `pub const`, not a `vlessxhttp.
//! listen_port` secret — unlike `vless+reality`, this protocol has no
//! known co-tenant port conflict to dodge (the configurable-port idiom
//! exists there for legacy 3x-ui coexistence specifically), so there's
//! nothing to buy with the extra indirection today. See
//! [`VLESS_XHTTP_PORT`].
//!
//! ## REALITY keypair — REUSED, not separately minted
//!
//! [`server_secret_specs`](Protocol::server_secret_specs) returns only
//! the `vlessxhttp.path` secret. It deliberately does NOT declare
//! `vless.private_key` / `vless.public_key` / `vless.short_id` — those
//! are reused from whatever `vless+reality` already minted on the same
//! server, so the operator never has to think about "the REALITY pubkey"
//! as more than one value per node. **Consequence**: if `vless+xhttp` is
//! ever enabled on a server where `vless+reality` is NOT also enabled,
//! nothing has minted those keys, and [`server_inbound`]/[`client_config`]/
//! [`share_link`] fail loudly with `CoreError::MissingSecret` at render
//! time — the same established failure mode every other secret-reusing
//! protocol in this crate already has (e.g. `trojan`/`anytls` reusing
//! `tuic.cert_path`). No pre-flight UX guard ships for the pilot (single
//! hand-picked node, single operator) — confirmed with Pavel 2026-06-30.
//!
//! ## No `flow`
//!
//! XTLS-Vision (`flow=xtls-rprx-vision`) requires a raw TLS record
//! stream; xhttp HTTP-frames the connection instead, so `flow` is absent
//! everywhere in this file — server inbound, client outbound, and
//! share-link. This is the one structural difference from
//! `vless_reality.rs` that every test in this file's companion spec
//! exists to pin.
//!
//! **Stateless**, like every other Protocol in this crate.

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

use crate::vless_reality::DEFAULT_REALITY_SNI;

/// Listen port. Standalone, grep-verified unclaimed fleet-wide as of
/// 2026-06-30 (see this module's doc comment). Public so the admin
/// drift-detector and tests can reference it without duplicating the
/// literal.
pub const VLESS_XHTTP_PORT: u16 = 9443;

/// uTLS ClientHello fingerprint for the REALITY handshake under xhttp.
///
/// Deliberately a SEPARATE constant from `vless_reality::REALITY_UTLS_FP`
/// rather than importing it (that constant is crate-private to
/// `vless_reality.rs`, and re-exposing it would mean editing an existing
/// file beyond this protocol's two-new-files footprint — this crate's
/// established convention at this kind of boundary is small duplication
/// over coupling; see `wgturn.rs`'s duplicated `WGTURN_PORT`).
///
/// Set to match `vless_reality`'s current value (`"randomized"`, switched
/// 2026-06-16 — RU TSPU fingerprints the static Chrome uTLS ClientHello).
/// **UNVERIFIED for xhttp specifically**: xhttp HTTP-frames the handshake
/// differently from raw-TCP REALITY, so it is not confirmed TSPU
/// fingerprints it by the same rule. Flagged in plans/xray-xhttp.md §11
/// for live RU verification alongside the client-session format sign-off;
/// change this constant if that test shows xhttp needs different tuning.
const XHTTP_UTLS_FP: &str = "randomized";

/// Default xhttp transport mode when `vlessxhttp.mode` is unset. `auto`
/// is Xray-core's own default (currently behaves as `stream-one`) and
/// requires no client-side coordination — sing-box-lx and Xray-core both
/// accept it without the operator picking a specific mode.
const DEFAULT_XHTTP_MODE: &str = "auto";

/// Set of bytes percent-encoded in the `#<name>` URL fragment (RFC 3986).
/// Mirrors `vless_reality.rs` / `vless_ws.rs`.
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

#[derive(Debug, Default)]
pub struct VlessXhttp;

impl VlessXhttp {
    pub fn new() -> Self {
        Self
    }
}

/// `RenderCtx::require("vlessxhttp.path")` + reject anything outside the
/// URL-path-safe `[A-Za-z0-9_-]` charset. The secret is bootstrap-minted
/// as url-safe base64 (so it always matches), but a hand-set value
/// carrying `/`, `?`, `#`, whitespace or a control char would corrupt
/// both the Xray `xhttpSettings.path` and the `path=` share-link query.
/// Mirrors `vless_ws.rs::checked_path` exactly.
fn checked_path<'a>(ctx: &'a RenderCtx<'_>) -> Result<&'a str> {
    let path = ctx.require("vlessxhttp.path")?;
    if path.is_empty()
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(CoreError::Render(format!(
            "vlessxhttp.path must be a non-empty [A-Za-z0-9_-] string (url-safe-base64 \
             minted by bootstrap); got {path:?}"
        )));
    }
    Ok(path)
}

/// `RenderCtx::or_default("vlessxhttp.mode", DEFAULT_XHTTP_MODE)` + reject
/// anything outside Xray-core's known xhttp transport modes. Without this,
/// an operator-set value could carry `&`/`#`/`%` and corrupt the
/// `share_link` query string (review-agent finding 2026-06-30); validating
/// here also turns a bad value into a render-time error naming the secret
/// key, instead of an opaque `xray run -test` failure at apply time.
fn checked_mode<'a>(ctx: &'a RenderCtx<'_>) -> Result<&'a str> {
    let mode = ctx.or_default("vlessxhttp.mode", DEFAULT_XHTTP_MODE);
    match mode {
        "auto" | "packet-up" | "stream-up" | "stream-one" => Ok(mode),
        _ => Err(CoreError::Render(format!(
            "vlessxhttp.mode must be one of auto/packet-up/stream-up/stream-one \
             (Xray-core's known xhttp transport modes); got {mode:?}"
        ))),
    }
}

impl Protocol for VlessXhttp {
    fn id(&self) -> ProtocolId {
        ProtocolId("vless+xhttp".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", VLESS_XHTTP_PORT)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // Same REALITY active-probe defence as vless+reality and wgturn
        // (NM-12's two existing Strong-tier protocols): an unauthenticated
        // probe gets transparently forwarded to the real `dest:` upstream,
        // indistinguishable from a genuine visitor. xhttp's HTTP-framing
        // adds a layer that mimics ordinary HTTP/2-3 traffic on top of
        // REALITY's TLS cover — never weaker camouflage than plain
        // vision+TCP.
        vpnctl_core::DpiRisk::Strong
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        // Deliberately does NOT declare vless.private_key / public_key /
        // short_id — those are REUSED from vless+reality's mint. See this
        // module's doc comment for the consequence when reality isn't
        // enabled on the same server.
        vec![vpnctl_core::ServerSecretSpec::Password {
            key: "vlessxhttp.path",
            entropy_bytes: 16,
        }]
    }

    /// Xray-core inbound JSON. Field names verified against
    /// `XTLS/Xray-core`'s `infra/conf/vless.go` + `infra/conf/
    /// transport_internet.go` source 2026-06-30 — NOT a copy-paste of
    /// sing-box's shape, which uses different keys (`uuid`/`name` vs
    /// Xray's `id`/`email`; sing-box's `listen_port` vs Xray's `port`
    /// nested differently).
    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let private_key = ctx.require("vless.private_key")?;
        let short_id = ctx.require("vless.short_id")?;
        // `vless.sni` is expected to be a BARE hostname (no port) — it's
        // joined into a single "host:443" `dest` string below, unlike
        // sing-box's split `handshake.{server,server_port}` fields, so a
        // value already carrying a port would double up. Same implicit
        // contract `vless_reality.rs` relies on for this secret.
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let path = checked_path(ctx)?;
        let mode = checked_mode(ctx)?;

        // Xray client entries: "id" + "email" (NOT sing-box's "uuid" +
        // "name"). No "flow" — incompatible with xhttp transport.
        let clients_json: Vec<_> = users
            .iter()
            .map(|u| json!({ "id": u.uuid, "email": u.id.0 }))
            .collect();

        Ok(json!({
            "listen": "0.0.0.0",
            "port": VLESS_XHTTP_PORT,
            "protocol": "vless",
            "settings": {
                "clients": clients_json,
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "xhttpSettings": {
                    "path": format!("/{path}"),
                    "mode": mode
                },
                "realitySettings": {
                    "dest": format!("{sni}:443"),
                    "serverNames": [sni],
                    "privateKey": private_key,
                    "shortIds": [short_id]
                }
            }
        }))
    }

    /// sing-box-lx-compatible outbound JSON. Transport type/field names
    /// (`type":"xhttp"`, snake_case `path`/`mode`) verified against
    /// `Leadaxe/sing-box-lx`'s `option/v2ray_xhttp.go` +
    /// `constant/v2ray.go` source 2026-06-30 — this IS the client the
    /// operator's VPNRouter app embeds (see plans/xray-xhttp.md §2).
    /// `tls.reality`/`tls.utls` shape is unchanged from
    /// `vless_reality.rs` (the fork adds xhttp/AWG2 transport, not a
    /// REALITY change).
    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let public_key = ctx.require("vless.public_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let path = checked_path(ctx)?;
        let mode = checked_mode(ctx)?;

        Ok(json!({
            "type": "vless",
            "tag": "vless-xhttp-out",
            "server": ctx.server.address,
            "server_port": VLESS_XHTTP_PORT,
            "uuid": user.uuid,
            "tls": {
                "enabled": true,
                "server_name": sni,
                "utls": { "enabled": true, "fingerprint": XHTTP_UTLS_FP },
                "reality": {
                    "enabled": true,
                    "public_key": public_key,
                    "short_id": short_id
                }
            },
            "transport": {
                "type": "xhttp",
                "path": format!("/{path}"),
                "mode": mode
            }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let public_key = ctx.require("vless.public_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let path = checked_path(ctx)?;
        let mode = checked_mode(ctx)?;
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);

        // No `flow=` (xhttp/Vision are mutually exclusive — see module
        // doc comment). Param set/order otherwise mirrors
        // `vless_reality.rs::share_link`'s style for this protocol
        // family; there is no legacy bash link to match byte-for-byte
        // (xhttp has no bash-era predecessor).
        Ok(format!(
            "vless://{uuid}@{addr}:{port}?encryption=none&security=reality&sni={sni}&fp={fp}&pbk={pbk}&sid={sid}&type=xhttp&path=%2F{path}&mode={mode}#{name}",
            uuid = user.uuid,
            addr = host_for_url(&ctx.server.address),
            port = VLESS_XHTTP_PORT,
            fp = XHTTP_UTLS_FP,
            pbk = public_key,
            sid = short_id,
            sni = sni,
            path = path,
            mode = mode,
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

    fn dummy_server() -> Server {
        Server {
            id: ServerId("xray-node-1".into()),
            address: "203.0.113.9".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("xray".into())],
            enabled_protocols: vec![ProtocolId("vless+xhttp".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn full_secrets() -> HashMap<String, String> {
        let mut s = HashMap::new();
        s.insert("vless.private_key".into(), "priv-key-material".into());
        s.insert("vless.public_key".into(), "pub-key-material".into());
        s.insert("vless.short_id".into(), "deadbeef".into());
        s.insert("vlessxhttp.path".into(), "Ab3x9Zq2Kp7Lm".into());
        s
    }

    fn user(name: &str) -> User {
        User {
            id: UserId(name.into()),
            uuid: format!("uuid-{name}"),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    #[test]
    fn id_and_port_and_dpi_tier() {
        let p = VlessXhttp::new();
        assert_eq!(p.id(), ProtocolId("vless+xhttp".into()));
        assert_eq!(p.listen_ports(), &[("tcp", 9443)]);
        assert_eq!(p.dpi_risk(), vpnctl_core::DpiRisk::Strong);
    }

    #[test]
    fn secret_specs_mints_only_path_not_reality_keypair() {
        let specs = VlessXhttp::new().server_secret_specs();
        assert_eq!(specs.len(), 1, "must mint exactly one secret: {specs:?}");
        match &specs[0] {
            vpnctl_core::ServerSecretSpec::Password { key, entropy_bytes } => {
                assert_eq!(*key, "vlessxhttp.path");
                assert_eq!(*entropy_bytes, 16);
            }
            other => panic!("expected Password spec, got {other:?}"),
        }
    }

    #[test]
    fn server_inbound_missing_vless_secret_fails_loud() {
        let s = dummy_server();
        let mut secrets = HashMap::new();
        secrets.insert("vlessxhttp.path".into(), "Ab3x9Zq2Kp7Lm".into());
        let ctx = RenderCtx::new(&s, &secrets);
        let err = VlessXhttp::new()
            .server_inbound(&ctx, &[user("alice")])
            .unwrap_err();
        match err {
            CoreError::MissingSecret { key, .. } => assert_eq!(key, "vless.private_key"),
            other => panic!("expected MissingSecret, got {other:?}"),
        }
    }

    #[test]
    fn server_inbound_happy_path_has_no_flow_field() {
        let s = dummy_server();
        let secrets = full_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let inbound = VlessXhttp::new()
            .server_inbound(&ctx, &[user("alice")])
            .unwrap();
        assert_eq!(inbound["protocol"], "vless");
        assert_eq!(inbound["port"], 9443);
        assert_eq!(inbound["streamSettings"]["network"], "xhttp");
        assert_eq!(inbound["streamSettings"]["security"], "reality");
        assert_eq!(
            inbound["streamSettings"]["xhttpSettings"]["path"],
            "/Ab3x9Zq2Kp7Lm"
        );
        assert_eq!(
            inbound["streamSettings"]["realitySettings"]["dest"],
            "yahoo.com:443"
        );
        let client = &inbound["settings"]["clients"][0];
        assert_eq!(client["id"], "uuid-alice");
        assert_eq!(client["email"], "alice");
        assert!(
            client.get("flow").is_none(),
            "xhttp clients must NOT carry a flow field: {client:?}"
        );
    }

    #[test]
    fn client_config_has_no_flow_field() {
        let s = dummy_server();
        let secrets = full_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let cfg = VlessXhttp::new()
            .client_config(&ctx, &user("alice"))
            .unwrap();
        assert_eq!(cfg["type"], "vless");
        assert_eq!(cfg["transport"]["type"], "xhttp");
        assert_eq!(cfg["transport"]["path"], "/Ab3x9Zq2Kp7Lm");
        assert_eq!(cfg["transport"]["mode"], "auto");
        assert!(
            cfg.get("flow").is_none(),
            "xhttp outbound must NOT carry a flow field: {cfg:?}"
        );
    }

    #[test]
    fn share_link_format_has_no_flow_param() {
        let s = dummy_server();
        let secrets = full_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let link = VlessXhttp::new().share_link(&ctx, &user("alice")).unwrap();
        assert_eq!(
            link,
            "vless://uuid-alice@203.0.113.9:9443?encryption=none&security=reality&sni=yahoo.com&fp=randomized&pbk=pub-key-material&sid=deadbeef&type=xhttp&path=%2FAb3x9Zq2Kp7Lm&mode=auto#alice"
        );
        assert!(
            !link.contains("flow="),
            "xhttp share-link must NOT contain a flow param: {link}"
        );
    }

    #[test]
    fn share_link_mode_override() {
        let s = dummy_server();
        let mut secrets = full_secrets();
        secrets.insert("vlessxhttp.mode".into(), "stream-up".into());
        let ctx = RenderCtx::new(&s, &secrets);
        let link = VlessXhttp::new().share_link(&ctx, &user("alice")).unwrap();
        assert!(link.contains("mode=stream-up"));
    }

    #[test]
    fn share_link_byte_stable_across_runs() {
        let s = dummy_server();
        let secrets = full_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let a = VlessXhttp::new().share_link(&ctx, &user("alice")).unwrap();
        let b = VlessXhttp::new().share_link(&ctx, &user("alice")).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn checked_mode_rejects_unknown_values() {
        let s = dummy_server();
        let mut secrets = full_secrets();
        secrets.insert("vlessxhttp.mode".into(), "custom-injected&mode".into());
        let ctx = RenderCtx::new(&s, &secrets);
        let err = VlessXhttp::new()
            .share_link(&ctx, &user("alice"))
            .unwrap_err();
        assert!(matches!(err, CoreError::Render(_)));
    }

    #[test]
    fn checked_path_rejects_illegal_chars() {
        let s = dummy_server();
        let mut secrets = full_secrets();
        secrets.insert("vlessxhttp.path".into(), "has a space".into());
        let ctx = RenderCtx::new(&s, &secrets);
        let err = VlessXhttp::new()
            .share_link(&ctx, &user("alice"))
            .unwrap_err();
        assert!(matches!(err, CoreError::Render(_)));
    }
}
