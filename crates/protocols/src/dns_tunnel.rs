//! dns-tunnel protocol — companion to the `dns-tunnel` kernel.
//!
//! The `dns-tunnel` kernel (see `crates/kernels/src/dns_tunnel.rs`) is a
//! last-resort transport that tunnels TCP-over-DNS to НСДИ resolvers via
//! **slipstream-rust** (QUIC-over-DNS). It is the 4th fallback in the
//! stack, after VLESS+REALITY (TCP:443), TUIC (UDP:8443) and NAIVE
//! (caddy:443) — engaged only when РКН flips to white-list mode and rubs
//! out everything else. PoC proven + deployed standalone on box
//! 213.155.15.93 (2026-06-08); see `DNS-TUNNEL.md`.
//!
//! ## Two-process client (NOT a single sing-box outbound)
//!
//! Unlike VLESS / TUIC / Hysteria2, the dns-tunnel client is a **bundle
//! of two processes**, exactly mirroring the server side:
//!
//! ```text
//! [app] → SOCKS 127.0.0.1:1080 (sing-box mixed inbound)
//!          → VLESS outbound → 127.0.0.1:7001
//!            → slipstream-client (multipath: 195.208.4.1:53 + 195.208.5.1:53)
//!              → DNS queries <data>.<domain> → НСДИ resolvers → node:53
//! ```
//!
//! Because the wrapping is slipstream-client + a loopback VLESS — NOT a
//! single sing-box `outbound` object — this protocol's
//! [`Protocol::appears_in_sing_box_sub`] returns `false`. If we let a
//! `type: "dns-tunnel"` object slip into the `/sub` envelope, every
//! sing-box / Hiddify client fed the result refuses to start with
//! «unknown outbound type» (or worse, silently drops EVERY route,
//! including the working VLESS / TUIC ones). Same hard `false` as
//! `wgturn`.
//!
//! ## Share-link wire format
//!
//! ```text
//! dns-tunnel://<base64url-nopad(JSON{v:1, d, r, fp, uuid})>#<query-escaped-label>
//! ```
//!
//! Fields (all required — the two-process client can't start without
//! any of them):
//!   * `d`    — tunnel domain (the slipstream `-d` value; doubles as the
//!     QUIC SNI). Operator-set secret `dns-tunnel:domain`.
//!   * `r`    — multipath resolver list (`["195.208.4.1:53","195.208.5.1:53"]`),
//!     the slipstream-client `-r` flags. Operator-set secret
//!     `dns-tunnel:resolvers` (comma-separated); a vpnctl default of the
//!     two НСДИ resolvers applies when unset.
//!   * `fp`   — the node-auto-generated ECDSA-P256 leaf cert SHA-256
//!     fingerprint, for client-side cert pinning (the cert is
//!     self-signed → the pin replaces a CA). NOT a secret — it's a
//!     public pin. Operator-set secret `dns-tunnel:fingerprint`.
//!   * `uuid` — the wrapped loopback VLESS UUID. This is the single
//!     server-wide inbound UUID the kernel renders into
//!     `127.0.0.1:9001` (PoC `tunnel-singbox-server.json.tpl`
//!     `${TUNNEL_UUID}`). Minted server-side as the
//!     `dns-tunnel:loopback_uuid` secret (see
//!     [`Protocol::server_secret_specs`]), so the low-tech user imports
//!     a single artefact with nothing to fill in (CLAUDE.md north-star).
//!
//! Format version is `1`; an older client fails a newer version with
//! «unsupported version». The byte-shape is pinned by
//! `spec_dns_tunnel.rs` (cargo-mutants soft-fails on the protocols
//! crate, so an exact-bytes test is the regression net).
//!
//! ## server_inbound + client_config
//!
//! Both return a type-tagged marker (`{"type":"dns-tunnel"}`) — the
//! kernel renders the REAL loopback VLESS inbound + slipstream server
//! config itself (it owns BOTH systemd units); this protocol contributes
//! no sing-box-style inbound block. Trait-compliance stubs, same shape
//! as `wgturn`.
//!
//! Stateless, like every other Protocol in this crate.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

/// Format-version byte the dns-tunnel share-link carries under the `v`
/// key. Bumping requires a coordinated client + server change.
const FORMAT_VERSION: i32 = 1;

/// vpnctl default multipath resolver set — both НСДИ resolvers
/// (`195.208.4.1` / `195.208.5.1`), which stay reachable even under
/// РФ IP-whitelist mode (the whole reason this transport exists). Used
/// when the operator hasn't pinned `dns-tunnel:resolvers`. Multipath
/// over both gives ~246 KB/s vs ~78 KB/s single-resolver (DNS-TUNNEL.md
/// §2).
const DEFAULT_RESOLVERS: &str = "195.208.4.1:53,195.208.5.1:53";

/// Label-escape set for the `#<label>` fragment. Identical policy to
/// `wgturn`: the user-id alphabet is validated upstream as
/// `[A-Za-z0-9._-]+`, so the Go-interop-divergent characters (` `, `+`)
/// are unreachable; `utf8_percent_encode`'s `%20`-for-space is fine.
const LABEL: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[derive(Debug, Default)]
pub struct DnsTunnel;

impl DnsTunnel {
    pub fn new() -> Self {
        Self
    }
}

/// Build the JSON `wireFormat` payload. Field tags are short (`d`, `r`,
/// `fp`, `uuid`) to keep the encoded URL compact — one less character to
/// paste on a phone.
///
/// **Key order:** `serde_json::Value::Object` is a `BTreeMap` (the
/// `preserve_order` feature is NOT enabled in our workspace), so keys
/// serialise in lexicographic order — `d, fp, r, uuid, v` — NOT
/// declaration order. The byte-stability guarantee holds because
/// `BTreeMap` ordering is deterministic per key set. The two-process
/// client parser is field-order-insensitive (`serde`/`encoding-json`).
fn build_wire_format(domain: &str, resolvers: &[String], fingerprint: &str, uuid: &str) -> Value {
    json!({
        "v": FORMAT_VERSION,
        "d": domain,
        "r": resolvers,
        "fp": fingerprint,
        "uuid": uuid,
    })
}

/// Parse the comma-separated `dns-tunnel:resolvers` secret (or the
/// vpnctl default) into a trimmed, non-empty resolver list. Empty
/// entries (a trailing comma, doubled commas) are dropped; an
/// all-empty value falls back to NOTHING and is rejected by the caller
/// so a typo'd secret can't ship a resolver-less link the client can't
/// use.
fn parse_resolvers(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

impl Protocol for DnsTunnel {
    fn id(&self) -> ProtocolId {
        ProtocolId("dns-tunnel".to_string())
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // Moderate — NOT Strong. This is a last-resort transport whose
        // camouflage is "DNS queries to НСДИ resolvers". НСДИ is a
        // FIXED, MONITORED point: high stable QPS + long TXT records are
        // visible to ML detectors (DNS-TUNNEL.md §10), and РКН can close
        // the lane by rotating/restricting the resolvers. Acceptable
        // for break-glass use, not a daily driver — so don't oversell it
        // as Strong.
        vpnctl_core::DpiRisk::Moderate
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        // The client is a TWO-process bundle (slipstream-client +
        // loopback VLESS sing-box), NOT a single sing-box outbound. A
        // `type: "dns-tunnel"` object in the /sub envelope makes the
        // whole config unparseable → sing-box / Hiddify drops every
        // route (including the working VLESS / TUIC ones). Hard `false`,
        // same as wgturn.
        false
    }

    fn server_inbound(&self, _ctx: &RenderCtx<'_>, _users: &[User]) -> Result<serde_json::Value> {
        // The dns-tunnel kernel renders its OWN loopback VLESS inbound +
        // slipstream server config (it owns BOTH systemd units); this
        // protocol contributes no sing-box-style inbound block. The
        // kernel NEVER reads this value — it's a throwaway marker that
        // keeps the trait shape uniform without polluting any merged
        // config. Same approach as wgturn's `{"type":"wgturn"}`.
        Ok(json!({ "type": "dns-tunnel" }))
    }

    fn client_config(&self, _ctx: &RenderCtx<'_>, _user: &User) -> Result<serde_json::Value> {
        // Same reasoning — the client artefact is the `dns-tunnel://`
        // bundle URL (rendered by `share_link` below), not a single JSON
        // outbound. Trait-compliance stub.
        Ok(json!({ "type": "dns-tunnel" }))
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        // The wrapped loopback VLESS inbound UUID — a single server-wide
        // value the kernel renders into `127.0.0.1:9001` (PoC
        // `${TUNNEL_UUID}`) and the share-link embeds. Minted as a
        // url-safe random string consumed as an OPAQUE UUID by sing-box
        // → `Password` (NOT base64-decoded). 16 bytes of entropy is a
        // UUID's worth.
        //
        // `dns-tunnel:domain`, `dns-tunnel:resolvers`,
        // `dns-tunnel:fingerprint`, `dns-tunnel:forward_target` and
        // `dns-tunnel:engine` are operator-set PARAMS (the cert
        // fingerprint is the node-auto-generated ECDSA leaf's SHA-256,
        // captured by the operator after first run), so nothing to
        // mint for them. The ECDSA keypair is node-auto-generated by
        // slipstream on first start → NO crypto secret declared here.
        vec![vpnctl_core::ServerSecretSpec::Password {
            key: "dns-tunnel:loopback_uuid",
            entropy_bytes: 16,
        }]
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        // ── Tunnel domain (SNI) — operator-set, required. ─────────────
        let domain = ctx.secrets.get("dns-tunnel:domain").ok_or_else(|| {
            CoreError::Render(
                "dns-tunnel share_link: missing server secret \
                 `dns-tunnel:domain` — set the slipstream tunnel domain \
                 via /admin/servers/<id>/secrets"
                    .into(),
            )
        })?;

        // ── Cert fingerprint pin — operator-set, required. ────────────
        // The slipstream cert is self-signed ECDSA-P256 (auto-generated
        // node-side), so the SHA-256 fingerprint pin is what the client
        // trusts in lieu of a CA. It's a PIN, not a secret (DNS-TUNNEL.md
        // §12), but the share-link can't be emitted without it.
        let fingerprint = ctx.secrets.get("dns-tunnel:fingerprint").ok_or_else(|| {
            CoreError::Render(
                "dns-tunnel share_link: missing server secret \
                 `dns-tunnel:fingerprint` — capture the node's slipstream \
                 leaf-cert SHA-256 fingerprint and set it via \
                 /admin/servers/<id>/secrets"
                    .into(),
            )
        })?;

        // ── Wrapped loopback VLESS UUID — minted server secret. ───────
        let uuid = ctx.secrets.get("dns-tunnel:loopback_uuid").ok_or_else(|| {
            CoreError::Render(
                "dns-tunnel share_link: missing server secret \
                 `dns-tunnel:loopback_uuid` — mint via the add-server \
                 wizard, or visit /admin/servers/<id>/secrets to fix"
                    .into(),
            )
        })?;

        // ── Multipath resolver list — operator-set or vpnctl default. ─
        let resolvers_raw = ctx
            .secrets
            .get("dns-tunnel:resolvers")
            .map(String::as_str)
            .unwrap_or(DEFAULT_RESOLVERS);
        let resolvers = parse_resolvers(resolvers_raw);
        if resolvers.is_empty() {
            return Err(CoreError::Render(format!(
                "dns-tunnel share_link: `dns-tunnel:resolvers` {resolvers_raw:?} \
                 parsed to an empty list — must be a comma-separated \
                 `host:port` set (e.g. 195.208.4.1:53,195.208.5.1:53)"
            )));
        }

        let wire = build_wire_format(domain, &resolvers, fingerprint, uuid);
        let json_bytes = serde_json::to_vec(&wire)
            .map_err(|e| CoreError::Render(format!("dns-tunnel share_link: marshal: {e}")))?;
        let payload = URL_SAFE_NO_PAD.encode(&json_bytes);
        let label = utf8_percent_encode(&user.id.0, LABEL).to_string();
        Ok(format!("dns-tunnel://{payload}#{label}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use vpnctl_core::{KernelId, Server, ServerId, UserId};

    const FAKE_FP: &str = "47:1E:87:8F:3E:48:C8:1C:5F:BF:30:2E:B8:A8:3A:05:72:0D:B9:77:A2:11:81:09:E6:E5:EF:92:C4:66:7B:92";
    const FAKE_UUID: &str = "e09b09af-2500-4753-b219-937ce13b5257";

    fn dummy_user() -> User {
        User {
            id: UserId("alex".into()),
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some("st".into()),
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn dummy_server() -> Server {
        Server {
            id: ServerId("dns-tunnel-node".into()),
            address: "203.0.113.42".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("dns-tunnel".into())],
            enabled_protocols: vec![ProtocolId("dns-tunnel".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn secrets_complete() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("dns-tunnel:domain".into(), "t.example.com".into());
        m.insert("dns-tunnel:fingerprint".into(), FAKE_FP.into());
        m.insert("dns-tunnel:loopback_uuid".into(), FAKE_UUID.into());
        m
    }

    #[test]
    fn id_returns_dns_tunnel() {
        assert_eq!(DnsTunnel::new().id(), ProtocolId("dns-tunnel".into()));
    }

    #[test]
    fn dpi_risk_is_moderate_not_strong() {
        assert_eq!(DnsTunnel::new().dpi_risk(), vpnctl_core::DpiRisk::Moderate);
    }

    #[test]
    fn appears_in_sing_box_sub_is_false() {
        assert!(!DnsTunnel::new().appears_in_sing_box_sub());
    }

    #[test]
    fn server_inbound_returns_marker() {
        let server = dummy_server();
        let secrets = secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let v = DnsTunnel::new().server_inbound(&ctx, &[]).unwrap();
        assert_eq!(v["type"], "dns-tunnel");
    }

    #[test]
    fn client_config_returns_marker() {
        let server = dummy_server();
        let secrets = secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let v = DnsTunnel::new().client_config(&ctx, &dummy_user()).unwrap();
        assert_eq!(v["type"], "dns-tunnel");
    }

    #[test]
    fn server_secret_specs_declares_only_loopback_uuid() {
        let specs = DnsTunnel::new().server_secret_specs();
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0],
            vpnctl_core::ServerSecretSpec::Password {
                key: "dns-tunnel:loopback_uuid",
                entropy_bytes: 16,
            }
        );
    }

    #[test]
    fn share_link_scheme_and_default_resolvers() {
        let server = dummy_server();
        let secrets = secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let link = DnsTunnel::new().share_link(&ctx, &dummy_user()).unwrap();
        assert!(link.starts_with("dns-tunnel://"), "scheme: {link}");
        let payload = link
            .strip_prefix("dns-tunnel://")
            .unwrap()
            .split('#')
            .next()
            .unwrap();
        let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["d"], "t.example.com");
        assert_eq!(v["fp"], FAKE_FP);
        assert_eq!(v["uuid"], FAKE_UUID);
        assert_eq!(
            v["r"],
            serde_json::json!(["195.208.4.1:53", "195.208.5.1:53"])
        );
    }

    #[test]
    fn share_link_label_fragment_carries_user_id() {
        let server = dummy_server();
        let secrets = secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let link = DnsTunnel::new().share_link(&ctx, &dummy_user()).unwrap();
        assert!(link.ends_with("#alex"), "label lost: {link}");
    }

    #[test]
    fn share_link_honours_resolver_override() {
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert(
            "dns-tunnel:resolvers".into(),
            " 8.8.8.8:53 , 1.1.1.1:53 ".into(),
        );
        let ctx = RenderCtx::new(&server, &secrets);
        let link = DnsTunnel::new().share_link(&ctx, &dummy_user()).unwrap();
        let payload = link
            .strip_prefix("dns-tunnel://")
            .unwrap()
            .split('#')
            .next()
            .unwrap();
        let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        // Trimmed + split; whitespace around commas dropped.
        assert_eq!(v["r"], serde_json::json!(["8.8.8.8:53", "1.1.1.1:53"]));
    }

    #[test]
    fn share_link_byte_stable_across_runs() {
        let server = dummy_server();
        let secrets = secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let a = DnsTunnel::new().share_link(&ctx, &dummy_user()).unwrap();
        let b = DnsTunnel::new().share_link(&ctx, &dummy_user()).unwrap();
        assert_eq!(a, b, "share_link is not byte-stable");
    }

    #[test]
    fn share_link_errors_when_domain_missing() {
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.remove("dns-tunnel:domain");
        let ctx = RenderCtx::new(&server, &secrets);
        let err = DnsTunnel::new()
            .share_link(&ctx, &dummy_user())
            .unwrap_err();
        assert!(format!("{err}").contains("dns-tunnel:domain"));
    }

    #[test]
    fn share_link_errors_when_fingerprint_missing() {
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.remove("dns-tunnel:fingerprint");
        let ctx = RenderCtx::new(&server, &secrets);
        let err = DnsTunnel::new()
            .share_link(&ctx, &dummy_user())
            .unwrap_err();
        assert!(format!("{err}").contains("dns-tunnel:fingerprint"));
    }

    #[test]
    fn share_link_errors_when_uuid_missing() {
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.remove("dns-tunnel:loopback_uuid");
        let ctx = RenderCtx::new(&server, &secrets);
        let err = DnsTunnel::new()
            .share_link(&ctx, &dummy_user())
            .unwrap_err();
        assert!(format!("{err}").contains("dns-tunnel:loopback_uuid"));
    }

    #[test]
    fn share_link_errors_when_resolvers_empty() {
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert("dns-tunnel:resolvers".into(), " , , ".into());
        let ctx = RenderCtx::new(&server, &secrets);
        let err = DnsTunnel::new()
            .share_link(&ctx, &dummy_user())
            .unwrap_err();
        assert!(format!("{err}").contains("dns-tunnel:resolvers"));
    }
}
