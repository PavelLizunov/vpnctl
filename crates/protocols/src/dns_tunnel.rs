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
//! dns-tunnel://<base64url-nopad(JSON{v, d, r, fp, uuid, cert?, auth?})>#<query-escaped-label>
//! ```
//!
//! Fields:
//!   * `v`    — format version. `1` (no `cert`) or `2` (with `cert`); see
//!     the versioning note below. Required. NOTE: `auth` (below) is
//!     INDEPENDENT of `v` — adding `auth` does NOT change the version; its
//!     presence is signalled by the field itself.
//!   * `d`    — tunnel domain (the slipstream `-d` value; doubles as the
//!     QUIC SNI). Operator-set secret `dns-tunnel:domain`. Required.
//!   * `r`    — multipath resolver list (`["195.208.4.1:53","195.208.5.1:53"]`),
//!     the slipstream-client `-r` flags. Operator-set secret
//!     `dns-tunnel:resolvers` (comma-separated); a vpnctl default of the
//!     two НСДИ resolvers applies when unset. Required. ALWAYS present —
//!     it's the censorship-network fallback path, NEVER removed or gated
//!     by the presence of `auth`.
//!   * `fp`   — the node-auto-generated ECDSA-P256 leaf cert SHA-256
//!     fingerprint, for client-side cert pinning / display (the cert is
//!     self-signed → the pin replaces a CA). NOT a secret — it's a
//!     public pin. Operator-set secret `dns-tunnel:fingerprint`. Required.
//!   * `uuid` — the wrapped loopback VLESS UUID. This is the USER'S OWN
//!     per-user identity (`User.uuid`) — the SAME UUID they already
//!     carry for VLESS-REALITY — reusing the standard vpnctl user model
//!     instead of a single shared server-wide secret. The kernel renders
//!     every granted user's `User.uuid` into the loopback VLESS inbound's
//!     `users[]` at `127.0.0.1:9001` (see
//!     `crates/kernels/src/dns_tunnel.rs`), so the link authenticates as
//!     that specific user through the tunnel. The historical server-wide
//!     `dns-tunnel:loopback_uuid` secret (PoC `${TUNNEL_UUID}`) survives
//!     only as the kernel's optional backward-compat fallback entry. The
//!     low-tech user still imports a single artefact with nothing to fill
//!     in (CLAUDE.md north-star). Required.
//!   * `cert` — OPTIONAL. The FULL server leaf certificate in PEM
//!     (`-----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----`,
//!     multi-line, the `\n` line breaks survive JSON as an escaped
//!     string). Present ONLY when the operator has set the
//!     `dns-tunnel:cert_pem` secret. `slipstream-client` pins the
//!     self-signed cert with `--cert <leaf.pem>` (a FULL PEM file) —
//!     it has NO `--pin <hash>` flag — so the SHA-256 `fp` alone is NOT
//!     consumable by the client. The client writes `cert` to a temp file
//!     and passes `--cert <that file>`. When `cert` is present the
//!     profile is fully self-contained (the client needs no out-of-band
//!     PEM). `fp` stays alongside `cert` for human verification / display.
//!   * `auth` — OPTIONAL. The AUTHORITATIVE DNS endpoint(s) the box binds
//!     directly (`213.155.15.93:53`), so an r6+ client can run
//!     `slipstream-client --authoritative <auth>` and bypass the recursive
//!     НСДИ resolvers entirely (the recursor drops the covert-DNS stream
//!     after a few minutes — see `plans/dns-tunnel-server-side-2026-06-11.md`).
//!     Present ONLY when the operator has set the `dns-tunnel:authoritative`
//!     secret. Value semantics mirror the secret: a SINGLE `host:port`
//!     emits `auth` as a JSON STRING; a comma-separated MULTI value emits
//!     `auth` as a JSON ARRAY of strings (the client accepts string OR
//!     array). The authoritative path is fast + stable but NOT
//!     whitelist/DPI-resistant (DNS goes straight to the box IP) — `r`
//!     stays the censorship fallback. `auth` is INDEPENDENT of `v`: it does
//!     NOT bump the version; its presence alone signals the capability.
//!
//! ### Versioning
//!
//! Backward-compat is decided by FIELD PRESENCE, with `v` as a redundant
//! signal:
//!   * `dns-tunnel:cert_pem` UNSET → output is byte-identical to the
//!     historical link: `{d, fp, r, uuid, v:1}`, NO `cert` field. Pre-cert
//!     consumers keep working unchanged.
//!   * `dns-tunnel:cert_pem` SET → `v` is bumped to `2` AND the `cert`
//!     field is added. A consumer can detect cert-carrying links by EITHER
//!     `v == 2` OR the presence of `cert` (both signal the same thing).
//!   * `dns-tunnel:authoritative` is ORTHOGONAL to the version: setting it
//!     adds an `auth` field but does NOT touch `v` (a cert-less link with
//!     `auth` is still `v:1`; a cert-carrying link with `auth` is still
//!     `v:2`). A consumer detects the authoritative capability purely by
//!     the presence of `auth`, not by `v`.
//!
//! Format version is pinned by `spec_dns_tunnel.rs` (cargo-mutants
//! soft-fails on the protocols crate, so an exact-bytes test is the
//! regression net).
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

/// Format-version byte for a cert-LESS dns-tunnel share-link (the
/// historical shape `{d, fp, r, uuid, v:1}`). Emitted when the
/// `dns-tunnel:cert_pem` secret is absent — byte-identical to the
/// pre-cert link so existing consumers don't break.
const FORMAT_VERSION_NO_CERT: i32 = 1;

/// Format-version byte for a cert-CARRYING dns-tunnel share-link (adds
/// the optional `cert` field with the full leaf PEM). Emitted ONLY when
/// the `dns-tunnel:cert_pem` secret is set. Consumers can detect the
/// richer shape by EITHER `v == 2` OR the presence of `cert`.
const FORMAT_VERSION_WITH_CERT: i32 = 2;

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
/// serialise in lexicographic order — `auth, cert, d, fp, r, uuid, v` —
/// NOT insertion order. The byte-stability guarantee holds because
/// `BTreeMap` ordering is deterministic per key set. The two-process
/// client parser is field-order-insensitive (`serde`/`encoding-json`).
///
/// `cert_pem` is the OPTIONAL full leaf-cert PEM. When `Some`, the
/// payload gains a `cert` field (the full PEM, line breaks preserved as
/// `\n` through JSON) AND `v` becomes `2`; when `None` the output is
/// byte-identical to the historical `v:1` link (no `cert` field) for
/// backward compatibility.
///
/// `auth` is the OPTIONAL authoritative-endpoint value, already shaped by
/// [`parse_authoritative`] as a JSON STRING (single `host:port`) or a
/// JSON ARRAY of strings (comma-separated multi). When `Some`, the
/// payload gains an `auth` field; when `None` the field is omitted. `auth`
/// is INDEPENDENT of `v` — it never changes the version byte; only `cert`
/// drives `v`. (`r` is emitted UNCONDITIONALLY regardless of `auth`.)
fn build_wire_format(
    domain: &str,
    resolvers: &[String],
    fingerprint: &str,
    uuid: &str,
    cert_pem: Option<&str>,
    auth: Option<Value>,
) -> Value {
    // Version is driven ONLY by cert presence (auth is orthogonal).
    let version = if cert_pem.is_some() {
        FORMAT_VERSION_WITH_CERT
    } else {
        FORMAT_VERSION_NO_CERT
    };
    // Build via the BTreeMap-backed Object so keys stay lexicographic
    // (`auth, cert, d, fp, r, uuid, v`) and the output is byte-stable.
    let mut obj = serde_json::Map::new();
    obj.insert("v".into(), json!(version));
    obj.insert("d".into(), json!(domain));
    obj.insert("r".into(), json!(resolvers));
    obj.insert("fp".into(), json!(fingerprint));
    obj.insert("uuid".into(), json!(uuid));
    if let Some(cert) = cert_pem {
        obj.insert("cert".into(), json!(cert));
    }
    if let Some(auth) = auth {
        obj.insert("auth".into(), auth);
    }
    Value::Object(obj)
}

/// Parse the OPTIONAL `dns-tunnel:authoritative` secret into the `auth`
/// field value, or `None` when the secret is absent / blank. Mirrors
/// [`parse_resolvers`]'s comma-split-and-trim discipline:
///   * a SINGLE non-empty `host:port` → a JSON STRING (`"213…:53"`);
///   * MULTIPLE comma-separated entries → a JSON ARRAY of strings;
///   * an all-empty value (typo'd `" , "`) → `None`, treated as absent so
///     a cleared secret can't ship an empty/garbage `auth`.
///
/// The client accepts either string or array, so the string form keeps
/// the common single-endpoint link compact.
fn parse_authoritative(raw: &str) -> Option<Value> {
    let endpoints: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    match endpoints.as_slice() {
        [] => None,
        [single] => Some(json!(single)),
        _ => Some(json!(endpoints)),
    }
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
        // The wrapped loopback VLESS inbound's OPTIONAL admin/fallback
        // UUID — the historical single server-wide value (PoC
        // `${TUNNEL_UUID}`, live on box 213). Post per-user-UUID it is no
        // longer the primary auth path: the kernel renders every GRANTED
        // user's own `User.uuid` into `127.0.0.1:9001` and each user's
        // share-link embeds THEIR `User.uuid`. This secret is kept &
        // minted so (a) the live `e09b09af-…` deploy keeps working
        // byte-for-byte and (b) a server with zero granted users still has
        // one inbound entry. Minted as a url-safe random string consumed
        // as an OPAQUE UUID by sing-box → `Password` (NOT base64-decoded).
        // 16 bytes of entropy is a UUID's worth.
        //
        // `dns-tunnel:domain`, `dns-tunnel:resolvers`,
        // `dns-tunnel:fingerprint`, `dns-tunnel:cert_pem`,
        // `dns-tunnel:forward_target` and `dns-tunnel:engine` are
        // operator-set PARAMS (the cert fingerprint is the
        // node-auto-generated ECDSA leaf's SHA-256, and `cert_pem` is the
        // full leaf-cert PEM, both captured by the operator after first
        // run), so nothing to mint for them. The ECDSA keypair is
        // node-auto-generated by slipstream on first start → NO crypto
        // secret declared here.
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

        // ── Wrapped loopback VLESS UUID — the user's OWN identity. ────
        // Per-user: embed `user.uuid` (the SAME UUID this user already
        // carries for VLESS-REALITY), not the shared server-wide
        // `dns-tunnel:loopback_uuid` secret. The kernel renders every
        // granted user's `user.uuid` into the loopback VLESS inbound's
        // `users[]` (see `crates/kernels/src/dns_tunnel.rs`), so this link
        // authenticates as that specific user through the tunnel. The
        // shared `loopback_uuid` survives only as the kernel's optional
        // backward-compat fallback entry — the per-user link is the
        // correct primary path.
        let uuid = user.uuid.as_str();

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

        // ── Full leaf-cert PEM — operator-set, OPTIONAL. ──────────────
        // `slipstream-client` pins the self-signed cert with
        // `--cert <leaf.pem>` (a FULL PEM file; there is NO `--pin <hash>`
        // flag), so the SHA-256 `fp` alone is not consumable by the
        // client. When the operator has captured the node's leaf cert and
        // set `dns-tunnel:cert_pem`, embed the full PEM under `cert` so
        // the profile is self-contained (the client writes it to a temp
        // file and passes `--cert`). Absent → behave exactly as before
        // (no `cert`, `v:1`); setting it is a separate ops step.
        let cert_pem = ctx
            .secrets
            .get("dns-tunnel:cert_pem")
            .map(String::as_str)
            .filter(|s| !s.trim().is_empty());

        // ── Authoritative DNS endpoint(s) — operator-set, OPTIONAL. ───
        // When set, embed `auth` so an r6+ client can run
        // `slipstream-client --authoritative <auth>`, bypassing the
        // recursive НСДИ resolvers (which drop the covert-DNS stream after
        // a few minutes — see plans/dns-tunnel-server-side-2026-06-11.md).
        // A single `host:port` → STRING; comma-separated → ARRAY. The
        // authoritative path is fast + stable but NOT whitelist/DPI-proof
        // (DNS goes straight to the box IP), so `r` ALWAYS stays as the
        // censorship fallback. Absent → no `auth`, output unchanged. `auth`
        // does NOT change `v` (orthogonal to the cert version bump).
        let auth = ctx
            .secrets
            .get("dns-tunnel:authoritative")
            .map(String::as_str)
            .and_then(parse_authoritative);

        let wire = build_wire_format(domain, &resolvers, fingerprint, uuid, cert_pem, auth);
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
    /// A multi-line dummy leaf-cert PEM. The point is the BEGIN/END
    /// markers + embedded newlines survive base64url + JSON round-trip.
    const FAKE_CERT_PEM: &str =
        "-----BEGIN CERTIFICATE-----\nMIIBdummyLine1\nMIIBdummyLine2\n-----END CERTIFICATE-----\n";

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
        // Per-user UUID: the link carries the USER'S own uuid, NOT the
        // shared `dns-tunnel:loopback_uuid` secret (FAKE_UUID).
        assert_eq!(v["uuid"], dummy_user().uuid);
        assert_ne!(
            v["uuid"], FAKE_UUID,
            "must embed the per-user uuid, not the shared loopback secret"
        );
        assert_eq!(
            v["r"],
            serde_json::json!(["195.208.4.1:53", "195.208.5.1:53"])
        );
    }

    #[test]
    fn share_link_embeds_per_user_uuid_not_loopback_secret() {
        // The core per-user-identity contract: even with the shared
        // `dns-tunnel:loopback_uuid` secret present, the emitted link
        // carries `user.uuid` (the same UUID the user has for VLESS).
        let server = dummy_server();
        let secrets = secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let alice = dummy_user();
        let mut bob = dummy_user();
        bob.id = UserId("bob".into());
        bob.uuid = "22222222-2222-2222-2222-222222222222".into();

        let link_a = DnsTunnel::new().share_link(&ctx, &alice).unwrap();
        let link_b = DnsTunnel::new().share_link(&ctx, &bob).unwrap();

        let decode = |link: &str| -> serde_json::Value {
            let payload = link
                .strip_prefix("dns-tunnel://")
                .unwrap()
                .split('#')
                .next()
                .unwrap();
            let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
            serde_json::from_slice(&raw).unwrap()
        };
        assert_eq!(decode(&link_a)["uuid"], alice.uuid);
        assert_eq!(decode(&link_b)["uuid"], bob.uuid);
        // Two different users → two different embedded UUIDs.
        assert_ne!(decode(&link_a)["uuid"], decode(&link_b)["uuid"]);
        // And neither equals the shared loopback secret.
        assert_ne!(decode(&link_a)["uuid"], FAKE_UUID);
    }

    #[test]
    fn share_link_works_without_loopback_secret() {
        // share_link no longer depends on `dns-tunnel:loopback_uuid` — the
        // per-user uuid is its own identity. Removing that secret must NOT
        // break the link (regression guard for the old required-secret
        // behaviour).
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.remove("dns-tunnel:loopback_uuid");
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
        assert_eq!(v["uuid"], dummy_user().uuid);
    }

    #[test]
    fn share_link_embeds_full_cert_pem_when_secret_present() {
        // With `dns-tunnel:cert_pem` set the link carries the FULL PEM
        // under `cert` (so the client can write it to a temp file +
        // `--cert`), bumps `v` to 2, and STILL carries the per-user uuid
        // and the fingerprint.
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert("dns-tunnel:cert_pem".into(), FAKE_CERT_PEM.into());
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
        assert_eq!(v["v"], 2, "cert-carrying link bumps version to 2");
        assert_eq!(v["cert"], FAKE_CERT_PEM, "full PEM must round-trip");
        // BEGIN/END markers + newlines survive base64url + JSON.
        let cert = v["cert"].as_str().unwrap();
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert.contains("-----END CERTIFICATE-----"));
        assert!(cert.contains('\n'), "PEM line breaks must survive");
        // uuid is still the per-user identity; fp still present.
        assert_eq!(v["uuid"], dummy_user().uuid);
        assert_eq!(v["fp"], FAKE_FP);
    }

    #[test]
    fn share_link_without_cert_pem_is_unchanged_v1() {
        // Backward-compat: absent `dns-tunnel:cert_pem` → no `cert` field,
        // v stays 1, fp present — byte-identical to the historical link.
        let server = dummy_server();
        let secrets = secrets_complete();
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
        assert_eq!(v["v"], 1);
        assert!(v.get("cert").is_none(), "no cert field when secret unset");
        assert_eq!(v["fp"], FAKE_FP, "fp stays present");
    }

    #[test]
    fn share_link_blank_cert_pem_treated_as_absent() {
        // A whitespace-only secret must NOT flip the link to v2 with an
        // empty cert — treat it as absent (defensive against a cleared
        // secret left as "" / "  ").
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert("dns-tunnel:cert_pem".into(), "   \n  ".into());
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
        assert_eq!(v["v"], 1);
        assert!(v.get("cert").is_none());
    }

    #[test]
    fn share_link_two_users_share_cert_distinct_uuid() {
        // Two granted users → same cert + domain (server-wide), distinct
        // per-user uuid.
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert("dns-tunnel:cert_pem".into(), FAKE_CERT_PEM.into());
        let ctx = RenderCtx::new(&server, &secrets);
        let alice = dummy_user();
        let mut bob = dummy_user();
        bob.id = UserId("bob".into());
        bob.uuid = "22222222-2222-2222-2222-222222222222".into();

        let decode = |link: &str| -> serde_json::Value {
            let payload = link
                .strip_prefix("dns-tunnel://")
                .unwrap()
                .split('#')
                .next()
                .unwrap();
            let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
            serde_json::from_slice(&raw).unwrap()
        };
        let va = decode(&DnsTunnel::new().share_link(&ctx, &alice).unwrap());
        let vb = decode(&DnsTunnel::new().share_link(&ctx, &bob).unwrap());
        assert_eq!(va["cert"], FAKE_CERT_PEM);
        assert_eq!(vb["cert"], FAKE_CERT_PEM);
        assert_eq!(va["d"], vb["d"]);
        assert_ne!(va["uuid"], vb["uuid"]);
        assert_eq!(va["uuid"], alice.uuid);
        assert_eq!(vb["uuid"], bob.uuid);
    }

    #[test]
    fn share_link_with_cert_is_byte_stable() {
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert("dns-tunnel:cert_pem".into(), FAKE_CERT_PEM.into());
        let ctx = RenderCtx::new(&server, &secrets);
        let a = DnsTunnel::new().share_link(&ctx, &dummy_user()).unwrap();
        let b = DnsTunnel::new().share_link(&ctx, &dummy_user()).unwrap();
        assert_eq!(a, b, "cert-carrying share_link is not byte-stable");
    }

    #[test]
    fn share_link_emits_auth_string_for_single_endpoint() {
        // A single `host:port` in `dns-tunnel:authoritative` → `auth` is a
        // JSON STRING. `r` still present; `v` unchanged (no cert → 1).
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert("dns-tunnel:authoritative".into(), "213.155.15.93:53".into());
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
        assert_eq!(v["auth"], "213.155.15.93:53", "single → string auth");
        assert!(v["auth"].is_string(), "single endpoint must be a string");
        // `r` is the censorship fallback — ALWAYS present.
        assert_eq!(
            v["r"],
            serde_json::json!(["195.208.4.1:53", "195.208.5.1:53"])
        );
        // auth is orthogonal to v — no cert → still v1.
        assert_eq!(v["v"], 1, "auth must NOT bump the version");
    }

    #[test]
    fn share_link_emits_auth_array_for_multiple_endpoints() {
        // Comma-separated `dns-tunnel:authoritative` → `auth` is a JSON
        // ARRAY of strings (trimmed). Empty entries dropped.
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert(
            "dns-tunnel:authoritative".into(),
            " 213.155.15.93:53 , 198.51.100.7:53 ".into(),
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
        assert!(v["auth"].is_array(), "multi endpoint must be an array");
        assert_eq!(
            v["auth"],
            serde_json::json!(["213.155.15.93:53", "198.51.100.7:53"])
        );
        // r untouched.
        assert_eq!(
            v["r"],
            serde_json::json!(["195.208.4.1:53", "195.208.5.1:53"])
        );
    }

    #[test]
    fn share_link_no_auth_field_when_secret_absent() {
        // Backward-compat: absent `dns-tunnel:authoritative` → no `auth`
        // field at all, output byte-identical to the historical link.
        let server = dummy_server();
        let secrets = secrets_complete();
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
        assert!(v.get("auth").is_none(), "no auth field when secret unset");
    }

    #[test]
    fn share_link_blank_auth_treated_as_absent() {
        // A whitespace/comma-only secret must NOT emit an empty/garbage
        // `auth` — treat it as absent (defensive against a cleared secret).
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert("dns-tunnel:authoritative".into(), " , , ".into());
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
        assert!(v.get("auth").is_none());
    }

    #[test]
    fn share_link_auth_coexists_with_cert_v2() {
        // `auth` is orthogonal to the cert version bump: cert + auth → v2
        // with BOTH fields present.
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert("dns-tunnel:cert_pem".into(), FAKE_CERT_PEM.into());
        secrets.insert("dns-tunnel:authoritative".into(), "213.155.15.93:53".into());
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
        assert_eq!(v["v"], 2, "cert still drives v2");
        assert_eq!(v["cert"], FAKE_CERT_PEM);
        assert_eq!(v["auth"], "213.155.15.93:53");
    }

    #[test]
    fn share_link_with_auth_is_byte_stable() {
        let server = dummy_server();
        let mut secrets = secrets_complete();
        secrets.insert(
            "dns-tunnel:authoritative".into(),
            "213.155.15.93:53,198.51.100.7:53".into(),
        );
        let ctx = RenderCtx::new(&server, &secrets);
        let a = DnsTunnel::new().share_link(&ctx, &dummy_user()).unwrap();
        let b = DnsTunnel::new().share_link(&ctx, &dummy_user()).unwrap();
        assert_eq!(a, b, "auth-carrying share_link is not byte-stable");
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
