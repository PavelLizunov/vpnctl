//! wgturn protocol — companion to the `wgturn` kernel.
//!
//! The wgturn-core daemon (see `crates/kernels/src/wgturn.rs`) hosts
//! a custom wire format combining a VK-TURN-relayed transport with a
//! WireGuard backend. The client URL format is `wgturn://...` and
//! mirrors upstream's `pkg/wgshare` encoder.
//!
//! ## Wire format
//!
//! ```text
//! wgturn://<base64url-nopad(JSON{v:1, sp, cp, psk?, ep, ad, ai?, dns?, mtu?, ka?})>#<query-escaped-label>
//! ```
//!
//! Required fields (per upstream `pkg/wgshare/share.go::Validate`):
//!   * `sp` — server WireGuard public key (44-char base64)
//!   * `cp` — client WireGuard private key (44-char base64)
//!   * `ep` — endpoint in `host:port` form
//!   * `ad` — assigned client address CIDR (e.g. `10.7.0.5/24`)
//!
//! Optional fields:
//!   * `psk` — pre-shared key (44-char base64). Omitted in vpnctl's
//!     phase 2 — PSK rotation is out of scope until a real operator
//!     workflow needs it.
//!   * `ai` — AllowedIPs as a list of CIDRs. We always emit
//!     `["0.0.0.0/0", "::/0"]` (full tunnel).
//!   * `dns` — list of resolver IPs. We emit `["1.1.1.1"]`.
//!   * `mtu` — interface MTU. We emit 1280 (typical for tunneled WG).
//!   * `ka` — persistent-keepalive seconds. We emit 25.
//!
//! Format version is `1`; older binaries fail to parse a newer version
//! string with «unsupported version». Bumping requires a coordinated
//! upstream + downstream change.
//!
//! ## Per-user secrets sourcing
//!
//! Server-side WireGuard public key (`sp`) comes from
//! `ctx.secrets["wgturn:server_wg_public"]` — minted by
//! `daemon::wizard_bootstrap::bootstrap_server_secrets` alongside the
//! private half.
//!
//! Client-side private key (`cp`) comes from
//! `user.wireguard_private` — the server-generated half of the
//! Curve25519 pair created at user-add time when the operator chose
//! `--gen-wireguard` (or its web-UI equivalent). Per CLAUDE.md «users
//! are maximally low-tech», we REFUSE to mint a wgturn share-link
//! when the user has no server-generated private — the alternative
//! («paste the privkey yourself») violates the one-action ceiling.
//!
//! Endpoint (`ep`) is `ctx.server.address` + `:` + the wgturn listen
//! port. Default port `WGTURN_PORT` (56000); a server-side override
//! via `wgturn:listen_port` is honoured.
//!
//! Client address (`ad`) is computed deterministically from the
//! user's index in `ctx.peers`: `10.7.0.<2+idx>/24`. The /24 base
//! mirrors WireGuard's `10.66.0.x` but uses a distinct prefix so a
//! single VPN node hosting BOTH amneziawg + wgturn doesn't collide
//! routes.
//!
//! ## Phase-1 → Phase-2 contract change
//!
//! Phase 1 returned `Err` from `share_link` to force operators through
//! a server-side `wgturn-cli provision-url` flow. Phase 2 (this
//! commit) emits the URL offline; the kernel's apt-installed
//! `wgturn-cli` is now used ONLY for the `serve` mode and the
//! `connect-url` client-side helper, never for URL generation.
//!
//! ## server_inbound + client_config
//!
//! Both still return type-tagged empty objects — wgturn-core's TOML
//! config is emitted entirely by the `wgturn` kernel's
//! `render_config`; this protocol doesn't contribute a sing-box-
//! style inbound block. Trait-compliance stubs.
//!
//! Stateless, like every other Protocol in this crate.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

/// Default UDP port `wgturn-cli serve` listens on. Kept in sync with
/// `crates/kernels/src/wgturn.rs::DEFAULT_LISTEN_PORT` — the value is
/// duplicated rather than shared because the kernels and protocols
/// crates are independent (kernel × protocol orthogonality).
pub const WGTURN_PORT: u16 = 56000;

/// Format-version byte the wgturn share-link `wireFormat` carries
/// under the `v` key. Must match upstream `pkg/wgshare/share.go::
/// formatVersion`. Bumping requires a coordinated change there +
/// here.
const FORMAT_VERSION: i32 = 1;

/// Standard WireGuard MTU for tunneled deployments. Matches what
/// AmneziaWG / wg-quick ship by default and what upstream
/// `pkg/wgshare`'s test suite uses.
const DEFAULT_MTU: i32 = 1280;

/// PersistentKeepalive seconds. 25 keeps NAT mappings alive across
/// most carrier paths without needless wakeups.
const DEFAULT_KEEPALIVE_SECONDS: i32 = 25;

/// Per-user `/32` base host octet — each granted user gets
/// `10.7.0.<2 + index>/24`. Shared addressing logic lives in
/// `wg_addressing::peer_octet_in_slash24`; only the base octet +
/// /24 prefix-text are wgturn-specific.
const PEER_OCTET_BASE: u16 = 2;

/// Label-escape set for the `#<label>` fragment.
///
/// **Caveat about Go interop:** `utf8_percent_encode` emits `%20`
/// for the space character; Go's `url.QueryEscape` (used by upstream
/// `pkg/wgshare`) emits `+`. The two diverge for `space` and `+`,
/// and `url.QueryUnescape` decodes `+` back to space (silent
/// asymmetry).
///
/// In vpnctl the user-id alphabet is validated upstream as
/// `[A-Za-z0-9._-]+`, so the divergent characters (` `, `+`) are
/// unreachable in practice. If the validator ever loosens, switch
/// to a form-style encoder (or verify against upstream's
/// `url.PathUnescape`, which treats `+` literally).
const LABEL: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[derive(Debug, Default)]
pub struct WgTurn;

impl WgTurn {
    pub fn new() -> Self {
        Self
    }
}

/// Build the JSON `wireFormat` payload — mirror of upstream
/// `pkg/wgshare/share.go::wireFormat`. Field tags are short (`sp`,
/// `cp`, `ep`, …) to keep the encoded URL compact; every saved
/// character is one less to paste on a phone. Renaming any tag
/// breaks the upstream parser → bump `FORMAT_VERSION` if you have to.
///
/// We build the JSON `Value` by hand (vs `#[derive(Serialize)]`) for
/// two reasons:
///   1. The protocols crate doesn't already depend on `serde` (only
///      `serde_json`), and we'd rather not add a dep for one struct.
///   2. We explicitly control which optional fields are present —
///      mirrors Go's `,omitempty` semantics without a custom helper.
///
/// **Key order:** `serde_json::Value::Object` is a `BTreeMap` (since
/// the `preserve_order` feature is NOT enabled in our workspace), so
/// the serialised JSON emits keys in **lexicographic** order — `ad,
/// ai, cp, dns, ep, ka, mtu, sp, v` — NOT in the Go struct's
/// declaration order. This is fine because Go's `encoding/json`
/// `Unmarshal` is field-order-insensitive — the upstream parser
/// reconstructs the same struct regardless. The byte-stability
/// guarantee (`share_link_byte_stable_across_runs`) holds because
/// `BTreeMap` ordering is deterministic per key set.
///
/// `psk` is always omitted (we don't issue PSKs in vpnctl phase 2).
/// `ai`, `dns`, `mtu`, `ka` are always emitted (with vpnctl-chosen
/// defaults) — no operator-tunable yet to make them omittable.
fn build_wire_format(server_pub: &str, client_priv: &str, endpoint: &str, address: &str) -> Value {
    json!({
        "v": FORMAT_VERSION,
        "sp": server_pub,
        "cp": client_priv,
        "ep": endpoint,
        "ad": address,
        "ai": ["0.0.0.0/0", "::/0"],
        "dns": ["1.1.1.1"],
        "mtu": DEFAULT_MTU,
        "ka": DEFAULT_KEEPALIVE_SECONDS,
    })
}

/// Compute the per-user `/24` host octet from the user's index in
/// `ctx.peers`. Thin wrapper around the shared addressing helper —
/// see `wg_addressing::peer_octet_in_slash24` for the missing-peer
/// + overflow semantics.
fn host_octet_for(ctx: &RenderCtx<'_>, user: &User) -> Result<u16> {
    crate::wg_addressing::peer_octet_in_slash24(ctx, user, PEER_OCTET_BASE)
}

impl Protocol for WgTurn {
    fn id(&self) -> ProtocolId {
        ProtocolId("wgturn".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        // Single UDP listener — the VK-TURN demuxer.
        &[("udp", WGTURN_PORT)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // Custom WireGuard variant with the VK-TURN demuxer prepended
        // — the canonical raw-WG 0x01 handshake-initiation type tag is
        // wrapped / obfuscated by the demuxer, so the trivial
        // `first 4 bytes == 0x01 0x00 0x00 0x00` DPI rule that drops
        // raw WireGuard on TSPU does NOT match. Active probing requires
        // the demuxer secret, which we don't share. Reported working in
        // RU through 2025 + Q1 2026.
        vpnctl_core::DpiRisk::Strong
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        // wgturn is delivered via the dedicated `wgturn-cli` client +
        // its own `wgturn://` share-link, NOT via sing-box. Sing-box
        // has no idea what `type: "wgturn"` is — if we let this slip
        // into the /sub config the whole sub envelope becomes
        // unparseable and Hiddify drops EVERY route (including the
        // working VLESS / TUIC ones). Hard `false` is correct.
        false
    }

    fn server_inbound(&self, _ctx: &RenderCtx<'_>, _users: &[User]) -> Result<serde_json::Value> {
        // wgturn-core renders its OWN TOML via the kernel's
        // `render_config`; the protocol doesn't contribute a sing-box-
        // style inbound block. Returning an empty marker keeps the
        // trait shape uniform without polluting any merged config.
        Ok(json!({ "type": "wgturn" }))
    }

    fn client_config(&self, _ctx: &RenderCtx<'_>, _user: &User) -> Result<serde_json::Value> {
        // Same reasoning — the client config is the `wgturn://` URL
        // (rendered by `share_link` below), not a JSON blob. Trait-
        // compliance stub.
        Ok(json!({ "type": "wgturn" }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        // ── Required fields, per upstream's Validate() ────────────
        let server_pub = ctx.secrets.get("wgturn:server_wg_public").ok_or_else(|| {
            CoreError::Render(
                "wgturn share_link: missing server secret \
                 `wgturn:server_wg_public` — mint via the add-server \
                 wizard, or visit /admin/servers/<id>/secrets to fix"
                    .into(),
            )
        })?;

        // Client privkey MUST be server-generated. Per CLAUDE.md
        // «users are maximally low-tech» the operator can't reasonably
        // ask the end-user to paste a private key — fail loud rather
        // than emitting a link that won't authenticate.
        let client_priv = user.wireguard_private.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "wgturn share_link: user '{}' has no server-generated \
                 wireguard_private — create the user via `--gen-wireguard` \
                 (CLI) or the «server-generated key» web-UI option to mint \
                 a complete key pair, then re-fetch the share-link",
                user.id.0
            ))
        })?;

        // Endpoint — host:port. Listen port is `wgturn:listen_port`
        // or default 56000. The kernel's render_config already
        // validates the port as u16; we re-parse defensively in case
        // a future deploy path skips that pre-validation.
        let listen_port: u16 = match ctx.secrets.get("wgturn:listen_port") {
            None => WGTURN_PORT,
            Some(s) => s.parse().map_err(|_| {
                CoreError::Render(format!(
                    "wgturn share_link: invalid `wgturn:listen_port` {s:?} \
                     — must be an integer in 0..=65535"
                ))
            })?,
        };
        let endpoint = format!("{}:{listen_port}", ctx.server.address);

        // Client address /24.
        let host_octet = host_octet_for(ctx, user)?;
        let address = format!("10.7.0.{host_octet}/24");

        let wire = build_wire_format(server_pub, client_priv, &endpoint, &address);
        let json_bytes = serde_json::to_vec(&wire)
            .map_err(|e| CoreError::Render(format!("wgturn share_link: marshal: {e}")))?;
        let payload = URL_SAFE_NO_PAD.encode(&json_bytes);
        let label = utf8_percent_encode(&user.id.0, LABEL).to_string();
        Ok(format!("wgturn://{payload}#{label}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use vpnctl_core::{KernelId, Server, ServerId, UserId};

    /// Valid 44-char WireGuard pubkey shape used across tests.
    const FAKE_SERVER_PUB: &str = "Qhh7nQwL+0fH3iZ8VAEcvVNlEMU8r9SiH3LzAh6Kj3o=";
    const FAKE_CLIENT_PRIV: &str = "0000000000000000000000000000000000000000000=";

    fn dummy_user() -> User {
        User {
            id: UserId("alex".into()),
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            tuic_password: None,
            wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
            wireguard_private: Some(FAKE_CLIENT_PRIV.into()),
            sub_token: Some("st".into()),
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn dummy_server() -> Server {
        Server {
            id: ServerId("wgturn-node".into()),
            address: "203.0.113.42".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("wgturn".into())],
            enabled_protocols: vec![ProtocolId("wgturn".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn server_secrets_complete() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("wgturn:server_wg_public".into(), FAKE_SERVER_PUB.into());
        m
    }

    #[test]
    fn id_returns_wgturn() {
        assert_eq!(WgTurn::new().id(), ProtocolId("wgturn".into()));
    }

    #[test]
    fn listen_ports_declares_udp_56000() {
        let p = WgTurn::new();
        let ports = p.listen_ports();
        assert_eq!(ports, &[("udp", 56000_u16)]);
    }

    #[test]
    fn appears_in_sing_box_sub_is_false() {
        // CRITICAL: wgturn's `type: "wgturn"` outbound is NOT
        // sing-box-native. If the /sub handler doesn't skip it,
        // every Hiddify / sing-box client fed the resulting envelope
        // refuses to start with «unknown outbound type wgturn» (or
        // worse, silently drops every route including the legit
        // VLESS / TUIC ones). Pin the trait override.
        // (Pavel 2026-05-19 bug report.)
        assert!(
            !WgTurn::new().appears_in_sing_box_sub(),
            "wgturn must opt OUT of the sing-box subscription"
        );
    }

    #[test]
    fn server_inbound_returns_wgturn_marker() {
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let v = WgTurn::new().server_inbound(&ctx, &[]).unwrap();
        assert_eq!(v["type"], "wgturn");
    }

    #[test]
    fn client_config_returns_wgturn_marker() {
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let v = WgTurn::new().client_config(&ctx, &user).unwrap();
        assert_eq!(v["type"], "wgturn");
    }

    // ── share_link encoder tests (phase 2) ─────────────────────────

    #[test]
    fn share_link_starts_with_wgturn_scheme_prefix() {
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let link = WgTurn::new().share_link(&ctx, &user).unwrap();
        assert!(link.starts_with("wgturn://"), "wrong scheme: {link}");
    }

    #[test]
    fn share_link_payload_is_base64url_no_pad() {
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let link = WgTurn::new().share_link(&ctx, &user).unwrap();
        let after_scheme = link.strip_prefix("wgturn://").unwrap();
        let payload = after_scheme.split('#').next().unwrap();
        // base64url-no-pad: alphabet is A-Z a-z 0-9 - _, no '+', no '/',
        // no trailing '='.
        assert!(
            !payload.ends_with('='),
            "base64url-NO-pad must not end in '=': {payload}"
        );
        for c in payload.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-base64url char {c:?} in payload: {payload}"
            );
        }
    }

    #[test]
    fn share_link_round_trips_to_wire_format_with_required_fields() {
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let link = WgTurn::new().share_link(&ctx, &user).unwrap();
        let payload = link
            .strip_prefix("wgturn://")
            .unwrap()
            .split('#')
            .next()
            .unwrap();
        let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();

        // Required fields per upstream Validate().
        assert_eq!(v["v"], 1, "format version: {v}");
        assert_eq!(v["sp"], FAKE_SERVER_PUB);
        assert_eq!(v["cp"], FAKE_CLIENT_PRIV);
        assert_eq!(v["ep"], "203.0.113.42:56000");
        assert_eq!(v["ad"], "10.7.0.2/24");

        // Optional fields we always emit.
        assert_eq!(v["ai"], serde_json::json!(["0.0.0.0/0", "::/0"]));
        assert_eq!(v["dns"], serde_json::json!(["1.1.1.1"]));
        assert_eq!(v["mtu"], 1280);
        assert_eq!(v["ka"], 25);

        // psk MUST be absent (omitempty) — not the empty string.
        assert!(v.get("psk").is_none(), "psk must be omitted, got: {v}");
    }

    #[test]
    fn share_link_uses_listen_port_override_when_set() {
        let server = dummy_server();
        let mut secrets = server_secrets_complete();
        secrets.insert("wgturn:listen_port".into(), "57000".into());
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let link = WgTurn::new().share_link(&ctx, &user).unwrap();
        let payload = link
            .strip_prefix("wgturn://")
            .unwrap()
            .split('#')
            .next()
            .unwrap();
        let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["ep"], "203.0.113.42:57000");
    }

    #[test]
    fn share_link_label_fragment_carries_user_id() {
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let link = WgTurn::new().share_link(&ctx, &user).unwrap();
        assert!(link.ends_with("#alex"), "label fragment lost: {link}");
    }

    #[test]
    fn share_link_assigns_per_user_address_from_peer_index() {
        // Three peers in order — alex / brian / clara. Each must land
        // on a distinct /24 host octet (2 / 3 / 4) so their routes
        // don't collide.
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let peers: Vec<User> = ["alex", "brian", "clara"]
            .iter()
            .map(|name| User {
                id: UserId((*name).into()),
                uuid: format!("{}-uuid", name),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: Some(FAKE_CLIENT_PRIV.into()),
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .collect();

        let mut octets: Vec<u16> = Vec::new();
        for u in &peers {
            let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
            let link = WgTurn::new().share_link(&ctx, u).unwrap();
            let payload = link
                .strip_prefix("wgturn://")
                .unwrap()
                .split('#')
                .next()
                .unwrap();
            let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            let ad = v["ad"].as_str().unwrap();
            // ad looks like "10.7.0.<N>/24" — parse N.
            let octet_str = ad
                .strip_prefix("10.7.0.")
                .and_then(|s| s.strip_suffix("/24"))
                .unwrap_or_else(|| panic!("unexpected address shape: {ad}"));
            octets.push(octet_str.parse().unwrap());
        }
        assert_eq!(octets, vec![2, 3, 4]);
    }

    #[test]
    fn share_link_errors_when_server_public_key_secret_missing() {
        let server = dummy_server();
        let secrets: HashMap<String, String> = HashMap::new(); // empty
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let err = WgTurn::new().share_link(&ctx, &user).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("wgturn:server_wg_public"),
            "must name the missing key: {msg}"
        );
    }

    #[test]
    fn share_link_errors_when_user_wireguard_private_missing() {
        // Per CLAUDE.md «users are maximally low-tech» — refuse to
        // mint a link that wouldn't authenticate on import.
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let mut user = dummy_user();
        user.wireguard_private = None;
        let err = WgTurn::new().share_link(&ctx, &user).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("wireguard_private"),
            "must name the missing user field: {msg}"
        );
        assert!(
            msg.contains("gen-wireguard"),
            "must point at the fix UX: {msg}"
        );
    }

    #[test]
    fn share_link_errors_when_listen_port_secret_is_garbage() {
        let server = dummy_server();
        let mut secrets = server_secrets_complete();
        secrets.insert("wgturn:listen_port".into(), "not-a-port".into());
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let err = WgTurn::new().share_link(&ctx, &user).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("wgturn:listen_port"),
            "must name the bad key: {msg}"
        );
        assert!(msg.contains("not-a-port"), "must quote bad value: {msg}");
    }

    #[test]
    fn share_link_errors_never_leak_client_privkey() {
        // Review-agent finding 5 — important: pin the contract that
        // NO error path in `share_link` emits the user's private key
        // verbatim. A future error message that interpolates
        // `client_priv` into format args would silently leak the
        // tunnel key into journald via the daemon's
        // `tracing::warn(error = %e)` calls.
        //
        // Strategy: drive every error branch we can without
        // touching the implementation, scan the resulting message
        // for the privkey string.
        let server = dummy_server();
        let user = dummy_user();
        assert!(
            user.wireguard_private
                .as_deref()
                .unwrap()
                .contains(FAKE_CLIENT_PRIV),
            "test fixture sanity check"
        );

        // Branch 1: missing server pubkey secret.
        let empty: HashMap<String, String> = HashMap::new();
        let ctx = RenderCtx::new(&server, &empty);
        let err = WgTurn::new().share_link(&ctx, &user).unwrap_err();
        assert!(
            !format!("{err}").contains(FAKE_CLIENT_PRIV),
            "missing-server-pubkey error leaked the client privkey: {err}"
        );

        // Branch 2: missing user.wireguard_private.
        let secrets = server_secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let mut no_priv = user.clone();
        no_priv.wireguard_private = None;
        let err = WgTurn::new().share_link(&ctx, &no_priv).unwrap_err();
        assert!(
            !format!("{err}").contains(FAKE_CLIENT_PRIV),
            "missing-privkey error leaked the client privkey: {err}"
        );

        // Branch 3: garbage listen_port.
        let mut bad = secrets.clone();
        bad.insert("wgturn:listen_port".into(), "not-a-port".into());
        let ctx = RenderCtx::new(&server, &bad);
        let err = WgTurn::new().share_link(&ctx, &user).unwrap_err();
        assert!(
            !format!("{err}").contains(FAKE_CLIENT_PRIV),
            "garbage-port error leaked the client privkey: {err}"
        );

        // Branch 4: user not in non-empty peers (route-collision branch).
        let other = User {
            id: UserId("brian".into()),
            uuid: "brian-uuid".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: Some(FAKE_CLIENT_PRIV.into()),
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        };
        let peers = vec![other];
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        let err = WgTurn::new().share_link(&ctx, &user).unwrap_err();
        assert!(
            !format!("{err}").contains(FAKE_CLIENT_PRIV),
            "user-not-in-peers error leaked the client privkey: {err}"
        );
    }

    #[test]
    fn share_link_byte_stable_across_runs_for_same_input() {
        // Same secrets + same user → byte-identical URL. Pins the
        // serde-json ordering + base64url alphabet against an
        // accidental dep upgrade that adds whitespace.
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = dummy_user();
        let a = WgTurn::new().share_link(&ctx, &user).unwrap();
        let b = WgTurn::new().share_link(&ctx, &user).unwrap();
        assert_eq!(a, b, "share_link is not byte-stable");
    }

    // ── peer_octet boundary ──

    #[test]
    fn host_octet_for_caps_at_254_peers() {
        // 253 peers fits (octet 2..=254); 254 overflows.
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let peers: Vec<User> = (0..254)
            .map(|i| User {
                id: UserId(format!("user-{i:03}")),
                uuid: format!("user-{i}-uuid"),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: Some(FAKE_CLIENT_PRIV.into()),
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .collect();
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        let last = peers.last().unwrap();
        let err = WgTurn::new().share_link(&ctx, last).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("/24") && msg.contains("overflow"),
            "must explain overflow: {msg}"
        );
    }

    #[test]
    fn host_octet_for_works_for_peer_at_octet_254() {
        // 253 peers — last one lands at octet 254 (max allowed).
        let server = dummy_server();
        let secrets = server_secrets_complete();
        let peers: Vec<User> = (0..253)
            .map(|i| User {
                id: UserId(format!("user-{i:03}")),
                uuid: format!("user-{i}-uuid"),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: Some(FAKE_CLIENT_PRIV.into()),
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .collect();
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        let last = peers.last().unwrap();
        let link = WgTurn::new().share_link(&ctx, last).unwrap();
        let payload = link
            .strip_prefix("wgturn://")
            .unwrap()
            .split('#')
            .next()
            .unwrap();
        let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["ad"], "10.7.0.254/24");
    }
}
