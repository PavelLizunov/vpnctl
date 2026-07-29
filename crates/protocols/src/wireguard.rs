//! WireGuard protocol — wire format clients consume. The Kernel that
//! actually runs WireGuard on the node (today: AmneziaWG with anti-DPI
//! obfuscation; future: vanilla `wg-quick`) reads this module's
//! `server_inbound()` envelope and transforms it into its native
//! config format (INI for wg-quick / amneziawg-tools, JSON for
//! sing-box's hypothetical `wireguard` inbound).
//!
//! # Envelope schema (the trait-impedance fix)
//!
//! `Protocol::server_inbound` returns `serde_json::Value`. AmneziaWG
//! renders INI, not JSON — so we'd hit a trait-impedance problem if
//! the Protocol returned a sing-box-flavoured JSON config. Instead,
//! this module returns a STABLE ENVELOPE that any Kernel can
//! deserialise into a typed struct and transform.
//!
//! Envelope shape (JSON, byte-stable across runs — uses BTreeMap
//! ordering for the `peers` field if applicable; users vec is iterated
//! in caller-provided order which is `inv.users_for_server`'s
//! lex-sorted-by-id order):
//!
//! ```json
//! {
//!   "type": "wireguard",
//!   "tag": "wg-in",
//!   "listen_port": 51820,
//!   "private_key": "<base64 server private key>",
//!   "address_cidr": "10.66.0.1/24",
//!   "peers": [
//!     { "name": "alex", "public_key": "<base64 user pubkey>", "allowed_ips": "10.66.0.2/32" }
//!   ]
//! }
//! ```
//!
//! Per-peer `allowed_ips` is computed deterministically from the
//! peer's index in the `users` slice: `10.66.0.<2 + index>/32`. This
//! is stable across re-renders provided callers pass users in the
//! same order each time (which `inv.users_for_server` does — it
//! `ORDER BY id`s).
//!
//! # Per-user contract
//!
//! Users with `wireguard_pubkey == None` are SKIPPED (not an error)
//! in `server_inbound` so a partially-provisioned node still deploys.
//! Same user → `share_link` is a HARD ERROR (the operator is asking
//! for something that can't possibly work). Same split as Hysteria2's
//! `tuic_password` handling.
//!
//! Pubkey validation: 44 chars, base64 (`[A-Za-z0-9+/]{43}=`). Reject
//! malformed early so a typo doesn't reach `awg setconf` and crash
//! the kernel module.
//!
//! # Client config
//!
//! `client_config` returns an envelope SUITABLE for transformation
//! into a client `.conf` file. The CLIENT private key is emitted as
//! a placeholder (`"<PASTE YOUR PRIVATE KEY HERE>"`) — vpnctl never
//! sees it. The operator (or AmneziaVPN's import flow) substitutes
//! it. Standard self-hosted-WireGuard UX.
//!
//! # Share link
//!
//! `wireguard://?conf=<base64url(.conf bytes)>#<user-id>`. Not an
//! IETF-blessed URI; chosen for stability + universal QR encoding.
//! AmneziaVPN clients accept it. Vanilla WireGuard mobile apps don't,
//! but the user-detail page already shows the raw conf alongside the
//! QR (operator can paste manually).
//!
//! Stateless, like every other Protocol in this crate.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

#[derive(Debug, Default)]
pub struct WireGuard;

impl WireGuard {
    pub fn new() -> Self {
        Self
    }
}

/// UDP port WireGuard listens on. Public so kernels + tests can format
/// endpoints without duplicating the literal.
pub const WIREGUARD_PORT: u16 = 51820;

/// Default tunnel-side server CIDR. `/24` gives 254 peer slots — more
/// than enough for a single-operator homelab.
const DEFAULT_SERVER_CIDR: &str = "10.66.0.1/24";

/// Placeholder substituted by the client's import flow / operator.
/// vpnctl deliberately never holds the client private key — the
/// peer-side keypair is generated on the device.
pub const CLIENT_PRIVKEY_PLACEHOLDER: &str = "<PASTE YOUR PRIVATE KEY HERE>";

/// Validate a base64-encoded WireGuard public key. WG keys are exactly
/// 32 bytes → 44 chars of standard-base64 with `=` padding (last char).
/// We don't decode — just shape-check, since the kernel module will
/// reject a wrong-length or malformed key with a clear error message
/// at apply time anyway.
///
/// **Public so the CLI + web user-create handlers can share the SAME
/// validator** (caught by review-agent: previously each call site had
/// its own ad-hoc reimplementation — silent drift risk).
pub fn is_valid_wg_pubkey(s: &str) -> bool {
    if s.len() != 44 {
        return false;
    }
    if !s.ends_with('=') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Fragment-only escape set for the user-id tag in `share_link`'s
/// `#name` portion. Identical to the FRAGMENT set used elsewhere in
/// this crate.
const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?');

impl Protocol for WireGuard {
    fn id(&self) -> ProtocolId {
        ProtocolId("wireguard".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("udp", WIREGUARD_PORT)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // Raw WireGuard's handshake initiation message is ALWAYS a
        // 148-byte UDP datagram that begins with `0x01 0x00 0x00 0x00`
        // (message_type=1 + 3 zero bytes for reserved). This is a
        // hard-coded constant in the WG protocol spec — it CANNOT be
        // changed without breaking the wire format. TSPU exploited
        // this since 2023 and now drops bare WireGuard 100% in RU
        // residential ASNs; GFW (CN) the same. The IR DPI blocks it
        // on similar grounds. Use `wgturn` (this crate's obfuscated
        // variant) or `amneziawg` (kernel-level junk-packet injection)
        // when WG-style transport is needed in a hostile environment.
        vpnctl_core::DpiRisk::Weak
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        // `client_config()` emits an INTERNAL `{ type: "wireguard",
        // interface: {...}, peer: {...} }` object — the shape consumed
        // by the wg-quick / AmneziaWG renderers, NOT a valid sing-box
        // outbound (sing-box's wireguard outbound is a flat object with
        // `server` / `server_port` / `private_key` / `peer_public_key`).
        // If this slips into the /sub envelope, sing-box / Hiddify sees
        // an unknown outbound shape and drops EVERY route (including the
        // working VLESS / TUIC ones). WireGuard is delivered via its own
        // `wg://` share link + `.conf` download. Hard `false`, same as
        // wgturn / dns-tunnel.
        false
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        // Server-side Curve25519 keypair. The per-user pair lives in
        // the `users` table (a different bootstrap path — user_create).
        vec![vpnctl_core::ServerSecretSpec::WireguardKeypair {
            private_key: "wireguard.server_private_key",
            public_key: "wireguard.server_public_key",
        }]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        // Server-side material — required.
        let private_key = ctx.require("wireguard.server_private_key")?;
        let listen_port: u16 = ctx
            .secrets
            .get("wireguard.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(WIREGUARD_PORT);
        let address_cidr = ctx
            .secrets
            .get("wireguard.server_address_cidr")
            .map(String::as_str)
            .unwrap_or(DEFAULT_SERVER_CIDR);

        // Per-user peers. Skip users without a pubkey (partial
        // provisioning is allowed — same convention as Hysteria2's
        // missing tuic_password). Reject MALFORMED pubkeys hard so a
        // typo doesn't reach the kernel module and kill the deploy.
        let mut peers: Vec<serde_json::Value> = Vec::with_capacity(users.len());
        for (idx, u) in users.iter().enumerate() {
            let Some(pubkey) = u.wireguard_pubkey.as_deref() else {
                continue;
            };
            if !is_valid_wg_pubkey(pubkey) {
                return Err(CoreError::Render(format!(
                    "user '{}' has malformed wireguard pubkey (must be 44 base64 chars ending '='): {pubkey:?}",
                    u.id.0
                )));
            }
            // /32 per peer — each user gets exactly one tunnel address.
            // 10.66.0.2 .. 10.66.0.255. Past 254 users we'd overflow;
            // homelab scale comfortably under that.
            let peer_octet = 2_u16.saturating_add(u16::try_from(idx).unwrap_or(u16::MAX));
            if peer_octet > 254 {
                return Err(CoreError::Render(format!(
                    "wireguard /24 has only 253 peer slots; user '{}' would overflow at index {idx}",
                    u.id.0
                )));
            }
            peers.push(json!({
                "name": u.id.0,
                "public_key": pubkey,
                "allowed_ips": format!("10.66.0.{peer_octet}/32"),
            }));
        }

        Ok(json!({
            "type": "wireguard",
            "tag": "wg-in",
            "listen_port": listen_port,
            "private_key": private_key,
            "address_cidr": address_cidr,
            "peers": peers,
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        // Server-side public key (NOT private) is what the client peer
        // needs in its [Peer] PublicKey field.
        let server_pub = ctx.require("wireguard.server_public_key")?;
        let listen_port: u16 = ctx
            .secrets
            .get("wireguard.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(WIREGUARD_PORT);

        // Where THIS user lands in the /24. We can't know the index
        // without the full users slice; use the user's pubkey as a
        // tagging marker the kernel can cross-reference if it has the
        // full peer list. Default to `.2/32` so a single-user
        // standalone client doesn't need extra context.
        // (For multi-user accuracy use `server_inbound`'s per-peer
        // allowed_ips; client_config is per-user only and lacks the
        // index.)
        let client_cidr = "10.66.0.2/32";

        // AmneziaWG sub-block. Emitted ONLY if the server has the
        // obfuscation params set — vanilla WireGuard servers don't,
        // and a vanilla WireGuard client given an `amneziawg` block
        // would just ignore it (per spec: unknown keys are skipped).
        // Still, omit when not set so the rendered conf stays minimal.
        let amnezia = amneziawg_block(ctx);

        // Server-generated private (low-tech UX) takes precedence;
        // operator-provided-pubkey path keeps the legacy placeholder.
        // See `render_client_conf` for the same fallback chain.
        //
        // Invariant guard: if private is set, the matching public MUST
        // also be set — the server's [Peer] block won't authenticate
        // a client whose pubkey isn't in the server's user list.
        // This pair is enforced by all write paths (CLI + web both
        // set both halves atomically), but a direct-SQL operator could
        // hand-set only one — fail loud here rather than ship a
        // silently-broken tunnel. (Review-agent finding on wg-keygen.)
        if user.wireguard_private.is_some() && user.wireguard_pubkey.is_none() {
            return Err(CoreError::Render(format!(
                "user '{}' has wireguard_private set but no wireguard_pubkey \
                 — the server [Peer] block can't authenticate this client; \
                 fix the inventory row before re-running",
                user.id.0
            )));
        }
        let client_private = user
            .wireguard_private
            .as_deref()
            .unwrap_or(CLIENT_PRIVKEY_PLACEHOLDER);
        let mut interface = json!({
            "private_key": client_private,
            "address_cidr": client_cidr,
            "dns": ["1.1.1.1"],
        });
        if let Some(a) = amnezia.clone()
            && let Some(map) = interface.as_object_mut()
        {
            map.insert("amneziawg".to_string(), a);
        }

        let _ = user; // single-user client_config doesn't differentiate

        Ok(json!({
            "type": "wireguard",
            "interface": interface,
            "peer": {
                "public_key": server_pub,
                "endpoint": format!("{}:{listen_port}", host_for_url(&ctx.server.address)),
                "allowed_ips": "0.0.0.0/0,::/0",
                "persistent_keepalive": 25,
            },
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        // Hard-error on missing pubkey — operator asked for a link
        // that can't possibly authenticate. Mirror Hysteria2's split.
        let pubkey = user.wireguard_pubkey.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no wireguard_pubkey — cannot mint a WireGuard share link",
                user.id.0
            ))
        })?;
        if !is_valid_wg_pubkey(pubkey) {
            return Err(CoreError::Render(format!(
                "user '{}' has malformed wireguard pubkey: {pubkey:?}",
                user.id.0
            )));
        }
        // Build a real .conf file body, base64url-no-pad it, embed
        // in a stable wireguard:// pseudo-URI. The client (AmneziaVPN
        // app) base64-decodes the `conf` query-param and treats as a
        // real config file.
        let conf = render_client_conf(ctx, user)?;
        let conf_b64 = URL_SAFE_NO_PAD.encode(conf.as_bytes());
        let tag = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!("wireguard://?conf={conf_b64}#{tag}"))
    }
}

/// Optional `amneziawg` sub-object — populated when the server has
/// the obfuscation secrets set. Returns `None` when ANY of the
/// required obfs params is missing (we don't half-render — either
/// the full obfuscation profile or none of it, otherwise the client
/// would silently fail to handshake).
///
/// All 9 keys are required together because AmneziaWG's protocol
/// expects them as a coherent set (the H1-H4 magic constants must
/// match between client and server, missing any breaks the
/// handshake).
fn amneziawg_block(ctx: &RenderCtx<'_>) -> Option<serde_json::Value> {
    let keys = [
        "amneziawg.jc",
        "amneziawg.jmin",
        "amneziawg.jmax",
        "amneziawg.s1",
        "amneziawg.s2",
        "amneziawg.h1",
        "amneziawg.h2",
        "amneziawg.h3",
        "amneziawg.h4",
    ];
    // All-or-nothing: if any missing, skip the whole block.
    for k in &keys {
        ctx.secrets.get(*k)?;
    }
    Some(json!({
        "jc":   ctx.secrets.get("amneziawg.jc"),
        "jmin": ctx.secrets.get("amneziawg.jmin"),
        "jmax": ctx.secrets.get("amneziawg.jmax"),
        "s1":   ctx.secrets.get("amneziawg.s1"),
        "s2":   ctx.secrets.get("amneziawg.s2"),
        "h1":   ctx.secrets.get("amneziawg.h1"),
        "h2":   ctx.secrets.get("amneziawg.h2"),
        "h3":   ctx.secrets.get("amneziawg.h3"),
        "h4":   ctx.secrets.get("amneziawg.h4"),
    }))
}

/// Public wrapper around the same `.conf` renderer used internally
/// by `share_link` and `amnezia_share_link`. Exposed so the daemon's
/// `.conf` download handler can serve a drag-drop-ready file
/// without going through a `share_link` plus base64-decode dance.
///
/// Returns the full INI body (Interface + Peer sections + AmneziaWG
/// obfs lines when secrets are set). Same error contract as
/// `share_link`: missing `wireguard.server_public_key` returns
/// `MissingSecret`.
pub fn render_client_conf_public(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    render_client_conf(ctx, user)
}

/// Compute the per-user `/32` octet for the target user on this
/// server. Thin wrapper around the shared `wg_addressing` helper
/// — both AmneziaWg (here) and wgturn pick from a /24 with the
/// same indexing scheme, only the base subnet differs.
///
/// Semantics (per `wg_addressing::peer_octet_in_slash24`):
///   * `ctx.peers` empty → `Ok(2)` legacy single-user fallback
///     (kept for byte-equality with pre-2026-05-17 clients holding
///     a `.conf` rendered without `with_peers`).
///   * `ctx.peers` populated + user found → `Ok(2 + idx)`.
///   * `ctx.peers` populated + user MISSING → `Err(Render)` —
///     tightened contract from the pre-extraction version that
///     silently returned 2; the caller built `RenderCtx` for the
///     wrong server.
fn peer_octet_for(ctx: &RenderCtx<'_>, user: &User) -> Result<u16> {
    crate::wg_addressing::peer_octet_in_slash24(ctx, user, 2)
}

/// Render the actual `.conf` text the share-link encodes. INI-format,
/// LF newlines, opens with a "do-not-edit" warning. Mirrors the conf
/// the AmneziaWG kernel writes server-side — same obfuscation block,
/// peer's keys swapped for client perspective.
///
/// **Private-key sourcing** (per CLAUDE.md "users are low-tech" rule):
///
/// - `user.wireguard_private` set (= server-generated via
///   `--gen-wireguard`) → conf is ready-to-import, single-action UX;
///   no editor step needed.
/// - `user.wireguard_private` is `None` (= operator-provided pubkey
///   only) → falls back to the legacy `<PASTE YOUR PRIVATE KEY HERE>`
///   placeholder + the comment block instructing the operator to
///   swap in the client-side privkey before forwarding to the user.
fn render_client_conf(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    let server_pub = ctx.require("wireguard.server_public_key")?;
    let listen_port: u16 = ctx
        .secrets
        .get("wireguard.listen_port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(WIREGUARD_PORT);
    let peer_octet = peer_octet_for(ctx, user)?;

    let mut out = String::with_capacity(512);
    out.push_str("# vpnctl-rendered AmneziaWG client config.\n");
    if user.wireguard_private.is_some() {
        out.push_str("# Private key was server-generated for ");
        out.push_str(&user.id.0);
        out.push_str(" — import this file as-is.\n\n");
    } else {
        out.push_str("# Replace <PASTE YOUR PRIVATE KEY HERE> with the privkey for ");
        out.push_str(&user.id.0);
        out.push('\n');
        out.push_str("# generated locally via `awg genkey`.\n\n");
    }

    out.push_str("[Interface]\n");
    out.push_str("PrivateKey = ");
    out.push_str(
        user.wireguard_private
            .as_deref()
            .unwrap_or(CLIENT_PRIVKEY_PLACEHOLDER),
    );
    out.push('\n');
    out.push_str("Address = 10.66.0.");
    out.push_str(&peer_octet.to_string());
    out.push_str("/32\n");
    out.push_str("DNS = 1.1.1.1\n");
    // AmneziaWG params (only if the server set them — same all-or-nothing
    // contract as the JSON envelope).
    if let Some(amnezia) = amneziawg_block(ctx) {
        let m = amnezia
            .as_object()
            .ok_or_else(|| CoreError::Render("amneziawg block must be a JSON object".into()))?;
        for (key, ini_key) in [
            ("jc", "Jc"),
            ("jmin", "Jmin"),
            ("jmax", "Jmax"),
            ("s1", "S1"),
            ("s2", "S2"),
            ("h1", "H1"),
            ("h2", "H2"),
            ("h3", "H3"),
            ("h4", "H4"),
        ] {
            if let Some(v) = m.get(key).and_then(|x| x.as_str()) {
                out.push_str(ini_key);
                out.push_str(" = ");
                out.push_str(v);
                out.push('\n');
            }
        }
    }
    out.push('\n');

    out.push_str("[Peer]\n");
    out.push_str("PublicKey = ");
    out.push_str(server_pub);
    out.push('\n');
    out.push_str("Endpoint = ");
    out.push_str(&host_for_url(&ctx.server.address));
    out.push(':');
    out.push_str(&listen_port.to_string());
    out.push('\n');
    out.push_str("AllowedIPs = 0.0.0.0/0, ::/0\n");
    out.push_str("PersistentKeepalive = 25\n");
    Ok(out)
}

// ────────────────────────────────────────────────────────────────────────
// AmneziaVPN deep-link (`vpn://...`) generator.
//
// Why this is a separate function (not a Protocol trait method): the
// Protocol trait's `share_link()` returns ONE link, but a WireGuard user
// actually has TWO distinct client UXs:
//   * Flow B — official WireGuard app / Hiddify — uses the standard
//     `wireguard://?conf=<base64(.conf)>` link rendered by `share_link()`
//     above.
//   * Flow C — AmneziaVPN — uses Amnezia's own `vpn://<...>` deep-link
//     wrapping a JSON container, NOT a WG `.conf` body. This function
//     produces THAT link.
//
// AmneziaVPN's import path (canonical reference:
// `github.com/amnezia-vpn/config-decoder`):
//   1. Strip `vpn://` prefix.
//   2. base64url-decode (`Base64UrlEncoding | OmitTrailingEquals`).
//   3. Try `qUncompress` (Qt format: 4-byte big-endian uncompressed-size
//      prefix + zlib stream). If it fails, treat the bytes as raw JSON.
//   4. Parse JSON; look for `containers` array with at least one
//      `{"container": "amnezia-wireguard", "wireguard": {...}}` entry.
//   5. Extract the `last_config` string (itself a JSON-stringified
//      object) for the actual client material — keys + endpoint + IP.
//
// We always compress (it shortens the link by ~60% for our typical
// payload and Amnezia handles the zlib path natively). The fallback
// path is there for resilience, not for us to exploit.
//
// ErrorCode 900 ("конфигурация не содержит контейнеров") = symptom of
// passing a `wireguard://?conf=` link to Amnezia. That's what was
// happening pre-2026-05-17; this function fixes it.

/// Construct an AmneziaVPN deep-link (`vpn://...`) for `user` on this
/// `ctx`'s server. Returns the full ready-to-paste URL.
///
/// Errors mirror `share_link`'s contract: missing wireguard_pubkey or
/// malformed pubkey → `CoreError::Render`. Missing server pubkey secret
/// (`wireguard.server_public_key`) → `CoreError::MissingSecret`.
pub fn amnezia_share_link(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    // Same upfront validation as `share_link` — operator asking for a
    // link that can't authenticate should fail loudly, not silently
    // produce an unusable link.
    let user_pub = user.wireguard_pubkey.as_deref().ok_or_else(|| {
        CoreError::Render(format!(
            "user '{}' has no wireguard_pubkey — cannot mint an AmneziaVPN link",
            user.id.0
        ))
    })?;
    if !is_valid_wg_pubkey(user_pub) {
        return Err(CoreError::Render(format!(
            "user '{}' has malformed wireguard pubkey: {user_pub:?}",
            user.id.0
        )));
    }
    let server_pub = ctx.require("wireguard.server_public_key")?;
    let listen_port: u16 = ctx
        .secrets
        .get("wireguard.listen_port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(WIREGUARD_PORT);
    // Per-user /32 — derived from the user's index in `ctx.peers`.
    // Without this, multiple WG users on the same server would all
    // claim 10.66.0.2 and only the first would actually route.
    let peer_octet = peer_octet_for(ctx, user)?;
    let client_ip = format!("10.66.0.{peer_octet}");

    // Reuse the same .conf renderer Flow B uses — keeps the bytes
    // identical between AmneziaVPN's "import key" and the standalone
    // .conf download. If Pavel's user later switches apps, the
    // material doesn't drift.
    let nat_conf = render_client_conf(ctx, user)?;
    // The `last_config` inner JSON. Keys mirror amnezia-client's
    // `WireGuardClientConfig::toJson` field names verbatim
    // (`client_priv_key`, `client_pub_key`, `server_pub_key`,
    // `client_ip`, `allowed_ips`, `persistent_keep_alive`, `config`).
    // Missing the private key in `user.wireguard_private` is allowed
    // (operator-paranoid path with placeholder); Amnezia will then
    // fail to handshake — but that's the same trade-off as Flow B.
    let mut last_config = serde_json::Map::new();
    last_config.insert("config".into(), json!(nat_conf));
    last_config.insert("hostName".into(), json!(ctx.server.address));
    last_config.insert("port".into(), json!(listen_port));
    last_config.insert("client_ip".into(), json!(client_ip));
    last_config.insert(
        "client_priv_key".into(),
        json!(
            user.wireguard_private
                .as_deref()
                .unwrap_or(CLIENT_PRIVKEY_PLACEHOLDER)
        ),
    );
    last_config.insert("client_pub_key".into(), json!(user_pub));
    last_config.insert("server_pub_key".into(), json!(server_pub));
    last_config.insert(
        "allowed_ips".into(),
        json!(["0.0.0.0/0".to_string(), "::/0".to_string()]),
    );
    last_config.insert("persistent_keep_alive".into(), json!("25"));

    let wireguard_obj = json!({
        // Container-level WireGuardServerConfig fields. AmneziaVPN
        // doesn't strictly need them for a client-only key but its
        // parser expects the protocol object to exist; the
        // `last_config` string inside is what drives the actual VPN.
        "port": listen_port.to_string(),
        "transport_proto": "udp",
        "subnet_address": "10.66.0.0",
        "last_config": serde_json::to_string(&serde_json::Value::Object(last_config))
            .map_err(|e| CoreError::Render(format!("amnezia last_config serialise: {e}")))?,
    });

    let top = json!({
        "containers": [
            {
                "container": "amnezia-wireguard",
                "wireguard": wireguard_obj,
            }
        ],
        "defaultContainer": "amnezia-wireguard",
        "description": user.id.0,
        "dns1": "1.1.1.1",
        "dns2": "1.0.0.1",
        "hostName": ctx.server.address,
    });

    let json_bytes = serde_json::to_vec(&top)
        .map_err(|e| CoreError::Render(format!("amnezia top JSON serialise: {e}")))?;
    let compressed = qcompress_zlib(&json_bytes)?;
    let b64 = URL_SAFE_NO_PAD.encode(&compressed);
    Ok(format!("vpn://{b64}"))
}

/// Qt-style `qCompress` output: 4-byte big-endian uncompressed-size
/// prefix followed by a zlib stream. Compression level 8 mirrors
/// amnezia-client's `qCompress(data, 8)` call so a byte-equality test
/// against their output is meaningful.
///
/// We use `flate2` with the pure-Rust backend (`rust_backend` feature)
/// to keep the dep graph free of C shims — same hygiene rule as the
/// rest of the workspace (no openssl-sys, no native-tls).
fn qcompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    let len = u32::try_from(data.len())
        .map_err(|_| CoreError::Render("amnezia payload >4 GiB — refuse to compress".into()))?;
    let mut out = Vec::with_capacity(data.len() / 4 + 16);
    out.extend_from_slice(&len.to_be_bytes());
    let mut enc = ZlibEncoder::new(&mut out, Compression::new(8));
    enc.write_all(data)
        .map_err(|e| CoreError::Render(format!("amnezia zlib write: {e}")))?;
    enc.finish()
        .map_err(|e| CoreError::Render(format!("amnezia zlib finish: {e}")))?;
    Ok(out)
}

/// AmneziaWG `awg://` share-link for the operator's sing-box-lx-based
/// client app (Flow F — distinct from Flow B `wireguard://?conf=` and
/// Flow C AmneziaVPN `vpn://`; D=wgturn, E=dns-tunnel are taken).
/// Operator-specified format:
///
/// ```text
/// awg://<server_pubkey>@<host>:<port>?private_key=<client_priv_b64>
///   &address=<10.66.0.N/32>&keepalive=25
///   &jc=<int>&jmin=<int>&jmax=<int>&s1=<int>&s2=<int>&s3=<int>&s4=<int>
///   &h1=<uint32>&h2=<uint32>&h3=<uint32>&h4=<uint32>#<Name>
/// ```
///
/// Design choices pinned by the AWG protocol semantics:
///   * `<server_pubkey>` (userinfo) is the PEER the client dials; the
///     `private_key` is the CLIENT's, server-generated (`--gen-wireguard`)
///     so the link is one-tap (no on-device key-gen — the low-tech
///     north-star). A user without a server-generated private key is a
///     HARD error (a placeholder link can't connect).
///   * `s3=0 & s4=0` ALWAYS — vpnctl serves AmneziaWG 1.x; s3 (cookie)
///     and s4 (transport) padding are BIDIRECTIONAL, and the server
///     doesn't apply them, so a non-zero value would desync every data
///     packet and break the tunnel.
///   * `h1`-`h4` are single uint32 magic headers (the per-server minted
///     1.x values); the schema also permits `min-max` ranges (2.0), unused.
///   * The 9 obfs params are REQUIRED — the link only makes sense for an
///     AmneziaWG node, so a server with no minted obfs is a hard error.
///
/// Values are emitted verbatim (standard-base64 keys, decimal obfs) to
/// match the operator's literal schema; the consuming app parses them.
pub fn awg_share_link(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    let server_pub = ctx.require("wireguard.server_public_key")?;
    // Operator must have generated the client keypair server-side.
    let client_priv = user.wireguard_private.as_deref().ok_or_else(|| {
        CoreError::Render(format!(
            "user '{}' has no server-generated wireguard private key — \
             an awg:// link can't be one-tap without it (use --gen-wireguard)",
            user.id.0
        ))
    })?;
    // The matching public must be in the server's [Peer] list, else the
    // server can't authenticate this client. Mirror share_link's gate.
    let user_pub = user.wireguard_pubkey.as_deref().ok_or_else(|| {
        CoreError::Render(format!(
            "user '{}' has wireguard_private but no wireguard_pubkey — \
             the server [Peer] block can't authenticate this client",
            user.id.0
        ))
    })?;
    if !is_valid_wg_pubkey(user_pub) {
        return Err(CoreError::Render(format!(
            "user '{}' has malformed wireguard pubkey: {user_pub:?}",
            user.id.0
        )));
    }
    let listen_port: u16 = ctx
        .secrets
        .get("wireguard.listen_port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(WIREGUARD_PORT);
    let peer_octet = peer_octet_for(ctx, user)?;
    let address = format!("10.66.0.{peer_octet}/32");

    // AmneziaWG obfs are REQUIRED for this link — all-or-nothing (same
    // coherence contract as the .conf / client_config paths).
    let obfs = amneziawg_block(ctx).ok_or_else(|| {
        CoreError::Render(
            "server has no AmneziaWG obfuscation params minted — \
             an awg:// link requires them (deploy the amneziawg kernel so \
             bootstrap mints amneziawg.{jc,jmin,jmax,s1,s2,h1-h4})"
                .into(),
        )
    })?;
    let m = obfs
        .as_object()
        .ok_or_else(|| CoreError::Render("amneziawg block must be a JSON object".into()))?;
    // Secret values are stored as decimal strings; emit verbatim.
    let g = |k: &str| -> &str { m.get(k).and_then(|v| v.as_str()).unwrap_or("0") };

    let host = host_for_url(&ctx.server.address);
    let tag = utf8_percent_encode(&user.id.0, FRAGMENT);
    Ok(format!(
        "awg://{server_pub}@{host}:{listen_port}?private_key={client_priv}\
         &address={address}&keepalive=25\
         &jc={jc}&jmin={jmin}&jmax={jmax}&s1={s1}&s2={s2}&s3=0&s4=0\
         &h1={h1}&h2={h2}&h3={h3}&h4={h4}#{tag}",
        jc = g("jc"),
        jmin = g("jmin"),
        jmax = g("jmax"),
        s1 = g("s1"),
        s2 = g("s2"),
        h1 = g("h1"),
        h2 = g("h2"),
        h3 = g("h3"),
        h4 = g("h4"),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_shape_check_accepts_valid_44_char_base64() {
        // Real-looking WG pubkey shape: 43 base64 + final '='.
        let k = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";
        assert!(is_valid_wg_pubkey(k));
    }

    #[test]
    fn pubkey_shape_check_rejects_wrong_length() {
        assert!(!is_valid_wg_pubkey("too-short="));
        assert!(!is_valid_wg_pubkey(&"x".repeat(43)));
        assert!(!is_valid_wg_pubkey(&"x".repeat(45)));
    }

    #[test]
    fn pubkey_shape_check_requires_trailing_eq_pad() {
        // Right length, wrong padding.
        let k = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJksA";
        assert!(!is_valid_wg_pubkey(k));
    }

    #[test]
    fn pubkey_shape_check_rejects_invalid_charset() {
        // Right length+padding but contains a `:` (not base64-alphabet).
        let k = "qXFvJL5KLmM3Of:hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";
        assert!(!is_valid_wg_pubkey(k));
    }

    #[test]
    fn appears_in_sing_box_sub_is_false() {
        // CRITICAL: WireGuard's `client_config()` is an internal
        // `{ type: "wireguard", interface, peer }` object, NOT a valid
        // sing-box outbound. If the /sub handler doesn't skip it, the
        // whole envelope becomes unparseable and Hiddify / sing-box
        // drops every route (including the legit VLESS / TUIC ones).
        // Pin the trait override (same contract as wgturn / dns-tunnel).
        assert!(
            !WireGuard::new().appears_in_sing_box_sub(),
            "wireguard must opt OUT of the sing-box subscription"
        );
    }

    // ── AmneziaVPN deep-link tests ─────────────────────────────────
    //
    // Pin the byte-format invariants Amnezia's parser depends on:
    //   * `vpn://` prefix exactly,
    //   * base64-url (NO trailing `=` padding),
    //   * qCompress envelope = 4-byte BE length + zlib stream,
    //   * round-trip decoded JSON must contain a single container
    //     `amnezia-wireguard` with the user's WG material accessible
    //     under `containers[0].wireguard.last_config` (itself a
    //     JSON-stringified object).

    use std::collections::HashMap;
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};

    fn fake_user() -> User {
        User {
            id: UserId("alex".into()),
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            tuic_password: None,
            wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
            wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
            sub_token: Some("st".into()),
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn fake_server() -> Server {
        Server {
            id: ServerId("vps1".into()),
            address: "198.51.100.42".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("wireguard".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn fake_secrets() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(
            "wireguard.server_public_key".into(),
            "Qhh7nQwL+0fH3iZ8VAEcvVNlEMU8r9SiH3LzAh6Kj3o=".into(),
        );
        m
    }

    #[test]
    fn qcompress_zlib_emits_4byte_be_length_prefix() {
        let data = b"hello amnezia";
        let out = qcompress_zlib(data).unwrap();
        assert!(out.len() >= 4);
        let len_prefix = u32::from_be_bytes([out[0], out[1], out[2], out[3]]);
        assert_eq!(len_prefix as usize, data.len());
        // Zlib stream starts with 0x78 (CMF) — every qCompress output
        // does, regardless of level. Pin it so a future swap of the
        // backend (deflate-rs etc) that emits raw-deflate instead of
        // zlib silently breaks Amnezia parsing.
        assert_eq!(out[4], 0x78, "byte 4 must be zlib CMF magic 0x78");
    }

    /// Pin compression level 8 by comparing it to level 1 on the SAME
    /// non-trivial payload (a JSON-like blob where the level actually
    /// matters — pure repetition compresses identically at every
    /// level via RLE). If a future refactor drops to `Compression::fast()`,
    /// level-1 output will be ≥ level-8 output and this test fires.
    #[test]
    fn qcompress_zlib_uses_high_compression_level() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        // Mixed text — enough variation that the encoder's match finder
        // has work to do; level 8 (full lazy matching) beats level 1
        // (greedy) by several bytes on this shape.
        let payload = br#"{"containers":[{"container":"amnezia-wireguard","wireguard":{"port":"51820","transport_proto":"udp","subnet_address":"10.66.0.0","last_config":"{\"client_ip\":\"10.66.0.2\",\"hostName\":\"203.0.113.7\",\"port\":51820,\"persistent_keep_alive\":\"25\"}"}}],"defaultContainer":"amnezia-wireguard","description":"test-user","hostName":"203.0.113.7"}"#;

        let our = qcompress_zlib(payload).unwrap();

        // Reference: same payload, level 1 (Compression::fast()).
        let mut fast_out = Vec::new();
        fast_out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        let mut enc = ZlibEncoder::new(&mut fast_out, Compression::fast());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap();

        assert!(
            our.len() <= fast_out.len(),
            "qcompress_zlib (claimed level 8) produced {} bytes; level-1 reference produced {}. Level 8 must be at least as compact as level 1.",
            our.len(),
            fast_out.len()
        );
        // Also confirm a non-trivial savings (>= 4 bytes) so the
        // test catches "we switched to default(level=6)" — default
        // compression is within 1-2 bytes of fast() on this size.
        assert!(
            our.len() + 4 <= fast_out.len(),
            "level-8 output {} bytes vs level-1 {} — savings <4 bytes suggests level was dropped below 8",
            our.len(),
            fast_out.len()
        );
    }

    #[test]
    fn amnezia_share_link_starts_with_vpn_prefix_and_is_base64url_no_pad() {
        let server = fake_server();
        let secrets = fake_secrets();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = fake_user();
        let link = amnezia_share_link(&ctx, &user).unwrap();
        assert!(link.starts_with("vpn://"), "wrong scheme prefix: {link:?}");
        let payload = link.strip_prefix("vpn://").unwrap();
        assert!(
            !payload.ends_with('='),
            "Amnezia parser requires base64-url WITHOUT padding (OmitTrailingEquals): {payload:?}"
        );
        // base64url alphabet only — `+`/`/` would fail Amnezia's
        // `Base64UrlEncoding` decode.
        for c in payload.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-base64url char {c:?} in payload"
            );
        }
    }

    #[test]
    fn amnezia_share_link_roundtrips_to_container_json_with_last_config() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        let server = fake_server();
        let secrets = fake_secrets();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = fake_user();
        let link = amnezia_share_link(&ctx, &user).unwrap();
        let b64 = link.strip_prefix("vpn://").unwrap();
        let raw = URL_SAFE_NO_PAD.decode(b64).unwrap();
        assert!(
            raw.len() > 4,
            "envelope must include the 4-byte length prefix"
        );
        let _len_prefix = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let mut dec = ZlibDecoder::new(&raw[4..]);
        let mut json_bytes = Vec::new();
        dec.read_to_end(&mut json_bytes).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        // Top-level shape Amnezia's importer reads.
        assert_eq!(v["defaultContainer"], "amnezia-wireguard");
        assert_eq!(v["hostName"], "198.51.100.42");
        assert_eq!(v["description"], "alex");
        assert!(v["containers"].is_array());
        let c0 = &v["containers"][0];
        assert_eq!(c0["container"], "amnezia-wireguard");
        let wg = &c0["wireguard"];
        assert_eq!(wg["transport_proto"], "udp");
        assert_eq!(wg["port"], "51820");
        // `last_config` is a JSON-stringified inner object — Amnezia
        // re-parses it from string. Pin both the stringification AND
        // the inner field names.
        let inner_str = wg["last_config"]
            .as_str()
            .expect("last_config must be a string");
        let inner: serde_json::Value = serde_json::from_str(inner_str).unwrap();
        assert_eq!(
            inner["client_pub_key"],
            user.wireguard_pubkey.as_deref().unwrap()
        );
        assert_eq!(
            inner["client_priv_key"],
            user.wireguard_private.as_deref().unwrap()
        );
        assert_eq!(
            inner["server_pub_key"],
            secrets["wireguard.server_public_key"]
        );
        assert_eq!(inner["client_ip"], "10.66.0.2");
        assert_eq!(inner["port"], 51820);
        assert_eq!(inner["hostName"], "198.51.100.42");
        assert_eq!(
            inner["allowed_ips"],
            serde_json::json!(["0.0.0.0/0", "::/0"])
        );
        // The `config` field carries the full .conf body (Interface+Peer).
        let conf = inner["config"]
            .as_str()
            .expect("inner config must be a string");
        assert!(conf.contains("[Interface]"));
        assert!(conf.contains("[Peer]"));
        assert!(conf.contains("Endpoint = 198.51.100.42:51820"));
    }

    #[test]
    fn amnezia_share_link_errors_on_missing_user_wireguard_pubkey() {
        let server = fake_server();
        let secrets = fake_secrets();
        let ctx = RenderCtx::new(&server, &secrets);
        let mut user = fake_user();
        user.wireguard_pubkey = None;
        let err = amnezia_share_link(&ctx, &user).unwrap_err();
        assert!(
            format!("{err}").contains("no wireguard_pubkey"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn amnezia_share_link_errors_on_missing_server_pubkey_secret() {
        let server = fake_server();
        let secrets = HashMap::new(); // missing wireguard.server_public_key
        let ctx = RenderCtx::new(&server, &secrets);
        let user = fake_user();
        let err = amnezia_share_link(&ctx, &user).unwrap_err();
        assert!(
            format!("{err}").contains("wireguard.server_public_key"),
            "expected MissingSecret(wireguard.server_public_key), got: {err}"
        );
    }

    // ── awg:// share-link (Flow D — sing-box-lx client app) ────────

    fn fake_secrets_awg() -> HashMap<String, String> {
        let mut m = fake_secrets(); // wireguard.server_public_key
        for (k, v) in [
            ("jc", "7"),
            ("jmin", "60"),
            ("jmax", "140"),
            ("s1", "30"),
            ("s2", "90"),
            ("h1", "1111111111"),
            ("h2", "2022222222"),
            ("h3", "333333333"),
            ("h4", "444444444"),
        ] {
            m.insert(format!("amneziawg.{k}"), v.into());
        }
        m
    }

    #[test]
    fn awg_share_link_matches_operator_schema() {
        let server = fake_server();
        let secrets = fake_secrets_awg();
        let ctx = RenderCtx::new(&server, &secrets);
        let user = fake_user();
        let link = awg_share_link(&ctx, &user).unwrap();

        // scheme + userinfo(server pubkey) @ host:port
        assert!(link.starts_with("awg://"), "scheme: {link}");
        assert!(
            link.contains(&format!(
                "awg://{}@198.51.100.42:51820?",
                secrets["wireguard.server_public_key"]
            )),
            "userinfo/host/port wrong: {link}"
        );
        // client private key = the server-generated one
        assert!(link.contains(&format!(
            "private_key={}",
            user.wireguard_private.as_deref().unwrap()
        )));
        assert!(link.contains("address=10.66.0.2/32"));
        assert!(link.contains("keepalive=25"));
        // obfs verbatim from secrets
        assert!(link.contains("jc=7"));
        assert!(link.contains("jmin=60"));
        assert!(link.contains("jmax=140"));
        assert!(link.contains("s1=30"));
        assert!(link.contains("s2=90"));
        // s3/s4 ALWAYS 0 (1.x server — bidirectional, unused server-side)
        assert!(link.contains("s3=0"));
        assert!(link.contains("s4=0"));
        assert!(link.contains("h1=1111111111"));
        assert!(link.contains("h4=444444444"));
        // fragment = user id
        assert!(link.ends_with("#alex"), "fragment: {link}");
    }

    #[test]
    fn awg_share_link_errors_without_server_generated_private_key() {
        let server = fake_server();
        let secrets = fake_secrets_awg();
        let ctx = RenderCtx::new(&server, &secrets);
        let mut user = fake_user();
        user.wireguard_private = None; // operator-provided-pubkey path
        let err = awg_share_link(&ctx, &user).unwrap_err();
        assert!(
            format!("{err}").contains("no server-generated wireguard private key"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn awg_share_link_errors_without_obfs_secrets() {
        // No amneziawg.* minted (e.g. a vanilla wg server) → hard error;
        // an awg:// link only makes sense for an AmneziaWG node.
        let server = fake_server();
        let secrets = fake_secrets(); // server pubkey only, no obfs
        let ctx = RenderCtx::new(&server, &secrets);
        let user = fake_user();
        let err = awg_share_link(&ctx, &user).unwrap_err();
        assert!(
            format!("{err}").contains("obfuscation params"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn awg_share_link_emits_base64_key_verbatim() {
        // The operator's schema places the standard-base64 private key RAW
        // in the query value; their sing-box-lx app parses values verbatim
        // (NOT application/x-www-form-urlencoded, under which `+` → space).
        // Pin verbatim emission of a key containing `+` and `/` so a future
        // percent-encoding change is a deliberate, test-breaking decision.
        let server = fake_server();
        let secrets = fake_secrets_awg();
        let ctx = RenderCtx::new(&server, &secrets);
        let mut user = fake_user();
        let key = "ab+CD/ef+GH/ijKLmnopQRSTuvwx0123456789ABCxz=";
        user.wireguard_private = Some(key.into());
        let link = awg_share_link(&ctx, &user).unwrap();
        assert!(
            link.contains(&format!("private_key={key}")),
            "private key must be emitted verbatim (raw +,/,= — not url-encoded): {link}"
        );
    }
}
