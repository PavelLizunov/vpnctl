use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, RenderCtx, Result, User};

use super::helpers::{
    CLIENT_PRIVKEY_PLACEHOLDER, FRAGMENT, is_valid_wg_pubkey, listen_port, peer_octet_for,
};
use super::render::render_client_conf;

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
pub(crate) fn amneziawg_block(ctx: &RenderCtx<'_>) -> Option<serde_json::Value> {
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
    let listen_port: u16 = listen_port(ctx.secrets);
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
pub(crate) fn qcompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
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
/// Flow C AmneziaVPN `vpn://`).
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
    let listen_port: u16 = listen_port(ctx.secrets);
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
