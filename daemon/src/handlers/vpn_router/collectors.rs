//! URI collectors and formatters for the ninitux subscription compatibility endpoint.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{RenderCtx, User, UserId};

use super::compat::server_display_label;
use crate::app::AppState;

/// Matches `urllib.parse.quote(s, safe="")` — encodes everything
/// except ASCII alphanumerics + `-._~`. Used for the URL fragment in
/// each vless:// link, mirroring `_make_uri_for_inbound` in
/// `subscription-server/app/ssh_manager.py`.
pub(crate) const NINITUX_QUOTE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Build a single ninitux-format vless URI. Caller provides the
/// pre-stripped server tag (`"de-01"` not `"vps-de-01"`).
///
/// Eight scalar args is a lot, but they're all independent strings
/// passed straight through to `format!()`; bundling them into a
/// `RenderCtx`-style struct would mean a copy at every callsite (the
/// caller already holds the values as `&str` from separate sources:
/// `Server.address`, `server_secrets["vless.public_key"]`, etc.). The
/// `clippy::too_many_arguments` lint targets readability problems
/// from cohesive parameters that ought to be grouped — these are
/// not. Pinned by `render_vless_uri_matches_ninitux_byte_format`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_vless_uri(
    server_ip: &str,
    port: u16,
    sni: &str,
    pbk: &str,
    sid: &str,
    client_uuid: &str,
    server_tag: &str,
    client_name: &str,
) -> String {
    // Param order: encryption, type, security, pbk, fp, sni, sid, spx, flow.
    //
    // 2026-05-23 quickfix (Pavel + другой пользователь):
    // «через V2rayTun появляются в списке конфиги, при подключении
    // интернет не работает; через Streisand / Shadowrocket — работает».
    // Symptom signature: V2Ray-core-based clients (V2rayTun, v2rayN)
    // require `encryption=none` even for REALITY (where encryption is
    // not actually used — it's a no-op marker meaning «no extra
    // encryption layer»). Without it, the V2Ray-core parser falls
    // back to its default («auto») which doesn't exist for VLESS,
    // and the dial silently returns ECONNRESET-shaped failures —
    // the client shows «connected» but no packets flow.
    //
    // Streisand / Shadowrocket / sing-box / Hiddify tolerate the
    // missing param. ADDING it doesn't change their behaviour:
    // `encryption=none` is the canonical VLESS marker, a no-op for
    // every client that already worked. So this is safe for every
    // platform tested in production.
    //
    // The bash legacy `/sub/<token>` path always included
    // `encryption=none` (byte-equality with `get-vless.sh`); we
    // intentionally dropped it for the ninitux endpoint when
    // subscription-server was decommissioned. That decision is now
    // reverted — every endpoint emits the same vless:// shape.
    let pbk_e = utf8_percent_encode(pbk, NINITUX_QUOTE);
    let sni_e = utf8_percent_encode(sni, NINITUX_QUOTE);
    let sid_e = utf8_percent_encode(sid, NINITUX_QUOTE);
    // `fp=randomized` (was `fp=chrome` until 2026-06-16).
    //
    // 2026-06-16 (Pavel + multiviruss/chachkamuti): V2rayTun, Streisand and
    // Happ stopped connecting to REALITY while Shadowrocket and Android
    // NekoRay kept working — on the SAME Wi-Fi and the SAME server. RU DPI
    // (TSPU) began fingerprinting the static Chrome uTLS ClientHello that
    // open-core clients emit on `fp=chrome` and RST-resetting those REALITY
    // sessions; Shadowrocket's own (different) ClientHello slipped through.
    // Ruled out server-side: Xray-core 26.3.27 AND sing-box 1.13.7/1.13.12
    // both complete the handshake from a clean datacenter, so the server,
    // config, version and flow are all fine — only the on-path uTLS
    // fingerprint mattered. Field-confirmed: the exact same is/REALITY link
    // failed on `fp=chrome`, connected on `fp=randomized` in v2rayTun.
    // `randomized` emits a fresh randomized ClientHello per handshake so the
    // static-fingerprint rule has nothing to match. Mirrors
    // `vless_reality.rs::REALITY_UTLS_FP` (Protocol-trait share_link path).
    let params = format!(
        "encryption=none&type=tcp&security=reality&pbk={pbk_e}&fp=randomized&sni={sni_e}&sid={sid_e}&spx=%2F&flow=xtls-rprx-vision"
    );

    // Fragment format (post-2026-05-20 + post-rename + operator-side
    // identification re-added):
    //   `{Country} VLESS ~{client_name}`
    // separator `~` chosen because it's the ONLY ASCII char that:
    //   1. is RFC-3986 unreserved (1 byte URL-encoded, no escape)
    //   2. doesn't appear in any of the existing 33 production
    //      user names (so the parser splitting on `~` is unambiguous)
    //
    // client_name is back in the label after Pavel's operational
    // concern: when a user reports a problem, the operator needs to
    // identify them from a screenshot of the outbound list (otherwise
    // they have to ask for device_id which most users can't find).
    // The sing-box log on the VPN node also carries `[user_name]` for
    // every connection, so the chain is end-to-end greppable by
    // username.
    let label = format!("{server_tag} VLESS ~{client_name}");
    let fragment = utf8_percent_encode(&label, NINITUX_QUOTE);

    // IPv6 literals must be bracketed in the authority
    // (`[2a00:1450::1]:443`) or every client parser splits on the wrong
    // `:` and the link is dead. Same helper the Protocol-trait
    // `share_link` path (`/sub`) uses, so both endpoints render
    // byte-identical authorities.
    let host = host_for_url(server_ip);

    format!("vless://{client_uuid}@{host}:{port}?{params}#{fragment}")
}

/// Look up all server-grant rows for `user_id` and turn each into a
/// ninitux-format vless URI string. Skips servers that don't carry
/// the `vless.public_key` / `vless.short_id` secrets (i.e. the
/// vless+reality inbound isn't provisioned there).
pub(crate) async fn collect_vless_uris_for_user(
    state: &AppState,
    user_id: &UserId,
    client_name: &str,
) -> Result<Vec<String>, String> {
    let servers = state
        .inv
        .servers_for_user(user_id)
        .await
        .map_err(|e| format!("servers_for_user: {e}"))?;

    let mut uris: Vec<String> = Vec::with_capacity(servers.len());
    for server in &servers {
        // Auto-suppress (migration 0030): skip a server the health
        // monitor flagged unreachable (per-server opt-in); auto-restores
        // on recovery. DB error → don't suppress (keep it in the sub).
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }
        // Visibility filter (migration 0018): ninitux endpoint emits
        // VLESS+REALITY only, so skip this server if vless+reality is
        // hidden globally OR per-this-user. Skipping = NO URI for this
        // server in the rendered config; user still has access via
        // /sub/<token> (which has its own filter) OR cached URIs (the
        // sing-box inbound stays running on the node).
        let visible = state
            .inv
            .visible_protocols_for_subscription(user_id, &server.id)
            .await
            .map_err(|e| format!("visible_protocols_for_subscription: {e}"))?;
        let vless_id = vpnctl_core::ProtocolId("vless+reality".to_string());
        if !visible.contains(&vless_id) {
            continue;
        }

        let secrets = state
            .inv
            .list_server_secrets(&server.id)
            .await
            .map_err(|e| format!("list_server_secrets: {e}"))?;
        let pbk = match secrets.get("vless.public_key") {
            Some(v) => v.as_str(),
            None => continue,
        };
        let sid = match secrets.get("vless.short_id") {
            Some(v) => v.as_str(),
            None => continue,
        };
        let sni = secrets
            .get("vless.sni")
            .map(String::as_str)
            .unwrap_or(vpnctl_protocols::DEFAULT_REALITY_SNI);

        // Per-server uuid override (Phase 1 + 2 merge). When no
        // override is pinned, falls back to user.uuid via COALESCE
        // inside the inventory layer — byte-stable with pre-Phase-2
        // behaviour for any user whose name doesn't match a
        // subscription-server client.
        let client_uuid = match state
            .inv
            .client_uuid_for(user_id, &server.id)
            .await
            .map_err(|e| format!("client_uuid_for: {e}"))?
        {
            Some(u) => u,
            None => continue,
        };

        // Per-server VLESS listen-port override (post-2026-05-26).
        // When a co-tenant service owns :443 on the host (e.g. legacy
        // 3x-ui Docker on 194.87.222.111), the operator sets
        // `vless.listen_port` server-secret to e.g. 8443. The ninitux
        // endpoint must emit the same alternate port, else clients hit
        // one port and the server binds another → handshake never
        // starts. Resolved through the protocols crate's single source
        // of truth so it can never drift from what sing-box binds /
        // share_link emits (cdn incident follow-up, PR #139 review).
        let port: u16 = vpnctl_protocols::reality_listen_port(&secrets);

        let custom_name = state
            .inv
            .server_display_name(&server.id)
            .await
            .map_err(|e| format!("server_display_name: {e}"))?;
        let server_display = server_display_label(&server.id.0, custom_name.as_deref());
        uris.push(render_vless_uri(
            &server.address,
            port,
            sni,
            pbk,
            sid,
            &client_uuid,
            &server_display,
            client_name,
        ));
    }
    Ok(uris)
}

/// Collect ninitux-format share-link URIs for `user` for ONE protocol
/// `pid` beyond the byte-stable vless render (naive, hysteria2, …) — one URI
/// per granted server where `pid` is enabled + visible (NM-10) and, when
/// `require_secret` is `Some`, provisioned with that server secret. Mirrors
/// the vless path's skip rules (auto-suppress + the SAME
/// `visible_protocols_for_subscription` filter) but renders through the
/// registry's `share_link`, so each protocol's URI format has ONE source of
/// truth (`crates/protocols/src/<proto>.rs`) instead of a hand-rolled
/// renderer per protocol here.
///
/// **Opt-in by grant + visibility.** Returns an empty Vec — never an error —
/// when `pid` isn't registered or the user isn't entitled to it on any
/// server. The caller appends the result AFTER all vless URIs, so a user not
/// opted into `pid` keeps a byte-identical vless blob: their vless cannot
/// break. Hiding `pid` on a server (NM-10) drops it here on the very next
/// request → instant per-request kill-switch, no redeploy.
///
/// **Failure-isolated.** A single server's render error is logged and
/// skipped (every other server — and every vless line — still renders). Only
/// a top-level inventory error propagates, and the caller treats even that as
/// "serve what we have", so an extra protocol is strictly additive and can
/// never drop a user's vless.
pub(crate) async fn collect_extra_protocol_uris(
    state: &AppState,
    user: &User,
    pid: &vpnctl_core::ProtocolId,
    label_tag: &str,
    require_secret: Option<&str>,
) -> Result<Vec<String>, String> {
    // Protocol not registered in this daemon's registry → nothing to add.
    let Some(proto) = state.registry.protocol(pid) else {
        return Ok(Vec::new());
    };

    let servers = state
        .inv
        .servers_for_user(&user.id)
        .await
        .map_err(|e| format!("servers_for_user: {e}"))?;

    // A node exposing BOTH naive and HY2 tags both share-links with a shared
    // `pair=<server id>` query param, so a client can route UDP — which naive
    // can't carry — through the co-located HY2 on the same node.
    let naive_pid = vpnctl_core::ProtocolId("naive".to_string());
    let hy2_pid = vpnctl_core::ProtocolId("hysteria2".to_string());
    let mut uris: Vec<String> = Vec::new();
    for server in &servers {
        // Same auto-suppress (migration 0030) skip as the vless path.
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }
        // OR-semantics visibility (NM-10): server-hidden OR per-user-denied
        // → protocol absent for this (user, server). This is the kill-switch.
        let visible = state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await
            .map_err(|e| format!("visible_protocols_for_subscription: {e}"))?;
        if !visible.contains(pid) {
            continue;
        }
        let secrets = state
            .inv
            .list_server_secrets(&server.id)
            .await
            .map_err(|e| format!("list_server_secrets: {e}"))?;
        // Skip a server not provisioned with the protocol's required server
        // secret (e.g. naive needs `naive.domain`) — the same way the vless
        // path skips a missing public_key / short_id.
        if let Some(req) = require_secret {
            if !secrets.contains_key(req) {
                continue;
            }
        }
        let ctx = RenderCtx::new(server, &secrets);
        match proto.share_link(&ctx, user) {
            Ok(link) => {
                // Re-label the URI fragment with the operator's server label
                // (display_name / country) in the ninitux house style
                // "{label} {TAG} ~{client}", matching the vless lines — the
                // protocol's own share_link only knows the username. Only the
                // cosmetic fragment after '#' is swapped; the URI STRUCTURE
                // the protocol built is left intact. A display_name lookup
                // error falls back to the default label (ISO map / id).
                let custom = state
                    .inv
                    .server_display_name(&server.id)
                    .await
                    .ok()
                    .flatten();
                let label = server_display_label(&server.id.0, custom.as_deref());
                let fragment = format!("{label} {label_tag} ~{}", user.id.0);
                let encoded = utf8_percent_encode(&fragment, NINITUX_QUOTE).to_string();
                let mut out = relabel_uri_fragment(&link, &encoded);
                // Co-located naive↔HY2 pairing (UX-3, migration 0031). Stamp
                // the naive/HY2 link with `pair=<server id>` in the query when
                // ALL hold: (a) THIS server has UDP pairing OPTED-IN by the
                // operator (`udp_pair_enabled`), and (b) it exposes BOTH naive
                // and HY2. Same node → same pair; a naive- or HY2-only node, or
                // a node without the opt-in → none; other nodes → their own id.
                // Single-server only by construction (the tag IS the server
                // id). Opaque to the client (it only matches naive↔HY2 on it);
                // unknown to other clients (silently ignored). DB error on the
                // flag → no pair (fail-safe; the link still works unpaired).
                if (pid == &naive_pid || pid == &hy2_pid)
                    && visible.contains(&naive_pid)
                    && visible.contains(&hy2_pid)
                    && state
                        .inv
                        .is_server_udp_pair_enabled(&server.id)
                        .await
                        .unwrap_or(false)
                {
                    let pair = utf8_percent_encode(&server.id.0, NINITUX_QUOTE).to_string();
                    out = add_query_param(&out, "pair", &pair);
                }
                uris.push(out);
            }
            Err(e) => {
                // One server's failure must not abort the others or the
                // vless lines — log + skip, never propagate.
                tracing::warn!(
                    target = "vpnctld::vpn_router",
                    user = %user.id,
                    server = %server.id,
                    protocol = %pid.0,
                    error = %e,
                    "extra-protocol share_link failed; skipping this server"
                );
            }
        }
    }
    Ok(uris)
}

/// Collect `awg://` AmneziaWG links for the ninitux subscription blob —
/// one per granted server that (a) runs the `amneziawg` kernel, (b) has
/// `wireguard` VISIBLE for this (user, server) (NM-10 hidden/deny gate —
/// `hidden=1` is the operator's advertise kill-switch), and (c) is
/// provisioned with the per-server obfs + server keypair.
///
/// Special-cased (NOT in `EXTRA_PROTOCOLS`) because `awg://` is rendered
/// by [`vpnctl_protocols::awg_share_link`], not the generic
/// `Protocol::share_link`, and needs a per-peer [`RenderCtx::with_peers`]:
/// the client's `/32` octet must match the server's live `awg0.conf`
/// `[Peer]` block 1:1. Both sides derive the octet from the SAME
/// `users_for_server` (ORDER BY id) list, so the subscription octet
/// matches the deployed config on every pull — a polling client
/// self-heals after any user-churn redeploy (the only stale-octet case
/// is a never-re-pulled one-shot artefact, which this endpoint isn't).
///
/// The `awg://` line lands strictly AFTER every vless (and the other
/// extras), so a client build without AmneziaWG support ignores the
/// trailing line and keeps every vless (forward-compatible rollout, same
/// posture as `dns-tunnel`). Failure-isolated: a server's render error is
/// logged + skipped, never dropping a user's vless. Returns a Vec (never
/// an error) for the same "serve what we have" contract.
pub(crate) async fn collect_awg_subscription_uris(state: &AppState, user: &User) -> Vec<String> {
    let servers = match state.inv.servers_for_user(&user.id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, error = %e, "awg: servers_for_user failed");
            return Vec::new();
        }
    };
    let wg_pid = vpnctl_core::ProtocolId("wireguard".to_string());
    let mut uris: Vec<String> = Vec::new();
    for server in &servers {
        // `awg://` only makes sense on an AmneziaWG node (obfs is a
        // property of that kernel); skip cleanly so a vanilla sing-box
        // WG server never hits awg_share_link's missing-obfs error path.
        if !server.kernels.iter().any(|k| k.0 == "amneziawg") {
            continue;
        }
        // Same auto-suppress (migration 0030) skip as the vless path.
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }
        // NM-10 visibility: server-hidden OR per-user-denied → no awg://
        // for this (user, server). This is the operator's kill-switch.
        match state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await
        {
            Ok(vis) if vis.contains(&wg_pid) => {}
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, server = %server.id, error = %e, "awg: visibility lookup failed; skipping");
                continue;
            }
        }
        let secrets = match state.inv.list_server_secrets(&server.id).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, server = %server.id, error = %e, "awg: list_server_secrets failed; skipping");
                continue;
            }
        };
        // `with_peers` so the per-user octet matches the kernel's awg0.conf.
        let peers = match state.inv.users_for_server(&server.id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, server = %server.id, error = %e, "awg: users_for_server failed; skipping");
                continue;
            }
        };
        let ctx = RenderCtx::with_peers(server, &secrets, &peers);
        // Pass the global `user` (not a per-server-UUID-resolved copy like
        // the vless / admin-card paths): `awg_share_link` keys off
        // `wireguard_private`/`wireguard_pubkey` + the peer octet, never
        // `user.uuid`, so the per-server-uuid step is intentionally omitted.
        // The octet (2 + position in this full peers list) matches the
        // kernel's awg0.conf [Peer] octet, which enumerates the SAME list
        // and counts pubkey-less granted users in the index too.
        match vpnctl_protocols::awg_share_link(&ctx, user) {
            Ok(link) => {
                // Re-label the fragment to the ninitux house style
                // "{label} AWG ~{client}", matching the vless / extra lines.
                let custom = state
                    .inv
                    .server_display_name(&server.id)
                    .await
                    .ok()
                    .flatten();
                let label = server_display_label(&server.id.0, custom.as_deref());
                let fragment = format!("{label} AWG ~{}", user.id.0);
                let encoded = utf8_percent_encode(&fragment, NINITUX_QUOTE).to_string();
                uris.push(relabel_uri_fragment(&link, &encoded));
            }
            Err(e) => {
                tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, server = %server.id, error = %e, "awg share_link failed; skipping this server");
            }
        }
    }
    uris
}

/// Swap the `#fragment` of a share-link URI for `encoded_fragment` (already
/// percent-encoded). The protocols percent-encode every other `#`, so the
/// first literal `#` is the fragment separator; a URI with no `#` just gets
/// one appended. (The one field interpolated raw is `server.address`; a `#`
/// there would already corrupt the URI upstream of this — not a new failure
/// mode, and a `#` in an IP/hostname is invalid anyway.)
pub(crate) fn relabel_uri_fragment(uri: &str, encoded_fragment: &str) -> String {
    match uri.find('#') {
        Some(i) => format!("{}#{encoded_fragment}", &uri[..i]),
        None => format!("{uri}#{encoded_fragment}"),
    }
}

/// Insert `key=encoded_value` into the query of a share-link URI, BEFORE any
/// `#fragment`. Uses `?` when the URI has no query yet, else `&`. The
/// protocols percent-encode every other `?`/`#`, so the first of each is the
/// genuine query / fragment boundary.
pub(crate) fn add_query_param(uri: &str, key: &str, encoded_value: &str) -> String {
    let (head, frag) = match uri.find('#') {
        Some(i) => (&uri[..i], &uri[i..]),
        None => (uri, ""),
    };
    let sep = if head.contains('?') { '&' } else { '?' };
    format!("{head}{sep}{key}={encoded_value}{frag}")
}

/// Encode the joined URIs as base64. Empty input → empty output.
pub(crate) fn make_config_blob(uris: &[String]) -> Option<String> {
    if uris.is_empty() {
        return None;
    }
    let joined = uris.join("\n");
    Some(BASE64_STANDARD.encode(joined.as_bytes()))
}
