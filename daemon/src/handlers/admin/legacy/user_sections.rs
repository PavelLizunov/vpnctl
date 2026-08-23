use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

use super::super::audit::{action_kind, summarize_audit_payload};
use super::super::helpers::*;
use super::super::servers::*;
use super::super::users::mask_secret;
use super::*;
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};
use vpnctl_core::humanize::format_size_bytes;
/// Build the canonical sub URL the QR encodes. Uses the request's `Host`
/// header so the QR is reachable from wherever the operator opened the
/// admin from (LAN IP, VPN IP, or the external one when we add reverse
/// proxy). Defaults to a sensible LAN guess if the header is missing —
/// rare in practice, but not worth crashing over.
pub(crate) fn sub_url(headers: &HeaderMap, sub_token: &str) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:18402");
    // Daemon is HTTP-only on LAN — when an operator stands up TLS in
    // front of vpnctld this becomes a config knob.
    format!("http://{host}/sub/{sub_token}")
}

/// Public production subscription URL — the one a client mobile app
/// will actually fetch from. Renders the ninitux-compat endpoint
/// served by `vpnctld` since the Phase 5 cutover (2026-05-19): nginx
/// on 192.168.0.207 reverse-proxies `https://ninitux.com/api/v1/app/config/{device_id}`
/// to `http://192.168.0.236:18402/api/v1/app/config/{device_id}`,
/// byte-equivalent for every registered user.
///
/// Returns `None` when the device_id fails the shape gate
/// (`vpnctl_crypto::is_valid_vpn_router_device_id`). Defensive —
/// `SqliteInventory::set_vpn_router_device_id` enforces the same
/// gate before writing, so a valid row should always pass; the
/// `None` branch closes the gap where a malformed device_id lands
/// in the DB via migration / external mutation / direct sqlite
/// edit. Without this check, a value like `evil?h=x.com` would
/// render as `https://ninitux.com/api/v1/app/config/evil?h=x.com`
/// and the QR a user scans would point at an attacker-controlled
/// path on a third-party host.
///
/// Hostname is hard-coded because the cutover IS the contract —
/// every client in production polls this exact URL on a fixed
/// schedule. Reading from a per-request `Host` header would
/// silently drift the displayed URL if the operator opens the admin
/// UI via IP vs hostname. (Review-agent flagged the hard-coding as
/// a config-knob debt — TODO: promote to `VPNCTLD_PUBLIC_SUBSCRIPTION_BASE_URL`
/// env var with this value as default, so staging deployments can
/// override. Defer; current deployment is a single domain.)
pub(crate) fn ninitux_url(device_id: &str) -> Option<String> {
    if !vpnctl_crypto::is_valid_vpn_router_device_id(device_id) {
        return None;
    }
    Some(format!("https://ninitux.com/api/v1/app/config/{device_id}"))
}

/// Render an inline SVG QR for the given URL. Returns
/// `<div class="ed-qr">...<svg>...</svg>...</div>`. The SVG carries
/// no scripts, no external refs.
/// Symmetric share-link card used by both Flow A (sing-box subscription
/// URL) and Flow B (WG-native wireguard:// link) on the user-detail page.
///
/// Layout: QR on the left, masked one-liner preview + read-only textarea
/// (click → select-all, plus triple-click as a JS-free fallback) +
/// italic footnote on the right. Same DOM shape for both flows so the
/// operator never has to switch mental models between "Hiddify column"
/// and "AmneziaVPN column" — the difference is only what bytes go into
/// QR + textarea.
///
/// **Single `link` parameter** (was `(qr_url, full_link)` until
/// review-agent 2026-05-17): the QR encoding and the copy text MUST
/// be the same bytes — otherwise the recipient scans one URL and the
/// operator hand-copies another, and a low-tech recipient («ctrl+c
/// уже много», CLAUDE.md) won't notice. Collapsing to one arg makes
/// the mismatch unrepresentable at the type level.
///
/// The textarea carries `data-select-on-click` (admin.js delegated
/// listener) so a single click selects the full link — the old inline
/// `onclick` was refused by the CSP and silently did nothing. Avoids
/// the Clipboard API which requires a secure context (HTTPS or
/// localhost) — the admin UI runs over plain HTTP on the homelab LAN,
/// so navigator.clipboard would silently fail on 192.168.0.236.
/// Triple-click is the JS-free fallback every browser supports; the
/// `title` attribute spells out both interactions.
pub(crate) fn share_link_card(link: &str, footnote: &Markup) -> Markup {
    html! {
        // `min-height: 244px` matches the QR card's outer dimension
        // (220 QR + 12 padding × 2 = 244). Forces every Flow card
        // (A/B/C) to the same row height regardless of URL length,
        // so the three-column grid above is visually aligned.
        //
        // The right-side `min-width: 0` is required so the flex child
        // can shrink below its natural width — otherwise long URLs in
        // the textarea push the column wider than its grid-track.
        div style="display: flex; gap: 14px; align-items: stretch; margin-bottom: 14px; min-height: 244px;" {
            (qr_svg(link))
            div style="flex: 1; display: flex; flex-direction: column; gap: 6px; min-width: 0;" {
                // Masked-preview is single-line with ellipsis. Pre-
                // 2026-05-19 it had `word-break: break-all` which let
                // long URLs wrap onto 2-3 lines — Flow A (short sub
                // URL = 1 line) and Flow B/C (long wireguard:// /
                // vpn:// = 2-3 lines) ended up with different
                // right-side heights, breaking the column alignment
                // Pavel screenshotted.
                div style="font-family: var(--mono); font-size: 11px; color: var(--soft); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;"
                     title=(mask_secret(link)) {
                    (mask_secret(link))
                }
                textarea readonly="readonly" rows="3"
                         data-select-on-click
                         title="Click to select the full link (or triple-click if JS is disabled), then Ctrl+C / Cmd+C to copy"
                         style="width: 100%; padding: 8px 10px; font-family: var(--mono); font-size: 10px; line-height: 1.45; color: var(--ink); background: var(--paper); border: 1px solid var(--rule); resize: vertical; word-break: break-all; box-sizing: border-box;" {
                    (link)
                }
                div style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; line-height: 1.5;" {
                    (footnote)
                }
            }
        }
    }
}

/// Fixed display side of every share-link QR, in CSS pixels. Picked
/// to fit on a phone screen at scan distance while keeping the
/// user-detail page's Flow column narrow enough that the textarea
/// doesn't wrap awkwardly.
const QR_DISPLAY_PX: u32 = 220;

pub(crate) fn qr_svg(url: &str) -> Markup {
    use qrcode::QrCode;
    use qrcode::render::svg;

    match QrCode::new(url.as_bytes()) {
        Ok(code) => {
            // Render at a sensible native size — the actual pixel
            // dimensions vary by URL length (denser matrix → larger
            // intrinsic SVG with `min_dimensions`). We don't care
            // because the CSS wrapper below forces the on-screen
            // size to a fixed `QR_DISPLAY_PX` regardless of the
            // intrinsic SVG dimensions.
            //
            // Pre-2026-05-19 the wrapper had NO fixed size: Flow A's
            // shortish subscription URL produced a ~220px SVG, but
            // Flow B's full wireguard:// (~600 chars base64) produced
            // a ~280-320px SVG. The three cards (A / B / C) jumped
            // 60-90px in width and the layout «прыгает» (Pavel
            // 2026-05-19).
            let svg_str = code
                .render::<svg::Color<'_>>()
                .min_dimensions(QR_DISPLAY_PX, QR_DISPLAY_PX)
                .quiet_zone(true)
                .dark_color(svg::Color("#1a1611"))
                .light_color(svg::Color("#f5efe6"))
                .build();
            // Wrapper: padded card + inner fixed-size frame. The
            // `> svg` selector with `!important` overrides the
            // hard-coded `width=` / `height=` attributes that
            // `qrcode`'s SVG builder writes — CSS scales the SVG to
            // QR_DISPLAY_PX uniformly. Matrix density still varies
            // visually (denser = finer modules) but the CARD width
            // is constant across all flows.
            //
            // Container width = QR + 2*padding (12px each side).
            let card_px = QR_DISPLAY_PX + 24;
            let inner_style = format!(
                "width: {QR_DISPLAY_PX}px; height: {QR_DISPLAY_PX}px; \
                 display: flex; align-items: stretch;"
            );
            let wrapper_style = format!(
                "display: inline-block; padding: 12px; background: var(--paper); \
                 border: 1px solid var(--rule); width: {card_px}px; height: {card_px}px; \
                 box-sizing: border-box;"
            );
            // Scoped <style> — targets the QR frame's SVG child.
            // `!important` overcomes the SVG's own intrinsic
            // width/height attrs which some browsers honour over CSS.
            //
            // The selector is `.vpnctl-qr-frame svg` (descendant, no
            // child combinator) because Maud HTML-escapes text inside
            // `style { "..." }` — a literal `>` would become `&gt;` and
            // the selector would silently match nothing. (Caught
            // 2026-05-19: previous version used `> svg` and the CSS
            // never applied → QR cards stayed at native SVG sizes →
            // visible-jump bug Pavel screenshotted.) Wrapping the CSS
            // string in `PreEscaped` would also work but the descendant
            // selector is semantically equivalent (frame has exactly
            // one SVG child) and harder to break.
            //
            // Inline style block sits inside the wrapper so it ships
            // only when a QR is rendered (no penalty to other pages).
            html! {
                div style=(wrapper_style) {
                    style {
                        ".vpnctl-qr-frame svg { \
                          width: 100% !important; \
                          height: 100% !important; \
                          display: block; \
                        }"
                    }
                    div class="vpnctl-qr-frame" style=(inner_style) {
                        (maud::PreEscaped(svg_str))
                    }
                }
            }
        }
        Err(e) => html! {
            div style="font-family: var(--mono); color: var(--red); font-size: 12px;" {
                "QR generation failed: " (e.to_string())
            }
        },
    }
}

/// Build all (server, protocol) share-links for a user — same logic as
/// the CLI's `vpnctl sub` and the daemon's `/sub/<token>` handler. Each
/// entry has the protocol id and the rendered URI; failures are logged
/// and skipped, never panic.
/// Sibling of `collect_share_links` — one `vpn://` deep link per
/// granted server that declares the `wireguard` protocol. Used by the
/// user-detail page's Flow C card (AmneziaVPN).
///
/// Errors from `amnezia_share_link` (missing user pubkey, missing
/// server private key, malformed pubkey) are LOGGED-AND-SKIPPED — the
/// page still renders. The empty-state classifier in the Flow C card
/// distinguishes "no grants" from "no WG-capable server" from "render
/// failed" using the same `wg_capable_granted` tally as Flow B.
/// For each server in `peers`, pick `user`'s per-server uuid out of
/// the peers list (migration 0016 made `users_for_server` return User
/// rows with `uuid` already overridden by `grants.client_uuid`). The
/// returned User has its `uuid` swapped to the per-server value; all
/// other fields stay at the user's global values.
///
/// `server_id` is for diagnostics only — we log a WARN when peers is
/// non-empty AND `user.id` is missing from it, because that means
/// some caller built the peers list for the wrong server OR a grant
/// got revoked between fetch + render. Either case would silently
/// render a wrong-uuid share-link (the byte-equivalent of pre-Phase-1
/// behaviour, but masking a real bug) — surfacing it as a warn
/// matches the wg_addressing::peer_octet_in_slash24 contract.
fn user_for_server_render(
    user: &vpnctl_core::User,
    peers: &[vpnctl_core::User],
    server_id: &vpnctl_core::ServerId,
) -> vpnctl_core::User {
    let per_server_uuid = peers
        .iter()
        .find(|p| p.id == user.id)
        .map(|p| p.uuid.as_str());
    match per_server_uuid {
        Some(uuid) => user.with_per_server_uuid(uuid),
        None => {
            if !peers.is_empty() {
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server_id,
                    user = %user.id,
                    "peer list for server does not contain target user; \
                     falling back to global user.uuid (caller bug — peers \
                     built for wrong server, or grant revoked mid-render)"
                );
            }
            user.clone()
        }
    }
}

pub(crate) fn collect_amnezia_links(
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &std::collections::HashMap<
        vpnctl_core::ServerId,
        std::collections::HashMap<String, String>,
    >,
    peers_per_server: &std::collections::HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
) -> Vec<(vpnctl_core::ServerId, String)> {
    let mut out = Vec::new();
    for server in servers {
        if !server.enabled_protocols.iter().any(|p| p.0 == "wireguard") {
            continue;
        }
        let Some(secrets) = secrets_per_server.get(&server.id) else {
            tracing::warn!(target = "vpnctld::admin", server = %server.id, "secrets missing for granted WG server (amnezia link)");
            continue;
        };
        let peers: &[vpnctl_core::User] = peers_per_server
            .get(&server.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let ctx = vpnctl_core::RenderCtx::with_peers(server, secrets, peers);
        let per_server_user = user_for_server_render(user, peers, &server.id);
        match vpnctl_protocols::amnezia_share_link(&ctx, &per_server_user) {
            Ok(link) => out.push((server.id.clone(), link)),
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server.id,
                    user = %user.id,
                    error = %e,
                    "amnezia_share_link failed, skipping Flow C entry"
                );
            }
        }
    }
    out
}

/// Sibling of [`collect_amnezia_links`] — one `awg://` link per
/// WG-enabled granted server for the user-detail Flow E card (the
/// operator's sing-box-lx-based client app). Servers without minted
/// AmneziaWG obfs (i.e. not running the `amneziawg` kernel) or a user
/// without a server-generated private key cause `awg_share_link` to
/// error; those are LOGGED-AND-SKIPPED so the page still renders and the
/// card naturally shows only AmneziaWG-capable servers.
pub(crate) fn collect_awg_links(
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &std::collections::HashMap<
        vpnctl_core::ServerId,
        std::collections::HashMap<String, String>,
    >,
    peers_per_server: &std::collections::HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
) -> Vec<(vpnctl_core::ServerId, String)> {
    let mut out = Vec::new();
    for server in servers {
        // awg:// only makes sense for an AmneziaWG node (obfs minted)
        // serving the wireguard protocol. Gate on BOTH so a vanilla
        // sing-box WG server (no obfs) is skipped cleanly rather than
        // hitting awg_share_link's error path on every page render.
        let is_amnezia = server.kernels.iter().any(|k| k.0 == "amneziawg");
        let serves_wg = server.enabled_protocols.iter().any(|p| p.0 == "wireguard");
        if !is_amnezia || !serves_wg {
            continue;
        }
        let Some(secrets) = secrets_per_server.get(&server.id) else {
            continue;
        };
        let peers: &[vpnctl_core::User] = peers_per_server
            .get(&server.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let ctx = vpnctl_core::RenderCtx::with_peers(server, secrets, peers);
        let per_server_user = user_for_server_render(user, peers, &server.id);
        match vpnctl_protocols::awg_share_link(&ctx, &per_server_user) {
            Ok(link) => out.push((server.id.clone(), link)),
            Err(e) => {
                tracing::debug!(
                    target = "vpnctld::admin",
                    server = %server.id,
                    user = %user.id,
                    error = %e,
                    "awg_share_link skipped (no obfs / no server-gen privkey)"
                );
            }
        }
    }
    out
}

pub(crate) fn collect_share_links(
    state: &AppState,
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &std::collections::HashMap<
        vpnctl_core::ServerId,
        std::collections::HashMap<String, String>,
    >,
    peers_per_server: &std::collections::HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
) -> Vec<(vpnctl_core::ServerId, vpnctl_core::ProtocolId, String)> {
    let mut out = Vec::new();
    for server in servers {
        let Some(secrets) = secrets_per_server.get(&server.id) else {
            tracing::warn!(target = "vpnctld::admin", server = %server.id, "secrets missing for granted server");
            continue;
        };
        let peers: &[vpnctl_core::User] = peers_per_server
            .get(&server.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let ctx = vpnctl_core::RenderCtx::with_peers(server, secrets, peers);
        let per_server_user = user_for_server_render(user, peers, &server.id);
        for pid in &server.enabled_protocols {
            let Some(proto) = state.registry.protocol(pid) else {
                tracing::warn!(target = "vpnctld::admin", protocol = %pid, "protocol not registered");
                continue;
            };
            match proto.share_link(&ctx, &per_server_user) {
                Ok(link) => out.push((server.id.clone(), pid.clone(), link)),
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::admin",
                        server = %server.id,
                        protocol = %pid,
                        error = %e,
                        "share_link failed, skipping"
                    );
                }
            }
        }
    }
    out
}

// ════════════════════════════════════════════════════════════════════
//  PR-User — informativeness cards for the user-detail page.
//
//  All seven cards reuse existing helpers (status_tile, sparkline_svg,
//  window_picker_section, humanize_bytes, fmt_traffic_progress,
//  format_msk_iso, ua_verdict) — no parallel styling. Bilingual via
//  tr() / t(). The only card that touches process state outside one
//  SQL query is user#1 (the online-now badge), and that read is
//  in-memory only — it walks the already-populated `snapshot_cache`
//  across the granted servers, never an extra DB round-trip or SSH.
// ════════════════════════════════════════════════════════════════════

/// user#1 — online-now presence badge. Walks `state.snapshot_cache`
/// across every server in `server_ids` (in production the granted set
/// joined with the full inventory; tests pass whatever they seeded),
/// counting the live clash-api connections whose `(source_ip,
/// source_port)` attribution resolves to `uid`. When the per-connection
/// attribution map misses (NM-11: the sing-box log scrape window may
/// have scrolled past a long-lived connection's accept line), we fall
/// back to `users_for_source_ips` — the same sourceIP-to-user_id join
/// the «Live connections» drill-down uses — over the unattributed
/// source IPs only, so a covered user still lights up green.
///
/// 🟢 online → "N conns on {server(s)}". Offline → "last seen {Xh
/// ago}" from `sub_access_aggregates_for_user.last_seen` (passed in as
/// `last_seen` so we don't re-query). Cheap: in-memory map reads +, at
/// most, one bounded `users_for_source_ips` query for the IPs the
/// in-memory map couldn't resolve.
pub(crate) async fn user_online_badge(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    server_ids: &[vpnctl_core::ServerId],
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // Per-server live connection count attributed to this user, plus
    // the set of (server, source_ip) pairs the in-memory attribution
    // map could NOT resolve — candidates for the sourceIP fallback.
    let mut conns_per_server: std::collections::BTreeMap<String, u32> =
        std::collections::BTreeMap::new();
    // Unresolved source IPs → the servers they appeared on (so the
    // fallback can credit the right server when a join succeeds).
    let mut unresolved: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for sid in server_ids {
        // `get_live`: the 🟢 online badge must NOT light up from a
        // snapshot the poller stopped refreshing (~2 intervals stale).
        let Some(snap) = state.snapshot_cache.get_live(sid) else {
            continue;
        };
        for c in &snap.snapshot.connections {
            match c.metadata.user.as_deref() {
                Some(u) if u == uid.0.as_str() => {
                    *conns_per_server.entry(sid.0.clone()).or_insert(0) += 1;
                }
                Some(_) => {
                    // Attributed to a DIFFERENT user — never this one.
                }
                None => {
                    // No user on the wire (e.g. an unpatched node) —
                    // defer to the sourceIP join below.
                    if !c.metadata.source_ip.is_empty() {
                        unresolved
                            .entry(c.metadata.source_ip.clone())
                            .or_default()
                            .push(sid.0.clone());
                    }
                }
            }
        }
    }

    // Fallback: resolve the unattributed source IPs via the same
    // sub_access_log sourceIP → user_id join the drill-down uses. One
    // bounded query over the distinct unresolved IPs (skipped entirely
    // when the in-memory map already covered everything).
    if !unresolved.is_empty() {
        let ips: Vec<String> = unresolved.keys().cloned().collect();
        match state.inv.users_for_source_ips(&ips, 7).await {
            Ok(map) => {
                for (ip, candidates) in &map {
                    // The join returns (user, hits) ordered hits-DESC;
                    // the top candidate is the most-likely owner. Credit
                    // the user only when THEY are that top candidate.
                    let owner_is_user = candidates
                        .first()
                        .map(|(u, _)| u.0.as_str() == uid.0.as_str())
                        .unwrap_or(false);
                    if owner_is_user {
                        if let Some(servers) = unresolved.get(ip) {
                            for s in servers {
                                *conns_per_server.entry(s.clone()).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "users_for_source_ips (online badge fallback) failed");
            }
        }
    }

    let total_conns: u32 = conns_per_server.values().copied().sum();
    let online = total_conns > 0;

    html! {
        @if online {
            @let server_count = conns_per_server.len();
            @let server_list = conns_per_server
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            span.ed-stat.ed-stat--active
                title=(tr(
                    lang,
                    "Presence — live from each node's clash-api snapshot (≤5 min old). NM-11 fallback attributes unresolved connections by source IP; unseen IPs remain uncounted.",
                    "Присутствие — live-снимок clash-api каждой ноды (не старше 5 мин). NM-11 fallback атрибутирует соединения по source IP; незнакомые IP не учитываются.",
                )) {
                span.ed-stat__dot {}
                b { (tr(lang, "online", "онлайн")) }
                " · " (total_conns) " "
                @if total_conns == 1 { (tr(lang, "conn", "соединение")) }
                @else { (tr(lang, "conns", "соединений")) }
                " "
                @if server_count == 1 { (tr(lang, "on ", "на ")) }
                @else { (tr(lang, "across ", "на ")) }
                span.ed-mono { (server_list) }
            }
        } @else {
            span.ed-stat.ed-stat--unknown
                title=(tr(lang, "Presence — no live connection in the latest clash-api snapshots.", "Присутствие — в последних снимках clash-api нет активных соединений.")) {
                span.ed-stat__dot {}
                (tr(lang, "offline", "офлайн"))
                " · "
                @match last_seen {
                    Some(ts) => {
                        @let ago = humanize_since(ts, lang);
                        (tr(lang, "last seen ", "последний раз ")) (ago)
                    }
                    None => (tr(lang, "never connected", "ни разу не подключался")),
                }
            }
        }
    }
}

/// Compact «X ago» for the presence badge — whole-unit granularity
/// (minutes / hours / days) is enough for «when was this user last
/// active». Clamps a future timestamp (clock skew) to «just now».
fn humanize_since(ts: chrono::DateTime<chrono::Utc>, lang: crate::i18n::Locale) -> String {
    use crate::i18n::tr;
    let secs = (chrono::Utc::now() - ts).num_seconds().max(0);
    if secs < 60 {
        tr(lang, "just now", "только что").to_string()
    } else if secs < 3600 {
        format!("{}{}", secs / 60, tr(lang, "m ago", "м назад"))
    } else if secs < 86_400 {
        format!("{}{}", secs / 3600, tr(lang, "h ago", "ч назад"))
    } else {
        format!("{}{}", secs / 86_400, tr(lang, "d ago", "д назад"))
    }
}

pub(crate) fn user_is_likely_shared(
    aggregates: &vpnctl_inventory::SubAccessAggregates,
    ua_clusters: &[vpnctl_inventory::UaCluster],
) -> bool {
    aggregates.distinct_asns >= 3
        || ua_clusters.iter().any(|c| {
            matches!(
                ua_verdict(c.distinct_ips, c.distinct_slash16),
                UaVerdict::LikelyShared
            )
        })
}

fn format_origin_ts(raw: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(raw) {
        Ok(dt) => format_msk_iso(dt.with_timezone(&chrono::Utc)),
        Err(_) => raw.to_string(),
    }
}

/// Classify a reserved / non-routable IP into a short human label so a
/// NULL GeoIP country reads as «private/LAN» or «loopback» instead of
/// the uninformative «(unknown)». For a self-hosted box, most of the
/// «(unknown)» origin rows are the homelab's OWN LAN / loopback /
/// CGNAT addresses hitting the /sub endpoint — labelling them makes
/// the operator instantly see «that's my infra, not a shared URL».
///
/// Returns `None` for an ordinary routable public IP (where
/// «(unknown)» genuinely means «GeoIP has no record») and for an
/// unparseable string. Ranges: RFC1918 private, RFC6598 CGNAT
/// (100.64/10), loopback, link-local (169.254/16, fe80::/10), ULA
/// (fc00::/7), unspecified.
pub(super) fn classify_reserved_ip(ip: &str) -> Option<&'static str> {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_private() {
                Some("private/LAN")
            } else if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
                // 100.64.0.0/10 — carrier-grade NAT (RFC6598).
                Some("CGNAT")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if v4.is_unspecified() {
                Some("unspecified")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Some("loopback")
            } else if v6.is_unspecified() {
                Some("unspecified")
            } else {
                let seg = v6.segments();
                if (seg[0] & 0xfe00) == 0xfc00 {
                    // fc00::/7 — unique local address (RFC4193).
                    Some("private/ULA")
                } else if (seg[0] & 0xffc0) == 0xfe80 {
                    // fe80::/10 — link-local.
                    Some("link-local")
                } else {
                    None
                }
            }
        }
    }
}

/// Fallback cell for a source IP whose GeoIP country/ASN came back
/// NULL: render the reserved-range class when the IP is non-routable,
/// else the generic `unknown` marker. Shared by the «Subscription
/// origins · By IP» table and the «Source IPs» traffic section so both
/// treat «(unknown)» identically.
fn ip_geo_fallback(ip: &str, unknown: &str) -> Markup {
    match classify_reserved_ip(ip) {
        Some(cls) => html! { em style="color: var(--mute);" { (cls) } },
        None => html! { em style="color: var(--mute);" { (unknown) } },
    }
}

/// Shared th/td inline styles for the origins tables (survived the R2
/// removal of the legacy verdict section that used to sit above them).
const ORIGINS_TH: &str = "padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;";
const ORIGINS_TD: &str = "padding: 5px 8px;";

/// abuse-origins — "Subscription origins" section (anchor `#origins`).
/// The actionable WHO-is-sharing view: three compact tables (by
/// country / by ISP / by IP) + a rough device-count line, all over the
/// 30-day non-egress `/sub` access window. Linked from the dashboard
/// likely-shared card. Renders an empty-state when the user has no
/// external (non-egress) fetches at all.
///
/// Pure render — every input is pre-fetched in `user_detail` (one
/// grouped query each, no N+1). Bilingual via `tr`; timestamps via
/// `format_origin_ts` → `format_msk_iso`.
pub(crate) fn user_subscription_origins_section(
    by_country: &[vpnctl_inventory::SubOriginCountry],
    by_asn: &[vpnctl_inventory::SubOriginAsn],
    by_ip: &[vpnctl_inventory::SubOriginIp],
    device_fp: &vpnctl_inventory::SubDeviceFp,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let unknown = tr(lang, "(unknown)", "(неизвестно)");
    // "No external fetches" is the union signal — if there are no
    // non-egress rows, all three breakdowns are empty.
    let empty = by_country.is_empty() && by_asn.is_empty() && by_ip.is_empty();

    html! {
        div.ed-rule {}
        // The anchor lives on the eyebrow so `#origins` lands the
        // viewport at the section heading.
        div.ed-art-eyebrow id="origins" {
            (tr(lang, "Subscription origins", "Источники подписки"))
        }
        @if empty {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
                (tr(
                    lang,
                    "No external subscription fetches recorded — nothing to break down by country, ISP or IP yet.",
                    "Внешних обращений к подписке не записано — пока нечего разбивать по странам, ISP или IP.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "Where this one subscription URL was fetched from over the last 30 days — real client IPs only (VPN-egress excluded). Many countries / ISPs / IPs for a single subscription is the clearest who-is-sharing signal.",
                    "Откуда тянули этот один URL подписки за последние 30 дней — только реальные клиентские IP (VPN-egress исключён). Много стран / ISP / IP на одну подписку — самый явный сигнал, что ссылку расшарили.",
                ))
            }

            // Device-count line — a sharing signal on its own.
            // TT-5: the old estimate was max(device_class, UA, JA4).
            // JA4 is ALWAYS 0 (no JA4-forwarding proxy is wired), so
            // «· 0 TLS-fingerprints» was permanent dead noise that read
            // as a broken feature — dropped. UA over-counts (every app
            // version is a distinct string); device_class collapses that
            // churn (4 Streisand builds → 1) but under-counts because
            // the parser leaves the custom ninitux client NULL. So we
            // lead with device_class when we have it (labelled honestly
            // as «client families»), fall back to the raw UA count
            // otherwise, and always show the raw UA count as the upper
            // bound — never a single false-precision «≈N devices».
            @let has_families = device_fp.distinct_device_classes > 0;
            @let lead_n = if has_families { device_fp.distinct_device_classes } else { device_fp.distinct_uas };
            p style="font-family: var(--mono); font-size: 12px; color: var(--ink); margin: 0 0 16px;" {
                "≈ " b { (lead_n) } " "
                @if has_families { (tr(lang, "client families", "клиентских семейств")) }
                @else { (tr(lang, "distinct user-agents", "уникальных user-agent")) }
                " "
                span.ed-tip title=(tr(
                    lang,
                    "«Client families» collapse app-version churn — four Streisand builds count as one client. The raw user-agent count is the upper bound (each version is a distinct string). Clients the UA parser doesn't recognise (the custom ninitux app) leave device_class NULL, so families under-count. TLS fingerprints (JA4) aren't captured — no fingerprint-forwarding proxy is wired.",
                    "«Клиентские семейства» схлопывают версии приложения — четыре сборки Streisand считаются одним клиентом. Сырое число user-agent — верхняя граница (каждая версия — отдельная строка). Клиенты, которых парсер UA не узнаёт (кастомный ninitux), оставляют device_class NULL, поэтому семейства недосчитывают. TLS-отпечатки (JA4) не снимаются — прокси с их форвардингом не подключён.",
                )) { "ⓘ" }
                @if has_families {
                    " " span style="color: var(--mute);" {
                        "(" (device_fp.distinct_uas) " " (tr(lang, "distinct UA", "уник. UA")) ")"
                    }
                }
            }

            // ── By country ───────────────────────────────────────────
            div.ed-art-eyebrow style="margin-top: 4px;" {
                (tr(lang, "By country", "По странам"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; margin-bottom: 18px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country", "страна")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "fetches", "обращений")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "distinct IPs", "уник. IP")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "distinct ASNs", "уник. ASN")) }
                    }
                }
                tbody {
                    @for row in by_country {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink);")) {
                                @match row.country.as_deref() {
                                    Some(c) if !c.is_empty() => (c),
                                    _ => em style="color: var(--mute);" { (unknown) },
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink);")) { (row.fetches) }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--soft);")) { (row.ips) }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--soft);")) { (row.asns) }
                        }
                    }
                }
            }

            // ── By ISP ───────────────────────────────────────────────
            div.ed-art-eyebrow {
                (tr(lang, "By ISP", "По провайдерам"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; margin-bottom: 18px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "ASN / ISP", "ASN / ISP")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country", "страна")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "fetches", "обращений")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "distinct IPs", "уник. IP")) }
                    }
                }
                tbody {
                    @for row in by_asn {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink); overflow-wrap: anywhere;")) {
                                @match row.asn.as_deref() {
                                    Some(a) if !a.is_empty() => (a),
                                    _ => em style="color: var(--mute);" { (unknown) },
                                }
                            }
                            td style=(format!("{ORIGINS_TD} color: var(--soft);")) {
                                @match row.country.as_deref() {
                                    Some(c) if !c.is_empty() => (c),
                                    _ => em style="color: var(--mute);" { (unknown) },
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink);")) { (row.fetches) }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--soft);")) { (row.ips) }
                        }
                    }
                }
            }

            // ── By IP ────────────────────────────────────────────────
            div.ed-art-eyebrow {
                (tr(lang, "By IP", "По IP"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "ip", "ip")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country", "страна")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "ASN / ISP", "ASN / ISP")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "fetches", "обращений")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "first seen", "впервые")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "last seen", "последний раз")) }
                    }
                }
                tbody {
                    @for row in by_ip {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink); overflow-wrap: anywhere;")) { (row.ip) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft);")) {
                                @match row.country.as_deref() {
                                    Some(c) if !c.is_empty() => (c),
                                    _ => (ip_geo_fallback(&row.ip, unknown)),
                                }
                            }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); overflow-wrap: anywhere;")) {
                                @match row.asn.as_deref() {
                                    Some(a) if !a.is_empty() => (a),
                                    _ => (ip_geo_fallback(&row.ip, unknown)),
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink);")) { (row.fetches) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); white-space: nowrap;")) { (format_origin_ts(&row.first_seen)) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); white-space: nowrap;")) { (format_origin_ts(&row.last_seen)) }
                        }
                    }
                }
            }
        }
    }
}

/// «Source IPs» — the source-IP counterpart to «Top destinations».
/// Per-(user, source_ip) activity over the last 30 days from the
/// persisted `vpn_user_source_ips` hit-counter (one hit per 5-min
/// clash tick the user had a live connection from that IP), GeoIP-
/// enriched (`geo`: ip → (country, asn)) and reserved-range-classified
/// so a NULL GeoIP country reads as «private/LAN» not «(unknown)».
///
/// This is the «разбей трафик по IP внутри пользователя» view —
/// grounded in ACTUAL VPN connections, not /sub URL fetches (which
/// the «Subscription origins» tables cover). Activity-weighted (hits
/// = ticks-alive) rather than byte-weighted, by deliberate design:
/// per-IP byte deltas would need diff-engine state per (user, ip,
/// conn) tuple (see migration 0034). Many distinct PUBLIC IPs or
/// countries here is the strongest grounded sharing signal.
///
/// Pure render — `rows` and `geo` are pre-fetched in `user_detail`.
pub(crate) fn user_source_ips_section(
    rows: &[vpnctl_inventory::VpnUserSourceIpRow],
    geo: &std::collections::HashMap<String, (Option<String>, Option<String>)>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let unknown = tr(lang, "(unknown)", "(неизвестно)");
    // Distinct routable (public) IPs — the sharing-signal headline.
    // Reserved/LAN/CGNAT addresses don't count toward «sharing».
    let distinct_public = rows
        .iter()
        .filter(|r| classify_reserved_ip(&r.source_ip).is_none())
        .count();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow id="source-ips" {
            (tr(lang, "Source IPs · last 30 days", "Source IP · 30 дней"))
        }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                (tr(
                    lang,
                    "No source-IP history yet. The poller records one hit per (client IP, 5-min tick) a connection was attributed to this user — wait for the next clash-api scrape, or the user simply hasn't connected.",
                    "Истории по source IP ещё нет. Поллер пишет один hit на (клиентский IP, 5-мин тик), в котором соединение отнесено к этому юзеру — подожди следующий скрейп clash-api, либо юзер просто не подключался.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "Which client IPs this user actually connected FROM (real VPN connections, not /sub fetches), over the last 30 days. Activity-weighted: hits = 5-min ticks the IP was live, not bytes. Private / LAN / CGNAT addresses are labelled rather than left as «(unknown)». Many distinct public IPs or countries = the strongest grounded sharing signal.",
                    "С каких клиентских IP юзер реально подключался (реальные VPN-соединения, не обращения к /sub) за 30 дней. Взвешено активностью: hits = 5-мин тики, в которых IP был живой, не байты. Приватные / LAN / CGNAT адреса подписаны, а не оставлены как «(неизвестно)». Много разных публичных IP или стран = самый достоверный сигнал расшаривания.",
                ))
            }
            p style="font-family: var(--mono); font-size: 12px; color: var(--ink); margin: 0 0 14px;" {
                "≈ " b { (distinct_public) } " "
                (tr(lang, "distinct public IPs · 30d", "уник. публичных IP · 30д"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "source ip", "source ip")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country / ISP", "страна / ISP")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}"))
                           title=(tr(lang, "Number of 5-min clash ticks where this user had a live connection from this IP. Not bytes, not connection count — activity time.", "Число 5-мин тиков clash, в которых у юзера было живое соединение с этого IP. Не байты и не число соединений — время активности.")) {
                            (tr(lang, "hits · 30d", "hits · 30д"))
                        }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "last seen", "последний раз")) }
                    }
                }
                tbody {
                    @for r in rows {
                        @let (country, asn) = geo.get(&r.source_ip).cloned().unwrap_or((None, None));
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink); overflow-wrap: anywhere;")) { (r.source_ip) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); overflow-wrap: anywhere;")) {
                                @match country.as_deref() {
                                    Some(c) if !c.is_empty() => {
                                        (c)
                                        @if let Some(a) = asn.as_deref() {
                                            @if !a.is_empty() {
                                                span style="color: var(--mute);" { " · " (a) }
                                            }
                                        }
                                    }
                                    _ => (ip_geo_fallback(&r.source_ip, unknown)),
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink); font-weight: 500;")) { (r.hit_count) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); white-space: nowrap;")) { (format_msk(r.last_seen)) }
                        }
                    }
                }
            }
        }
    }
}

/// user#5 — lifecycle facts: created · last seen · last fetch · age.
/// Phase Track-4 — UA fingerprint heuristic. Renders one row per
/// distinct User-Agent that has hit this user's `/sub` URL in the
/// last 24h, with a "likely roaming" / "likely shared URL" label.
///
/// Classifier (initial cut, intentionally conservative):
///   * `distinct_slash16 >= 3` → `likely shared URL` (orange)
///   * `distinct_ips >= 3 && distinct_slash16 <= 1` → `likely roaming`
///     (one device hopping subnets within one ISP)
///   * else → unlabeled (single-IP normal client)
///
/// On inventory error returns a small "(unavailable)" nudge instead
/// of failing the whole page.
///
/// user#7 (PR-User) — additive geo + last-seen footer. `UaCluster`
/// carries no per-row geo (the heuristic only needs IP/16 spread), so
/// the country / ASN / last-seen columns are summarised once below the
/// table from the user's 30-day `sub_access_aggregates_for_user`
/// (passed in to avoid a re-query). The per-UA table is unchanged.
pub(crate) async fn ua_clusters_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    aggregates: &vpnctl_inventory::SubAccessAggregates,
    lang: crate::i18n::Locale,
) -> Markup {
    let clusters = match state.inv.ua_clusters_for_user(uid, 24).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "ua_clusters_for_user failed");
            return html! {
                div.ed-rule {}
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "UA fingerprint", "Отпечаток User-Agent")) }
                p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                    "(temporarily unavailable — please retry)"
                }
            };
        }
    };
    if clusters.is_empty() {
        return html! {};
    }

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (crate::i18n::tr(lang, "UA fingerprint · last 24h", "Отпечаток User-Agent · за 24ч"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (crate::i18n::tr(
                lang,
                "Heuristic. One device usually roams within one ISP /16, while a shared sub URL spreads across many ISPs. Labels: orange = likely shared, green = likely roaming.",
                "Эвристика. Одно устройство обычно ходит в пределах одного ISP /16, а расшаренный sub URL расползается по разным ISP. Метки: оранжевый = вероятно расшарен, зелёный = вероятно роуминг.",
            ))
        }
        table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
            thead {
                tr style="border-bottom: 1px solid var(--ink);" {
                    th title="Distinct User-Agent strings the subscription URL was pulled with in the last 24h. Each cluster is one row."
                       style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "user-agent" }
                    th title="Total subscription pulls from this UA (one row per /sub/<token> or /api/v1/app/config/<device> GET that produced 200)."
                       style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "hits" }
                    th title="Distinct source IPs that pulled with this UA. Normal mobile client = 1-3 IPs (home wifi + LTE + travel). Many IPs = either roaming heavily or shared URL."
                       style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "ips" }
                    th title="Distinct /16 IPv4 prefixes (≈ISP-scale buckets). One user roaming between LTE + wifi tends to stay in 1-2 /16s. >=3 /16s strongly suggests the subscription URL was shared past one human."
                       style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "/16 nets" }
                    th title="Heuristic classification from (hits, ips, /16 nets): single = one human, roaming = one human on the move, shared = the URL escaped past one human."
                       style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "verdict" }
                }
            }
            tbody {
                @for c in &clusters {
                    @let verdict = ua_verdict(c.distinct_ips, c.distinct_slash16);
                    tr style="border-bottom: 1px dotted var(--rule);" {
                        td style="padding: 5px 8px; color: var(--soft); overflow-wrap: anywhere;" {
                            @match &c.ua {
                                Some(s) => (s),
                                None => em style="color: var(--mute);" { "(no UA)" },
                            }
                        }
                        td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (c.hits) }
                        td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (c.distinct_ips) }
                        td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (c.distinct_slash16) }
                        td style=(verdict.style()) { (verdict.label()) }
                    }
                }
            }
        }
        // user#7 — devices/UA geo + last-seen summary. Additive footer
        // under the per-UA table: country / ASN spread + the user's most
        // recent /sub fetch, all from the 30-day aggregates (no extra
        // query). Gives the operator the «where from / how long ago»
        // context the per-UA /16 spread can't.
        div style="display: flex; flex-wrap: wrap; gap: 28px; padding: 12px 0 0; font-family: var(--serif); font-size: 12px; color: var(--mute);" {
            span title=(crate::i18n::tr(lang, "Distinct ISO country codes the subscription was fetched from over the last 30 days (GeoIP).", "Уникальных ISO-кодов стран, из которых тянули подписку за 30 дней (GeoIP).")) {
                span.ed-mono style="color: var(--ink);" { (aggregates.distinct_countries) }
                " " (crate::i18n::tr(lang, "countries · 30d", "стран · 30д"))
            }
            span title=(crate::i18n::tr(lang, "Distinct ASN / ISP labels over the last 30 days (GeoIP-ASN).", "Уникальных ASN / ISP за 30 дней (GeoIP-ASN).")) {
                span.ed-mono style="color: var(--ink);" { (aggregates.distinct_asns) }
                " " (crate::i18n::tr(lang, "ASNs · 30d", "ASN · 30д"))
            }
            span title=(crate::i18n::tr(lang, "Most recent /sub fetch (any IP).", "Последнее обращение к /sub (любой IP).")) {
                (crate::i18n::tr(lang, "last seen ", "последний раз "))
                @match aggregates.last_seen {
                    Some(ts) => span.ed-mono style="color: var(--ink);" { (format_msk_iso(ts)) },
                    None => em { (crate::i18n::tr(lang, "never", "никогда")) },
                }
            }
        }
    }
}

/// Verdict shape — pairs the operator-visible label with its CSS
/// styling so the table cell stays consistent across rows.
enum UaVerdict {
    LikelyShared,
    LikelyRoaming,
    Unlabeled,
}

impl UaVerdict {
    fn label(&self) -> &'static str {
        match self {
            Self::LikelyShared => "likely shared URL",
            Self::LikelyRoaming => "likely roaming",
            Self::Unlabeled => "—",
        }
    }
    fn style(&self) -> &'static str {
        match self {
            Self::LikelyShared => "padding: 5px 8px; color: var(--acc); font-style: italic;",
            Self::LikelyRoaming => "padding: 5px 8px; color: var(--soft); font-style: italic;",
            Self::Unlabeled => "padding: 5px 8px; color: var(--mute);",
        }
    }
}

fn ua_verdict(distinct_ips: u64, distinct_slash16: u64) -> UaVerdict {
    if distinct_slash16 >= 3 {
        UaVerdict::LikelyShared
    } else if distinct_ips >= 3 && distinct_slash16 <= 1 {
        UaVerdict::LikelyRoaming
    } else {
        UaVerdict::Unlabeled
    }
}

/// Track-3 chunk 3 — live VPN stats section. Reads
/// `recent_vpn_stats_for_user(uid, 24h)` and renders aggregate KPIs
/// (bytes up/down, peak active connections) plus a per-server
/// breakdown.
///
/// Empty-state copy explicitly tells the operator that polling isn't
/// wired yet — chunk 4 lights up the background task. Without this
/// nudge the "no data" message would look like a bug.
/// Hourly upload+download sparkline over the last 24h. Renders as
/// inline SVG — paired bars (download = solid accent, upload = thin
/// ink) per hour-bucket, latest hour on the right. No JS, no
/// external refs, fits in ~140 chars of computed paint.
///
/// Empty hours (no traffic seen) render as blank cells so the
/// operator sees a true "quiet stretch" instead of a misleading
/// linear interpolation.
///
/// Returns empty Markup if the input is empty — caller already
/// has a "no live stats yet" empty-state above.
/// Window spec for `vpn_sparkline` — fixed grid of cells, each
/// `bucket_hours` long, ending at «now». 24h × 1h = 24 cells. 7d
/// × 24h = 7 cells. 30d × 24h = 30 cells. all-time uses a stretch
/// bucket so the operator always sees ≤30 bars even when the
/// daemon has been running for months.
#[derive(Clone, Copy, Debug)]
pub(super) struct VpnSparklineWindow {
    /// Tab id used in the URL (`?window=24h`).
    pub(super) slug: &'static str,
    /// Human label rendered in the tab + caption.
    pub(super) label_en: &'static str,
    pub(super) label_ru: &'static str,
    /// Cells in the grid.
    pub(super) cells: u32,
    /// Hours covered by each cell.
    pub(super) bucket_hours: u32,
    /// Optional caption-suffix override (else «per <bucket>»).
    pub(super) per_bucket_en: &'static str,
    pub(super) per_bucket_ru: &'static str,
}

pub(super) const VPN_SPARKLINE_WINDOWS: &[VpnSparklineWindow] = &[
    VpnSparklineWindow {
        slug: "24h",
        label_en: "24h",
        label_ru: "24ч",
        cells: 24,
        bucket_hours: 1,
        per_bucket_en: "per hour",
        per_bucket_ru: "в час",
    },
    VpnSparklineWindow {
        slug: "7d",
        label_en: "7 days",
        label_ru: "7 дней",
        cells: 7,
        bucket_hours: 24,
        per_bucket_en: "per day",
        per_bucket_ru: "в сутки",
    },
    VpnSparklineWindow {
        slug: "30d",
        label_en: "30 days",
        label_ru: "30 дней",
        cells: 30,
        bucket_hours: 24,
        per_bucket_en: "per day",
        per_bucket_ru: "в сутки",
    },
    VpnSparklineWindow {
        slug: "all",
        label_en: "all",
        label_ru: "всё",
        cells: 30,
        bucket_hours: 24 * 30,
        per_bucket_en: "per month",
        per_bucket_ru: "в месяц",
    },
];

pub(super) fn pick_vpn_sparkline_window(slug: Option<&str>) -> VpnSparklineWindow {
    let s = slug.unwrap_or("24h");
    VPN_SPARKLINE_WINDOWS
        .iter()
        .find(|w| w.slug == s)
        .copied()
        .unwrap_or(VPN_SPARKLINE_WINDOWS[0])
}

/// Multi-window VPN traffic sparkline (24h / 7d / 30d / all).
///
/// 2026-05-23 redesign — Pavel's feedback «график активности
/// непонятный»: the previous 24h-only chart packed 24 bars into
/// 384 px so each cell was 14 px wide, and a single hour of
/// activity surrounded by 23 empty hours looked like a noise
/// spike rather than a usable signal. Operator also wanted
/// «больше чем за 24 часа а еще и за все время». The redesign:
/// (a) supports four window slugs picked via `?window=...` query
/// param, (b) widens cells for smaller cell counts (7d → 50 px
/// bars instead of 14 px), (c) draws a 50%-of-max horizontal
/// rule so the operator can gauge «is this typical or a spike»,
/// (d) inline SVG `<title>` tooltips on each bar so hover shows
/// the absolute byte count for that bucket.
/// Round a byte count up to a «nice» tick value for Y-axis labels.
/// Powers-of-1024 family: 1, 2, 5, 10, 20, 50 × {KiB, MiB, GiB, TiB}.
/// Picks the smallest nice value ≥ `n`. Returns 1 KiB minimum so we
/// never emit a `0`-labelled axis for trace-but-nonzero traffic.
fn nice_byte_ceiling(n: u64) -> u64 {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;
    let units = [
        KIB,
        2 * KIB,
        5 * KIB,
        10 * KIB,
        20 * KIB,
        50 * KIB,
        100 * KIB,
        200 * KIB,
        500 * KIB,
        MIB,
        2 * MIB,
        5 * MIB,
        10 * MIB,
        20 * MIB,
        50 * MIB,
        100 * MIB,
        200 * MIB,
        500 * MIB,
        GIB,
        2 * GIB,
        5 * GIB,
        10 * GIB,
        20 * GIB,
        50 * GIB,
        100 * GIB,
        200 * GIB,
        500 * GIB,
        TIB,
        2 * TIB,
        5 * TIB,
        10 * TIB,
    ];
    for &u in &units {
        if u >= n.max(1) {
            return u;
        }
    }
    n
}

/// Format an X-axis tick label for the given bucket-start instant.
/// 1h buckets → `HH:MM` (e.g. «14:00»). 24h buckets → `MMM DD`
/// (e.g. «May 17»). 30d buckets → `MMM YYYY` (e.g. «May 2026»).
///
/// 2026-05-23 — converts to MSK (+03:00) before formatting. The
/// hourly bucket label especially matters: a peak at «14:00 UTC»
/// shown as «14:00» reads as 14:00 MSK, which is 11:00 UTC actually
/// — operator's intuition («it's 5pm Moscow time») gets the wrong
/// bar. Daily and monthly labels also shift, but the visual delta
/// is tiny (one day at most).
fn x_axis_tick_label(t: chrono::DateTime<chrono::Utc>, bucket_hours: u32) -> String {
    let fmt = if bucket_hours == 1 {
        "%H:%M"
    } else if bucket_hours == 24 {
        "%b %d"
    } else {
        "%b %Y"
    };
    t.with_timezone(&display_tz()).format(fmt).to_string()
}

/// user#6 — per-cell (upload + download) byte totals for the compact
/// `sparkline_svg` trend folded into `live_vpn_stats_section`. Buckets
/// `rows` into `window.cells` cells of `window.bucket_hours` each,
/// newest cell on the right — identical bucketing to `vpn_traffic_chart`
/// so the sparkline and the full chart can't disagree. Returns one f64
/// per cell (bytes); an all-zero series means «no traffic in window»
/// and the caller skips rendering the sparkline.
fn vpn_traffic_trend_series(
    rows: &[vpnctl_inventory::VpnStatsRow],
    window: VpnSparklineWindow,
) -> Vec<f64> {
    use chrono::{DurationRound, TimeDelta, Utc};
    let cells = window.cells as usize;
    let bucket_seconds = window.bucket_hours as i64 * 3600;
    let now = match Utc::now().duration_trunc(TimeDelta::seconds(bucket_seconds)) {
        Ok(t) => t,
        Err(_) => return vec![0.0; cells],
    };
    let mut per_cell: Vec<u64> = vec![0; cells];
    for r in rows {
        let row_t = match r.ts.duration_trunc(TimeDelta::seconds(bucket_seconds)) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let buckets_ago = now.signed_duration_since(row_t).num_seconds() / bucket_seconds;
        if !(0..cells as i64).contains(&buckets_ago) {
            continue;
        }
        let idx = (cells as i64 - 1 - buckets_ago) as usize;
        per_cell[idx] =
            per_cell[idx].saturating_add(r.upload_bytes.saturating_add(r.download_bytes));
    }
    per_cell.into_iter().map(|v| v as f64).collect()
}

/// PowerBI / Tableau-style stacked bar chart for VPN traffic.
///
/// Replaces the previous bare-bones sparkline. The redesign is
/// 2026-05-23 follow-up to Pavel's feedback: «график без явных
/// осей x и у… посмотри как оформляют аналитические данные в
/// powerbi или в tableau». Now includes:
///
/// * **Y-axis** on the left with 5 tick labels (`0`, `25%`, `50%`,
///   `75%`, `100%` of the «nice»-rounded max) — each labeled with
///   the byte count, not a raw percentage.
/// * **Horizontal grid lines** at every Y tick, drawn in
///   `var(--rule)` so they recede visually behind the bars.
/// * **X-axis** below with date / time labels at meaningful
///   intervals (every 6h for 24h, every day for 7d, every 5 days
///   for 30d, every 6 months for «all»). Dense windows skip ticks
///   to avoid label collision.
/// * **Stacked bars** — upload at bottom, download on top, both
///   in the editorial accent palette.
/// * **Legend** (`■ download · ■ upload`) below the chart so the
///   colour mapping is unambiguous.
/// * **Per-bar tooltip** via SVG `<title>` showing bucket start +
///   absolute byte values.
/// * **Summary line** below legend: `max X per Y · total Z`.
///
/// Chart geometry: 720×240 viewBox with 56 px left padding for
/// Y labels and 32 px bottom padding for X labels. Scales
/// responsively via `style="width: 100%; max-width: 720px;
/// height: auto"`.
pub(super) fn vpn_traffic_chart(
    rows: &[vpnctl_inventory::VpnStatsRow],
    window: VpnSparklineWindow,
    lang: crate::i18n::Locale,
) -> Markup {
    use chrono::{DurationRound, TimeDelta, Utc};
    let per_bucket = match lang {
        crate::i18n::Locale::En => window.per_bucket_en,
        crate::i18n::Locale::Ru => window.per_bucket_ru,
    };
    let cells = window.cells as usize;
    let bucket_seconds = window.bucket_hours as i64 * 3600;
    let now = match Utc::now().duration_trunc(TimeDelta::seconds(bucket_seconds)) {
        Ok(t) => t,
        Err(_) => return html! {},
    };
    let mut up_per_cell: Vec<u64> = vec![0; cells];
    let mut dn_per_cell: Vec<u64> = vec![0; cells];
    for r in rows {
        let row_t = match r.ts.duration_trunc(TimeDelta::seconds(bucket_seconds)) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let diff = now.signed_duration_since(row_t);
        let buckets_ago = diff.num_seconds() / bucket_seconds;
        if !(0..cells as i64).contains(&buckets_ago) {
            continue;
        }
        let idx = (cells as i64 - 1 - buckets_ago) as usize;
        up_per_cell[idx] = up_per_cell[idx].saturating_add(r.upload_bytes);
        dn_per_cell[idx] = dn_per_cell[idx].saturating_add(r.download_bytes);
    }
    let raw_max = up_per_cell
        .iter()
        .zip(dn_per_cell.iter())
        .map(|(u, d)| u.saturating_add(*d))
        .max()
        .unwrap_or(0);
    let total_window: u64 = up_per_cell
        .iter()
        .zip(dn_per_cell.iter())
        .map(|(u, d)| u.saturating_add(*d))
        .sum();
    // Y-axis ceiling rounded UP to the nearest «nice» power-of-1024
    // step so the topmost label reads clean («10 GiB» instead of
    // «8.7 GiB» — operators round in their head anyway, the chart
    // should do it for them).
    let y_max = nice_byte_ceiling(raw_max);
    // Chart geometry. Coordinates are in SVG-user units; the outer
    // <svg> uses `viewBox` so the chart scales responsively to its
    // container width without distorting proportions.
    let vb_w = 720;
    let vb_h = 240;
    let pad_l = 64; // y-axis label column
    let pad_r = 16; // breathing room on right
    let pad_t = 12; // top breathing room
    let pad_b = 44; // x-axis label row + legend
    let plot_w = (vb_w - pad_l - pad_r) as f64;
    let plot_h = (vb_h - pad_t - pad_b) as f64;
    let n_ticks_y: usize = 4;
    let bar_slot = plot_w / cells as f64;
    let bar_gap = if cells > 14 { 2.0 } else { 4.0 };
    let bar_w = (bar_slot - bar_gap).max(2.0);
    let mut svg_inner = String::new();
    // Y-axis grid lines + labels at 0, 25%, 50%, 75%, 100% of y_max.
    for t in 0..=n_ticks_y {
        let frac = t as f64 / n_ticks_y as f64;
        let val = ((y_max as f64) * frac) as u64;
        let y = pad_t as f64 + plot_h - frac * plot_h;
        // Grid line spans the plot area only (not over the label
        // column) so the chart-area / label-column separation is
        // clean. Skip the topmost line if it'd touch the chart
        // border.
        svg_inner.push_str(&format!(
            r#"<line x1="{x1}" y1="{y:.1}" x2="{x2}" y2="{y:.1}" stroke="var(--rule)" stroke-width="0.5"/>"#,
            x1 = pad_l,
            x2 = vb_w - pad_r,
        ));
        // Right-aligned Y label.
        svg_inner.push_str(&format!(
            r#"<text x="{x:.1}" y="{ty:.1}" text-anchor="end" font-family="var(--mono)" font-size="10" fill="var(--mute)">{label}</text>"#,
            x = pad_l as f64 - 6.0,
            ty = y + 3.0,
            label = if val == 0 {
                "0".to_string()
            } else {
                humanize_bytes(val)
            },
        ));
    }
    // X-axis baseline (the «0» line is implicit in the lowest grid
    // row above, but draw an explicit darker line so the chart has
    // a clear floor).
    svg_inner.push_str(&format!(
        r#"<line x1="{x1}" y1="{y:.1}" x2="{x2}" y2="{y:.1}" stroke="var(--ink)" stroke-width="0.8"/>"#,
        x1 = pad_l,
        x2 = vb_w - pad_r,
        y = pad_t as f64 + plot_h,
    ));
    // Bars + per-bar tooltips. Iterate cells; for each non-zero
    // total, draw upload then download stacked.
    for i in 0..cells {
        let up = up_per_cell[i];
        let dn = dn_per_cell[i];
        let total = up.saturating_add(dn);
        let x_left = pad_l as f64 + i as f64 * bar_slot + bar_gap / 2.0;
        let bucket_start =
            now - chrono::Duration::seconds((cells as i64 - 1 - i as i64) * bucket_seconds);
        let tooltip = format!(
            "{label}\n↓ download: {dn_h}\n↑ upload: {up_h}\ntotal: {t_h}",
            label = x_axis_tick_label(bucket_start, window.bucket_hours),
            dn_h = humanize_bytes(dn),
            up_h = humanize_bytes(up),
            t_h = humanize_bytes(total),
        );
        // Empty bar still gets a hover-rect so tooltip works even
        // on quiet hours («0 download, 0 upload at 03:00»). Hover
        // rect is invisible (fill="transparent") but full plot
        // height for easy targeting.
        svg_inner.push_str(&format!(
            r#"<g><title>{tooltip}</title><rect x="{x:.1}" y="{ht_y}" width="{w:.1}" height="{ht_h:.1}" fill="transparent"/>"#,
            x = x_left,
            ht_y = pad_t,
            w = bar_w,
            ht_h = plot_h,
        ));
        if y_max > 0 && total > 0 {
            let up_h = (up as f64 / y_max as f64) * plot_h;
            let dn_h = (dn as f64 / y_max as f64) * plot_h;
            let up_y = pad_t as f64 + plot_h - up_h;
            let dn_y = up_y - dn_h;
            if up_h > 0.3 {
                svg_inner.push_str(&format!(
                    r#"<rect x="{x:.1}" y="{up_y:.1}" width="{w:.1}" height="{up_h:.1}" fill="var(--soft)"/>"#,
                    x = x_left,
                    w = bar_w,
                ));
            }
            if dn_h > 0.3 {
                svg_inner.push_str(&format!(
                    r#"<rect x="{x:.1}" y="{dn_y:.1}" width="{w:.1}" height="{dn_h:.1}" fill="var(--acc)"/>"#,
                    x = x_left,
                    w = bar_w,
                ));
            }
        }
        svg_inner.push_str("</g>");
    }
    // X-axis labels. Pick tick interval so we render ~5-8 labels
    // total — denser windows skip ticks to avoid collision.
    let tick_every = match cells {
        0..=8 => 1,
        9..=16 => 2,
        17..=32 => 5,
        _ => 6,
    };
    for i in 0..cells {
        if i % tick_every != 0 && i != cells - 1 {
            continue;
        }
        let x_center = pad_l as f64 + i as f64 * bar_slot + bar_slot / 2.0;
        let bucket_start =
            now - chrono::Duration::seconds((cells as i64 - 1 - i as i64) * bucket_seconds);
        let label = x_axis_tick_label(bucket_start, window.bucket_hours);
        svg_inner.push_str(&format!(
            r#"<text x="{x:.1}" y="{y}" text-anchor="middle" font-family="var(--mono)" font-size="10" fill="var(--mute)">{label}</text>"#,
            x = x_center,
            y = vb_h - pad_b + 18,
        ));
    }
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {vb_w} {vb_h}" preserveAspectRatio="xMidYMid meet" aria-label="VPN traffic chart" style="display: block; width: 100%; max-width: 720px; height: auto;">{svg_inner}</svg>"#,
    );
    html! {
        div style="margin: 12px 0; padding: 12px 14px; background: var(--paper); border: 1px solid var(--rule);" {
            (maud::PreEscaped(svg))
            // Legend + summary line. Inline-flex so they stay on
            // one row when there's space and wrap on narrow viewports.
            div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: 12px; font-family: var(--mono); font-size: 11px; color: var(--mute); margin-top: 4px; padding: 0 4px;" {
                span {
                    span style="display: inline-block; width: 10px; height: 10px; background: var(--acc); vertical-align: middle; margin-right: 4px;" {}
                    (crate::i18n::tr(lang, "download", "загрузка"))
                    "  ·  "
                    span style="display: inline-block; width: 10px; height: 10px; background: var(--soft); vertical-align: middle; margin-right: 4px;" {}
                    (crate::i18n::tr(lang, "upload", "отправка"))
                }
                span {
                    (crate::i18n::tr(lang, "max ", "макс "))
                    b style="color: var(--ink);" { (humanize_bytes(raw_max)) }
                    " " (per_bucket) "  ·  "
                    (crate::i18n::tr(lang, "total ", "всего "))
                    b style="color: var(--ink);" { (humanize_bytes(total_window)) }
                }
            }
        }
    }
}

/// Top-of-page «time window» picker (2026-05-23 — Pavel «возможность
/// выбора как window: 24h / 7 days / 30 days / all»).
///
/// Renders ONE shared picker that drives every time-series tile on
/// the page below (VPN activity, Heavy users, Fleet traffic chart,
/// user-detail Live VPN stats, …). Sits at the top so the operator
/// picks once and scrolls down to see all tiles in sync.
///
/// Tab links use `#timeframe` anchor so a click jumps the browser
/// BACK to this picker (not the page top) after the reload —
/// preserves Pavel's «scroll-to-top is annoying» feedback.
///
/// `base_url` is the absolute path WITHOUT query string.
pub(super) fn window_picker_section(
    base_url: &str,
    active_slug: &str,
    lang: crate::i18n::Locale,
) -> Markup {
    html! {
        div id="timeframe" style="margin: 20px 0 6px; padding: 10px 14px; border: 1px solid var(--rule); background: var(--paper); display: flex; flex-wrap: wrap; gap: 18px; align-items: baseline;" {
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                (crate::i18n::tr(lang, "Window", "Окно"))
            }
            div style="display: flex; gap: 14px; font-family: var(--mono); font-size: 13px;" {
                @for w in VPN_SPARKLINE_WINDOWS {
                    @let label = match lang {
                        crate::i18n::Locale::En => w.label_en,
                        crate::i18n::Locale::Ru => w.label_ru,
                    };
                    @if w.slug == active_slug {
                        span style="font-weight: 600; color: var(--ink); border-bottom: 1.5px solid var(--ink); padding-bottom: 1px;" {
                            (label)
                        }
                    } @else {
                        a href=(format!("{base_url}?vpn_window={}#timeframe", w.slug))
                          style="color: var(--mute); text-decoration: none; border-bottom: 1px dotted var(--mute); padding-bottom: 1px;" {
                            (label)
                        }
                    }
                }
            }
            span style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 11px; margin-left: auto;" {
                (crate::i18n::tr(
                    lang,
                    "→ all charts + tiles below update together (custom date range — coming next)",
                    "→ все графики и плитки ниже обновляются вместе (произвольный диапазон дат — в следующем релизе)",
                ))
            }
        }
    }
}

/// Daemon-wide default threshold when a user has none set. 80% is
/// the magic number — operators historically miss the limit when
/// alerts only fire at 100% (by then the user is already over).
/// Picked once here so changing it later is one constant edit.
pub(crate) const DEFAULT_TRAFFIC_THRESHOLD_PCT: u8 = 80;

/// Format bytes as `1.2 GiB / 5 GiB (24%)` — used in the usage
/// progress bar copy.
fn fmt_traffic_progress(used: u64, limit: u64) -> String {
    let pct = if limit == 0 {
        0
    } else {
        ((used as u128 * 100) / limit as u128).min(999) as u32
    };
    format!(
        "{used} / {limit} ({pct}%)",
        used = humanize_bytes(used),
        limit = humanize_bytes(limit),
    )
}

/// user#3 — straight-line month-end traffic projection. Extrapolates
/// `used` (month-to-date bytes) to a full-month estimate assuming the
/// rest of the month matches the daily average so far:
/// `used / day_of_month × days_in_month`.
///
/// Returns `None` when `used == 0` (nothing to project — the «0»
/// projection is noise, not signal) so the caller can skip the line.
/// `day_of_month` is calendar-1-based and therefore never 0, but the
/// `.max(1)` guard makes the division provably panic-free regardless
/// of any future clock-skew bug. Saturating arithmetic throughout.
fn project_month_end(used: u64) -> Option<u64> {
    use chrono::Datelike;
    if used == 0 {
        return None;
    }
    let now = chrono::Utc::now();
    let day = u64::from(now.day()).max(1); // 1..=31, guarded
    let days_in_month = u64::from(days_in_month(now.year(), now.month()));
    // used / day × days_in_month, computed in u128 to avoid an
    // intermediate overflow on a multi-TiB month, then saturated back.
    let projected = (u128::from(used) * u128::from(days_in_month)) / u128::from(day);
    Some(projected.min(u128::from(u64::MAX)) as u64)
}

/// Calendar days in `(year, month)`. Handles leap Februaries. Returns
/// 30 for an out-of-range month (defensive — `chrono::Month` is always
/// 1..=12 in practice, but the fallback keeps the projection finite).
fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
        _ => 30,
    }
}

/// Per-user traffic-limit section on the user-detail page. Shows
/// the month-to-date total + the configured limit (if any) + an
/// inline form to change both. Operator can set a cap even when
/// no traffic has accrued yet — alerts fire only after the limit
/// is crossed.
pub(crate) async fn user_traffic_limit_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let used = state
        .inv
        .user_traffic_this_month(uid)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "user_traffic_this_month failed");
            0
        });
    let (limit_opt, threshold_opt) = state
        .inv
        .get_user_traffic_limit(uid)
        .await
        .unwrap_or((None, None));
    let threshold_eff = threshold_opt.unwrap_or(DEFAULT_TRAFFIC_THRESHOLD_PCT);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Traffic limit · month-to-date", "Лимит трафика · с начала месяца")) }
        @match limit_opt {
            Some(lim) if lim > 0 => {
                @let pct = ((used as u128 * 100) / lim as u128).min(999) as u32;
                @let over_threshold = pct >= u32::from(threshold_eff);
                @let over_limit = pct >= 100;
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                    (tr(
                        lang,
                        "Total upload + download this calendar month vs. the configured monthly cap. Alert fires at ",
                        "Суммарно upload + download за календарный месяц vs. настроенный месячный лимит. Алерт срабатывает при ",
                    ))
                    span.ed-mono { (threshold_eff) "%" } "."
                }
                div style="font-family: var(--mono); font-size: 13px; margin: 0 0 8px;" {
                    (fmt_traffic_progress(used, lim))
                    @if over_limit {
                        " · "
                        span style="color: var(--acc); font-weight: 600;" { (tr(lang, "OVER LIMIT", "СВЕРХ ЛИМИТА")) }
                    } @else if over_threshold {
                        " · "
                        span style="color: var(--acc);" { (tr(lang, "near limit", "у лимита")) }
                    }
                }
                @let bar_pct = pct.min(100);
                @let bar_fill = if over_threshold { "var(--acc)" } else { "var(--ink)" };
                @let _ = over_limit;
                div style="height: 8px; background: var(--rule); margin-bottom: 16px; overflow: hidden;" {
                    div style=(format!("height: 100%; width: {bar_pct}%; background: {bar_fill};")) {}
                }
                // user#3 — straight-line month-end projection. «If the
                // rest of the month looks like the part so far»:
                // used / day-of-month × days-in-month. Guards the
                // day-of-month == 0 impossibility (calendar days are
                // 1-based; the guard is belt-and-suspenders so a future
                // clock bug can't divide by zero). Only meaningful with
                // a cap set, so it lives in this arm.
                @if let Some(projected) = project_month_end(used) {
                    @let proj_pct = ((projected as u128 * 100) / lim as u128).min(999) as u32;
                    @let proj_over = proj_pct >= 100;
                    p style="font-family: var(--mono); font-size: 12px; margin: 0 0 14px; color: var(--mute);" {
                        (tr(lang, "projected ", "прогноз "))
                        span style=(if proj_over { "color: var(--acc); font-weight: 600;" } else { "color: var(--ink);" }) {
                            (humanize_bytes(projected))
                        }
                        (tr(lang, " by month-end (", " к концу месяца ("))
                        (proj_pct) (tr(lang, "% of cap)", "% лимита)"))
                        @if proj_over {
                            " · "
                            (tr(lang, "on track to exceed the cap", "по тренду превысит лимит"))
                        }
                    }
                }
            }
            _ => {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                    (tr(lang, "Used this month: ", "Использовано в этом месяце: "))
                    span.ed-mono { (humanize_bytes(used)) }
                    (tr(lang, " — no monthly cap configured. Set one below to get the ", " — месячный лимит не задан. Задай ниже, чтобы получать "))
                    span.ed-mono { (DEFAULT_TRAFFIC_THRESHOLD_PCT) "%-" (tr(lang, "of-limit alert", "от-лимита алерт")) }
                    (tr(lang, " on the dashboard.", " на дашборде."))
                }
            }
        }

        form method="post"
             action=(format!("/admin/users/{}/traffic-limit", path_segment_encode(&uid.0)))
             style="display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; padding: 10px 12px; background: var(--paper); border: 1px solid var(--rule);" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                (tr(lang, "limit", "лимит"))
            }
            // Operator-friendly input: GiB. Backend converts to
            // bytes. 0 / empty = clear the limit. With no cap the
            // field renders EMPTY + a placeholder — a literal «0.0»
            // read as "limit is zero" (design review 2026-07-10).
            @let limit_gib_value = limit_opt
                .map(|b| format!("{:.1}", b as f64 / 1_073_741_824.0))
                .unwrap_or_default();
            input type="number" name="limit_gib" step="0.1" min="0" max="100000"
                  value=(limit_gib_value)
                  placeholder=(tr(lang, "no cap", "нет лимита"))
                  title=(tr(
                      lang,
                      "Monthly cap in GiB (upload + download summed). 0 / empty = no cap. Resets on the first of each month.",
                      "Месячный лимит в GiB (upload + download суммой). 0 / пусто = без лимита. Сбрасывается первого числа месяца.",
                  ))
                  style="max-width: 80px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { (tr(lang, "GiB / month", "GiB / месяц")) }
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-left: 8px;" {
                (tr(lang, "alert at", "алерт при"))
            }
            input type="number" name="threshold_pct" step="1" min="1" max="100"
                  value=(threshold_eff)
                  title=(tr(
                      lang,
                      "Fire a dashboard alert (and Telegram if configured) when used / cap >= this percent. Default 80%.",
                      "Поднять алерт на дашборде (и в Telegram, если настроен), когда израсходовано ≥ этого процента лимита. По умолчанию 80%.",
                  ))
                  style="max-width: 56px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "%" }
            button type="submit"
                   title=(tr(
                       lang,
                       "Set both fields. 0 GiB = clear the limit (no cap).",
                       "Сохраняет оба поля. 0 GiB = снять лимит.",
                   ))
                   style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer; margin-left: auto;" {
                (crate::i18n::t(lang, crate::i18n::K::BtnSave))
            }
        }
    }
}

/// Phase 5c — «Когда была активна» session timeline. Builds an
/// implicit «active from-to» window per (user, server) from the
/// 5-min clash-poll observations: consecutive ticks extend the
/// session; a gap > 15 minutes closes it. Empty until the
/// poller has run at least one tick post-Phase-5c deploy.
pub(crate) async fn user_sessions_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    const LIMIT: i64 = 20;
    let rows = state
        .inv
        .recent_sessions_for_user(uid, LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "recent_sessions_for_user failed");
            Vec::new()
        });
    // TT-4: a session is "live" if its last tick landed within ~one
    // poll interval (5-min poll + slack) of now.
    let now = chrono::Utc::now();
    let live_cutoff = chrono::Duration::minutes(6);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Sessions · recent 20", "Сессии · последние 20"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Implicit «active from-to» windows per (user, server), newest activity first. Derived from 5-min clash-poll observations: consecutive ticks extend the session; a gap >15 minutes closes it and the next tick opens a new row. Because activity is sampled every 5 minutes, a window seen in a single tick renders «≤5m» (real duration unknown below that granularity). Peak conns shows the busiest snapshot during the session.",
                "Окна «активна с-по» на (юзер, сервер), свежая активность сверху. Источник — 5-минутные тики clash-poll: последовательные тики расширяют сессию, пропуск >15 минут закрывает её, следующий тик открывает новую. Активность сэмплится раз в 5 минут, поэтому окно, увиденное одним тиком, показывается как «≤5m» (точная длительность ниже этой гранулярности неизвестна). Peak conns — самый загруженный snapshot в этой сессии.",
            ))
        }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(
                    lang,
                    "No sessions yet. The poller writes one row per (user, server, activity window) — wait for the next clash-api scrape.",
                    "Сессий ещё нет. Поллер пишет одну запись на (юзер, сервер, окно активности) — подожди следующий скрейп clash-api.",
                ))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "server", "сервер"))
                        }
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "started", "началось"))
                        }
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "last seen", "последний"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "duration", "длительность"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;"
                           title=(tr(lang, "Max active_connections observed across all 5-min ticks within the session.", "Max active_connections по всем 5-минутным тикам внутри сессии.")) {
                            (tr(lang, "peak conns", "макс. соед."))
                        }
                    }
                }
                tbody {
                    @for r in &rows {
                        @let dur = r.duration();
                        @let mins = dur.num_minutes().max(0);
                        // TT-4: single-tick windows (started==last_seen)
                        // are «≤5m» not the misleading «0m» — the user
                        // WAS active, we just can't resolve below the
                        // 5-min poll granularity.
                        @let dur_str = if mins == 0 {
                            "≤5m".to_string()
                        } else if mins >= 60 {
                            format!("{}h{:02}m", mins / 60, mins % 60)
                        } else {
                            format!("{mins}m")
                        };
                        @let is_live = now.signed_duration_since(r.last_seen) < live_cutoff;
                        tr style=(if is_live { "border-bottom: 1px dotted var(--rule); background: color-mix(in oklab, var(--green) 7%, var(--paper));" } else { "border-bottom: 1px dotted var(--rule);" }) {
                            td style="padding: 4px 8px;" {
                                a href=(format!("/admin/servers/{}", crate::http_util::path_segment_encode(&r.server_id.0))) style="color: var(--ink); text-decoration: none;" { (r.server_id.0) }
                            }
                            td style="padding: 4px 8px;" { (format_msk(r.started_at)) }
                            td style="padding: 4px 8px;" {
                                (format_msk(r.last_seen))
                                @if is_live {
                                    " " span style="color: var(--green); font-weight: 600;" {
                                        "● " (tr(lang, "live", "активна"))
                                    }
                                }
                            }
                            td style="padding: 4px 8px; text-align: right; font-weight: 500;" { (dur_str) }
                            td style="padding: 4px 8px; text-align: right;" { (r.conn_count_peak) }
                        }
                    }
                }
            }
        }
    }
}

/// Phase 5b — «Куда ходит этот юзер» section. Top destinations
/// over the last 7 days, ranked by hit count (number of 5-min
/// clash-poll ticks where the pair was observed). Empty until
/// the poller has run at least one tick post-Phase-5b deploy.
pub(crate) async fn user_top_destinations_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    const TOP_N: u32 = 20;
    const WINDOW_DAYS: u32 = 7;
    let rows = state
        .inv
        .top_destinations_for_user(uid, WINDOW_DAYS, TOP_N)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "top_destinations_for_user failed");
            Vec::new()
        });

    // Phase 5d: enrich bare-IP labels via `dns_ptr_cache`. The
    // poller writes `IP:port` when sing-box's metadata.host was
    // empty (most TCP-to-IP traffic); the resolver background
    // job populates `dns_ptr_cache` separately. At render time we
    // bulk-lookup so each row that's still a bare IP can be shown
    // as `hostname:port (ip)` — matching the format
    // `snapshot_cache::aggregate_by_destination` uses on the
    // server-detail page (one canonical render shape for both).
    let mut ip_candidates: Vec<String> = rows
        .iter()
        .filter_map(|r| extract_ip_from_label(&r.destination_label).map(str::to_owned))
        .collect();
    ip_candidates.sort();
    ip_candidates.dedup();
    let dns_map = if ip_candidates.is_empty() {
        std::collections::HashMap::new()
    } else {
        state
            .inv
            .lookup_dns_ptr_bulk(&ip_candidates)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "lookup_dns_ptr_bulk failed");
                std::collections::HashMap::new()
            })
    };

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Top destinations · last 7 days", "Топ destinations · 7 дней"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Which hosts this user connects to most often. Derived from clash-api snapshots (one hit per 5-minute tick where a connection to that destination was active). Reverse-DNS resolved when possible (Phase 5a-2 cache).",
                "На какие хосты юзер ходит чаще всего. Источник — snapshot'ы clash-api (один hit на 5-минутный тик, в котором соединение к этому destination было активно). Reverse-DNS подставляется когда возможно (Phase 5a-2 cache).",
            ))
        }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(
                    lang,
                    "No destination history yet. The poller writes one hit per (destination, 5-min tick) — wait for the next clash-api scrape to fill this section.",
                    "Истории destinations ещё нет. Поллер пишет один hit на (destination, 5-минутный тик) — подожди следующий скрейп clash-api.",
                ))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "destination", "destination"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;"
                           title=(tr(lang, "Number of 5-min ticks where a connection to this destination was alive. Not connection count — a long-lived connection contributes N hits, N = ticks-it-was-up.", "Число 5-мин тиков, в которых соединение к этому destination было активно. Не число соединений — долгое соединение даёт N hits, N = тиков-сколько-жило.")) {
                            (tr(lang, "hits · 7d", "hits · 7д"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "last seen", "последний раз"))
                        }
                    }
                }
                tbody {
                    @for r in &rows {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 4px 8px; overflow-wrap: anywhere;" {
                                (enrich_destination_label(&r.destination_label, &dns_map))
                            }
                            td style="padding: 4px 8px; text-align: right; font-weight: 500;" { (r.hit_count) }
                            td style="padding: 4px 8px; text-align: right; color: var(--mute);" {
                                (format_msk(r.last_seen))
                            }
                        }
                    }
                }
            }
        }
    }
}

pub(crate) async fn live_vpn_stats_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    window_slug: Option<&str>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let window = pick_vpn_sparkline_window(window_slug);
    let since_hours = window.cells * window.bucket_hours;
    let rows = match state.inv.recent_vpn_stats_for_user(uid, since_hours).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "recent_vpn_stats_for_user failed");
            return html! {
                div.ed-rule {}
                div.ed-art-eyebrow { (tr(lang, "Live VPN stats", "Живая статистика VPN")) }
                p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                    (tr(lang, "(temporarily unavailable — please retry)", "(временно недоступно — повтори попытку)"))
                }
            };
        }
    };
    if rows.is_empty() {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { (t(lang, K::EyebrowLiveStats)) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    // Honest copy (audit 2026-06-10): the scheduler is
                    // LIVE (spawn_clash_poller, 5-min cadence) — blank
                    // here means no snapshot reached this user yet:
                    // poller can't SSH the node, sing-box clash-api off,
                    // or the user simply hasn't connected.
                    "No live stats yet. The clash-api poller runs every 5 minutes — blank means no snapshot has covered this user yet: the node may be unreachable over SSH, its sing-box may lack the clash-api block, or the user hasn't connected. The poller needs the SSH key on the vpnctld host's ",
                    "Живой статистики пока нет. Поллер clash-api снимает снэпшоты каждые 5 минут — пусто значит ни один снэпшот ещё не зацепил этого юзера: нода может быть недоступна по SSH, в её sing-box может не быть clash-api блока, либо юзер не подключался. Поллеру нужен SSH-ключ на хосте vpnctld в ",
                ))
                span.ed-mono { "/var/lib/vpnctl/.ssh" }
                (tr(
                    lang,
                    " plus per-node authorisation. Once wired, this section will show real per-user upload/download totals and active connection counts.",
                    " плюс авторизация на каждой ноде. Когда подключим — раздел покажет реальные upload/download по пользователю и активные подключения.",
                ))
            }
        };
    }

    // Aggregate over the window: total up + down (sum of all rows
    // for this user), peak active_connections.
    let mut total_up: u64 = 0;
    let mut total_dn: u64 = 0;
    let mut peak_conns: u32 = 0;
    let mut per_server: std::collections::BTreeMap<String, (u64, u64, u32)> =
        std::collections::BTreeMap::new();
    for r in &rows {
        total_up = total_up.saturating_add(r.upload_bytes);
        total_dn = total_dn.saturating_add(r.download_bytes);
        if r.active_connections > peak_conns {
            peak_conns = r.active_connections;
        }
        let entry = per_server.entry(r.server_id.0.clone()).or_default();
        entry.0 = entry.0.saturating_add(r.upload_bytes);
        entry.1 = entry.1.saturating_add(r.download_bytes);
        if r.active_connections > entry.2 {
            entry.2 = r.active_connections;
        }
    }

    let window_label = match lang {
        crate::i18n::Locale::En => window.label_en,
        crate::i18n::Locale::Ru => window.label_ru,
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Live VPN stats · ", "Живая VPN-статистика · "))
            (window_label)
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Pulled from each node's clash-api by the daemon. Numbers reflect actual VPN traffic (delta-vs-prior-snapshot per tick), not subscription-config fetches.",
                "Снимается с clash-api каждой ноды демоном. Числа — реальный VPN-трафик (дельта-к-прошлому-снэпшоту на каждом тике), не запросы конфига подписки.",
            ))
        }
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 18px;" {
            (status_tile("uploaded", &humanize_bytes(total_up), "var(--ink)"))
            (status_tile("downloaded", &humanize_bytes(total_dn), "var(--ink)"))
            (status_tile("peak conns", &peak_conns.to_string(), "var(--ink)"))
        }
        // user#6 — 7d/30d traffic trend folded in here. A
        // `window_picker_section` scoped to THIS user's detail page lets
        // the operator widen the window (24h / 7d / 30d / all) without a
        // separate query — the section already re-fetched `rows` at the
        // picked window above, so the compact `sparkline_svg` below just
        // re-buckets those same rows into per-cell (up+down) totals. The
        // full PowerBI-style chart still renders below; this is the
        // at-a-glance shape so a 30-day trend is one click away.
        (window_picker_section(
            &format!("/admin/users/{}/traffic", path_segment_encode(&uid.0)),
            window.slug,
            lang,
        ))
        @let trend = vpn_traffic_trend_series(&rows, window);
        @if trend.iter().any(|&v| v > 0.0) {
            @let trend_max = trend.iter().copied().fold(0.0_f64, f64::max);
            div style="margin: 6px 0 18px;" {
                div style="font-family: var(--mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-bottom: 2px;" {
                    (tr(lang, "traffic trend · ", "тренд трафика · ")) (window_label)
                }
                // R2 2026-07-10: label_max off — the in-SVG label printed
                // RAW BYTES («max 84028835»); the humanized caption below
                // replaces it. Width matches the tables (was 720 ≈ half).
                (sparkline_svg_scaled(&trend, 1160, 60, None, false))
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                    (tr(lang, "max ", "макс ")) (humanize_bytes(trend_max as u64))
                    (tr(lang, " per bucket", " на интервал"))
                }
            }
        }
        @if !per_server.is_empty() {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "server", "сервер")) }
                        th title=(tr(
                            lang,
                            "Sum of upload-bytes deltas from clash-api 5-min ticks over the picked window, weighted by each node's usage coefficient. Counts everything sing-box saw on this user's auth — VLESS, TUIC, Trojan; wgturn / WireGuard NOT included (kernel-level, no clash-api visibility).",
                            "Сумма upload-дельт clash-api (тик 5 минут) за выбранное окно, взвешенная коэффициентом нагрузки ноды. Считает всё, что sing-box видел на auth этого юзера — VLESS, TUIC, Trojan; wgturn / WireGuard НЕ входят (kernel-уровень, clash-api их не видит).",
                        ))
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "uploaded", "отправлено")) }
                        th title=(tr(lang, "Same window + same caveats as uploaded — download direction.", "То же окно и те же оговорки, что и у «отправлено» — направление download."))
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "downloaded", "принято")) }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "total", "всего")) }
                        th title=(tr(
                            lang,
                            "Maximum simultaneous active connections seen for this user during any 5-min poll window. >50 from a phone client = unusual (chat apps + browser keep ~5-15 sustained); >200 typically means torrent / web-crawler.",
                            "Максимум одновременных соединений юзера в любом 5-минутном окне поллера. >50 с телефона — необычно (мессенджеры + браузер держат ~5-15); >200 — обычно торрент / краулер.",
                        ))
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "peak conns", "пик соед.")) }
                    }
                }
                tbody {
                    @for (server_id, (up, dn, conns)) in &per_server {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 5px 8px; color: var(--ink);" { (server_id) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*up)) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*dn)) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink); font-weight: 600;" { (humanize_bytes(up.saturating_add(*dn))) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (conns) }
                        }
                    }
                }
            }
        }
        // 2026-05-23 — PowerBI-style chart. Window picker now
        // lives at top of page (`window_picker_section`); chart-
        // internal tabs removed so the operator has one mental
        // model «pick once, all tiles update». Anchor stays so
        // tab clicks from the top picker (or anchor links from
        // elsewhere) scroll back to the chart.
        div id="vpn-traffic" {
            (vpn_traffic_chart(&rows, window, lang))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 10px;" {
            (crate::i18n::tr(lang, "Aggregated from ", "Агрегировано из ")) (rows.len())
            @if rows.len() == 1 {
                (crate::i18n::tr(lang, " snapshot", " снэпшота"))
            } @else {
                (crate::i18n::tr(lang, " snapshots", " снэпшотов"))
            }
            (crate::i18n::tr(
                lang,
                " over the last 24 hours. Rows are auto-purged after 30 days.",
                " за последние 24 часа. Строки автоудаляются через 30 дней.",
            ))
        }
    }
}

// `vpn_kpi_tile` removed 2026-05-18 — was exactly equivalent to
// `status_tile(label, value, "var(--ink)")`. The 3 call sites at
// `live_vpn_stats_section` now invoke `status_tile` directly with
// the ink color so the editorial chrome (border + label-style + serif
// number) lives in exactly one helper.

// Error response helpers moved to helpers.rs

// `format_size_bytes` (storage sizes — JEDEC KB/MB/GB labels) moved
// to `vpnctl_core::humanize::format_size_bytes` (2026-05-18, post-
// host-fingerprint consolidation pass) — same fn was byte-identical
// in `cli/src/cmd/backup.rs`. **NOTE:** the sibling `humanize_bytes`
// (defined ~400 lines up, IEC KiB/MiB/GiB labels, 9 call sites for
// traffic counts) is INTENTIONALLY a different helper — see the
// crate-level rustdoc on `vpnctl_core::humanize` for the split
// rationale (storage vs traffic, JEDEC vs IEC).

/// Background, best-effort redeploy of `servers` after an inventory
/// mutation that changes node membership (grant / revoke / disable /
/// enable / delete) so the change lands on the nodes WITHOUT a manual
/// «Deploy all». Mirrors that button, scoped to the affected servers.
/// Without this, a grant only writes inv.db: the sub URI appears
/// instantly but the UUID never reaches the node's `users[]`, so the
/// REALITY handshake succeeds, VLESS-auth rejects, and the client is
/// silently forwarded to the cover dest — «connects but no internet»
/// (HANDOFF 2026-07-08 §4.1). `servers` must be captured by the caller
/// at the right moment — for a DELETE, BEFORE the cascade drops the
/// grants. Empty → no-op. `subject` labels the audit row: user id for
/// user-scoped triggers, server id for server-side bulk grant/revoke.
/// NOTE: apply_config restarts sing-box, so other users on a node see
/// a brief blip — inherent to any config change.
pub(crate) fn spawn_user_servers_redeploy(
    state: &AppState,
    servers: Vec<vpnctl_core::Server>,
    subject: String,
    trigger: &'static str,
) {
    if servers.is_empty() {
        return;
    }
    let inv = state.inv.clone();
    let registry = std::sync::Arc::clone(&state.registry);
    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let server_ids: Vec<String> = servers.iter().map(|s| s.id.0.clone()).collect();
    // Server-side bulk triggers target a SERVER; keep them out of the
    // `user.*` audit namespace so user-timeline filters don't surface
    // server-targeted rows (review 2026-07-08).
    let action: &'static str = if trigger.starts_with("server.") {
        "server.autodeploy"
    } else {
        "user.autodeploy"
    };
    tokio::spawn(async move {
        let errors = crate::wizard_bootstrap::redeploy_servers_collect_errors(
            servers,
            inv.clone(),
            registry,
            key_path,
        )
        .await;
        if errors.is_empty() {
            tracing::info!(
                target = "vpnctld::admin",
                subject = %subject,
                trigger,
                "auto-deploy applied (config re-rendered + sing-box reloaded)"
            );
        } else {
            tracing::warn!(
                target = "vpnctld::admin",
                subject = %subject,
                trigger,
                errors = ?errors,
                "auto-deploy: some servers failed to apply — retry via Deploy all"
            );
        }
        let _ = inv
            .audit(
                "admin",
                action,
                Some(&subject),
                Some(&serde_json::json!({
                    "trigger": trigger,
                    "servers": server_ids,
                    "ok": errors.is_empty(),
                    "errors": errors,
                })),
            )
            .await;
    });
}
