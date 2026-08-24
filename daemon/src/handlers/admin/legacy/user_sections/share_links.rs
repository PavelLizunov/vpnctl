use std::collections::HashMap;

use axum::http::{HeaderMap, header};
use maud::{Markup, html};

use crate::AppState;
use crate::handlers::admin::users::mask_secret;

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

/// Sibling of `collect_share_links` — one `vpn://` deep link per
/// granted server that declares the `wireguard` protocol. Used by the
/// user-detail page's Flow C card (AmneziaVPN).
///
/// Errors from `amnezia_share_link` (missing user pubkey, missing
/// server private key, malformed pubkey) are LOGGED-AND-SKIPPED — the
/// page still renders. The empty-state classifier in the Flow C card
/// distinguishes "no grants" from "no WG-capable server" from "render
/// failed" using the same `wg_capable_granted` tally as Flow B.
pub(crate) fn collect_amnezia_links(
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &HashMap<vpnctl_core::ServerId, HashMap<String, String>>,
    peers_per_server: &HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
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
/// WG-enabled granted server for the user-detail Flow F card (the
/// operator's sing-box-lx-based client app). Servers without minted
/// AmneziaWG obfs (i.e. not running the `amneziawg` kernel) or a user
/// without a server-generated private key cause `awg_share_link` to
/// error; those are LOGGED-AND-SKIPPED so the page still renders and the
/// card naturally shows only AmneziaWG-capable servers.
pub(crate) fn collect_awg_links(
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &HashMap<vpnctl_core::ServerId, HashMap<String, String>>,
    peers_per_server: &HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
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

/// Build all (server, protocol) share-links for a user — same logic as
/// the CLI's `vpnctl sub` and the daemon's `/sub/<token>` handler. Each
/// entry has the protocol id and the rendered URI; failures are logged
/// and skipped, never panic.
pub(crate) fn collect_share_links(
    state: &AppState,
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &HashMap<vpnctl_core::ServerId, HashMap<String, String>>,
    peers_per_server: &HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
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
