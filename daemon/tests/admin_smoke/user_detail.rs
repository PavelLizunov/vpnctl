
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{Server, ServerId, User, UserId};
use vpnctl_inventory::VpnStatsDelta;
use vpnctld::router;

use super::common::*;

/// Unknown user id must produce a 404 with the id echoed in the body
/// (helpful for the operator) but NOT mask-leaked beyond plain text.
#[tokio::test]
async fn admin_user_detail_unknown_id_returns_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let txt = std::str::from_utf8(&body).unwrap();
    assert!(
        txt.contains("does-not-exist"),
        "404 body should echo the id the operator asked for, got: {txt}"
    );
}

/// User-detail page on a populated inventory: renders the QR (inline
/// SVG), shows the masked sub-token, lists granted servers, and renders
/// per-protocol share links — NEVER echoing the full sub_token.
#[tokio::test]
async fn admin_user_detail_renders_qr_grants_and_share_links() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;

    // We need protocol secrets for a share-link to render. Seed VLESS
    // secrets on s0 only; s1 stays unconfigured to exercise the
    // skip-on-missing-secrets path.
    s.inv
        .set_server_secret(
            &ServerId("s0".into()),
            "vless.private_key",
            "QGZ8K-private-key-base64==",
        )
        .await
        .unwrap();
    s.inv
        .set_server_secret(
            &ServerId("s0".into()),
            "vless.public_key",
            "PUBLIC-KEY-BASE64=",
        )
        .await
        .unwrap();
    s.inv
        .set_server_secret(&ServerId("s0".into()), "vless.short_id", "deadbeef")
        .await
        .unwrap();
    s.inv
        .set_server_secret(&ServerId("s0".into()), "vless.sni", "www.microsoft.com")
        .await
        .unwrap();

    let u0 = s.inv.get_user(&UserId("u0".into())).await.unwrap().unwrap();
    let token = u0.sub_token.expect("token");

    let app = router(s);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users/u0")
                .header("host", "192.168.0.236:18402")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&bytes).unwrap();

    // The QR is an inline <svg>.
    assert!(html.contains("<svg "), "QR svg missing");
    // The QR is wrapped in a paper card (border-rule), not naked.
    assert!(
        html.contains("border: 1px solid var(--rule)"),
        "QR card border styling missing"
    );
    // The sub URL uses the Host header verbatim.
    let expected_url = format!("http://192.168.0.236:18402/sub/{token}");
    assert!(
        html.contains(&expected_url),
        "sub URL should use the Host header (expected {expected_url})"
    );
    // BUT the masked sub-token preview is also rendered separately, and
    // the FULL token must not appear outside the URL form.
    let occurrences = html.matches(token.as_str()).count();
    assert_eq!(
        occurrences, 1,
        "sub_token should appear exactly once (inside the sub URL), got {occurrences}"
    );
    // ui-audit §4 — the granted-server grid lives on the access tab
    // (lists EVERY granted server, incl. s1 which has no secrets); the
    // rendered share-links live on the delivery tab (only s0 renders).
    let fetch_tab = |uri: &'static str| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("host", "192.168.0.236:18402")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            String::from_utf8(bytes.to_vec()).unwrap()
        }
    };
    let html_access = fetch_tab("/admin/users/u0/access").await;
    // Both granted servers appear in the access grid.
    for id in ["s0", "s1"] {
        assert!(html_access.contains(id), "granted server {id} missing");
    }
    // At least one share-link rendered (s0 has VLESS secrets); s1 should
    // be skipped silently (its share_link will fail on missing secrets).
    let html_delivery = fetch_tab("/admin/users/u0/delivery").await;
    assert!(
        html_delivery.contains("vless://") || html_delivery.contains("Per-protocol share links"),
        "expected share-links section, got snippet: {}",
        &html_delivery[..html_delivery.len().min(800)]
    );

    // Regression for the 2026-05-19 QR-jump bug Pavel screenshotted:
    // the inline <style> that forces all QR SVGs to a uniform 220×220
    // display size MUST be present AND its selector must NOT be
    // HTML-escaped. Pre-fix the selector was `.vpnctl-qr-frame > svg`
    // and Maud escaped `>` to `&gt;` → invalid selector → CSS never
    // applied → QR cards stayed at native SVG dimensions (short URL
    // → 225 px, long wireguard:// → 300+ px, visible jumps).
    assert!(
        html.contains("vpnctl-qr-frame"),
        "QR frame wrapper class must be present so the inline style can target it"
    );
    assert!(
        html.contains(".vpnctl-qr-frame svg") || html.contains(".vpnctl-qr-frame > svg"),
        "inline CSS targeting the QR's SVG child must be present"
    );
    assert!(
        !html.contains(".vpnctl-qr-frame &gt; svg"),
        "Maud escaped `>` in the QR CSS selector — selector is invalid and \
         the size-normalisation CSS will silently fail. Use a descendant \
         selector (no `>`) or wrap the CSS string in PreEscaped."
    );
}

/// A user granted a dns-tunnel server sees the dedicated "Flow E —
/// dns-tunnel" delivery card carrying their OWN per-user
/// `dns-tunnel://…uuid=user.uuid…` link (mirror of wgturn's Flow D).
/// The link must NOT leak into the strict sing-box subscription
/// (`appears_in_sing_box_sub() == false`, pinned separately in
/// sub_endpoint.rs).
#[tokio::test]
async fn user_detail_renders_dns_tunnel_flow_e_card_for_granted_user() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // u0 granted, u1 not granted.
    seed(&s.inv, 0, 2, &[]).await;
    seed_dns_tunnel_server(&s.inv, "dt", "u0").await;

    let u0 = s.inv.get_user(&UserId("u0".into())).await.unwrap().unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/u0/delivery").await;

    // The Flow E delivery card renders.
    assert!(
        html.contains("Flow E"),
        "dns-tunnel Flow E delivery card missing for granted user"
    );
    // The per-user dns-tunnel:// link is surfaced.
    assert!(
        html.contains("dns-tunnel://"),
        "per-user dns-tunnel:// share-link missing from user-detail"
    );
    // The link embeds THIS user's own uuid (base64url payload decodes to
    // JSON carrying `"uuid":"<u0.uuid>"`). Locate the link, decode it,
    // and assert the embedded uuid is u0's.
    use base64::Engine;
    let start = html.find("dns-tunnel://").unwrap() + "dns-tunnel://".len();
    let tail = &html[start..];
    let payload: String = tail
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .expect("payload is base64url-no-pad");
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        v["uuid"].as_str(),
        Some(u0.uuid.as_str()),
        "dns-tunnel link must embed the granted user's own uuid"
    );
}

/// A user with NO dns-tunnel grant must NOT see the Flow E card or any
/// `dns-tunnel://` link — the card is gated on a granted dns-tunnel
/// server (sibling of wgturn's Flow-D gating).
#[tokio::test]
async fn user_detail_omits_dns_tunnel_flow_e_card_for_non_granted_user() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 2, &[]).await;
    // dt granted to u0 only; u1 must not inherit the card.
    seed_dns_tunnel_server(&s.inv, "dt", "u0").await;

    let app = router(s);
    let html = fetch_html(app, "/admin/users/u1/delivery").await;

    assert!(
        !html.contains("Flow E"),
        "Flow E card leaked onto a user with no dns-tunnel grant"
    );
    assert!(
        !html.contains("dns-tunnel://"),
        "dns-tunnel:// link leaked onto a user with no dns-tunnel grant"
    );
}

/// COVERAGE GAP — the user-detail handler has a fallback branch that
/// renders "No sub-token assigned" when `user.sub_token == None`, but
/// the public inventory API never lets us reach that state today:
/// `add_user` inserts whatever the struct holds, then `open()` runs
/// `backfill_sub_tokens` which mints a token for every NULL row. So
/// after `seed()` every user has `Some(token)`.
///
/// The user-detail "pending deploy" banner (multiviruss incident) now
/// carries an in-view one-click deploy button so the operator doesn't
/// have to bounce to /admin/servers. R2 2026-07-10: the button targets
/// the PER-USER pending SSE endpoint — the old fleet deploy-all
/// redeployed every server in the inventory when a single node was
/// pending (operator report). `data-reload-self` reloads THIS page on
/// done so the banner re-computes/clears.
#[tokio::test]
async fn admin_user_detail_pending_banner_has_inline_deploy_all_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // u0 granted s0+s1, NO server.deploy after → pending-deploy banner.
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;
    // The banner keys off the user's latest audit mutation vs each
    // server's last deploy. The low-level `seed()` helper doesn't write
    // audit rows (the real add_user/grant handlers do — that's why
    // satta_blud's banner showed in prod), so stamp a user.grant row to
    // mirror the real flow. With no server.deploy on s0/s1, both are
    // pending → banner renders.
    s.inv
        .audit("admin", "user.grant", Some("u0"), None)
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0").await;
    // Banner is present.
    assert!(
        html.contains("Config not yet deployed to") || html.contains("ещё не задеплоен"),
        "pending-deploy banner must render when grants aren't deployed"
    );
    // In-view deploy button wired to the per-user pending SSE endpoint
    // — NOT the fleet-wide deploy-all.
    assert!(
        html.contains(r#"data-sse-url="/admin/users/u0/deploy-pending/sse""#),
        "in-view deploy button must target the per-user pending SSE endpoint"
    );
    assert!(
        !html.contains(r#"data-sse-url="/admin/servers/deploy-all/sse""#),
        "user page must NOT wire the fleet-wide deploy-all any more"
    );
    // Label carries the pending count (both seeded servers pending).
    assert!(
        html.contains("deploy pending "),
        "button label must say 'deploy pending (N)'"
    );
    assert!(
        html.contains(r#"data-reload-self="true""#),
        "user-page deploy must reload this page (not bounce to /admin/servers)"
    );
    assert!(
        html.contains(r#"id="user-deploy-log""#),
        "in-view deploy needs its own log pane"
    );
}

/// Phase C-2 (writes) will add a `clear_sub_token` / `regenerate_sub_token`
/// pair that lets us write a real assertion here. For now this test
/// just confirms the present-token branch keeps working — see also the
/// handler-side comment marking the dead branch as defensive.
#[tokio::test]
async fn admin_user_detail_handles_missing_sub_token() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;

    // Confirm the precondition: open() backfilled a token, so the
    // None branch can't be reached without bypassing the public API.
    let u0 = s.inv.get_user(&UserId("u0".into())).await.unwrap().unwrap();
    assert!(
        u0.sub_token.is_some(),
        "open() should have backfilled — None branch is currently unreachable via public API"
    );

    let html = fetch_html(router(s), "/admin/users/u0/overview").await;
    assert!(
        html.contains("Subscription"),
        "subscription section heading missing"
    );
    assert!(
        !html.contains("No sub-token assigned"),
        "user has a token — must not render the 'no token' fallback"
    );
}

#[tokio::test]
async fn admin_user_detail_renders_ninitux_url_as_primary_when_device_id_pinned() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // Pin a ninitux device_id on the user.
    s.inv
        .set_vpn_router_device_id(&UserId("u0".into()), TEST_NINITUX_DEVICE_ID)
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/u0/overview").await;

    let expected_ninitux =
        format!("https://ninitux.com/api/v1/app/config/{TEST_NINITUX_DEVICE_ID}");
    assert!(
        html.contains(&expected_ninitux),
        "ninitux production URL must be rendered as the primary subscription URL — \
         expected substring: {expected_ninitux}"
    );
    // device_id is shown verbatim (it's not a secret — it's a device fingerprint).
    assert!(
        html.contains(TEST_NINITUX_DEVICE_ID),
        "vpn_router_device_id must be displayed in the Subscription section"
    );
    // The LAN URL must still appear (operator might need it for debug),
    // but inside a <details> collapsible — not as the primary block.
    assert!(
        html.contains("legacy /sub/&lt;token&gt; fallback")
            || html.contains("legacy /sub/<token> fallback"),
        "legacy /sub/<token> URL must be present BUT demoted inside a <details> labelled 'legacy'"
    );
}

#[tokio::test]
async fn admin_user_detail_qr_encodes_ninitux_url_not_lan_url_when_device_id_pinned() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .set_vpn_router_device_id(&UserId("u0".into()), TEST_NINITUX_DEVICE_ID)
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/u0/overview").await;

    // QR SVG embeds the URL via the qrcode crate. The textContent isn't
    // in the SVG, but the URL appears in the <details> form action OR
    // as an `aria-label` / `title` if rendered. The reliable invariant
    // we can pin: the primary QR card appears BEFORE the <details>
    // legacy fallback, AND the bytes of the ninitux URL appear BEFORE
    // the bytes of the LAN URL in the HTML stream. That ordering proves
    // the ninitux URL is the primary (QR-encoded) one, not the LAN URL.
    let n_pos = html
        .find("https://ninitux.com/api/v1/app/config/")
        .expect("ninitux URL must appear");
    let lan_pos = html
        .find("/sub/")
        .expect("legacy LAN URL must appear (in collapsed fallback)");
    assert!(
        n_pos < lan_pos,
        "ninitux URL ({n_pos}) must appear BEFORE the LAN URL ({lan_pos}) so the \
         QR card encodes ninitux. Otherwise QR encodes the LAN URL = mobile clients break."
    );
}

#[tokio::test]
async fn admin_user_detail_falls_back_to_lan_url_when_no_device_id() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    // u0 has NO vpn_router_device_id pinned — confirm fallback.
    let u0 = s.inv.get_user(&UserId("u0".into())).await.unwrap().unwrap();
    assert!(u0.vpn_router_device_id.is_none());

    let html = fetch_html(router(s), "/admin/users/u0/overview").await;
    // Ninitux URL MUST NOT appear at all — no device_id → no production URL.
    assert!(
        !html.contains("https://ninitux.com/api/v1/app/config/"),
        "no device_id pinned → ninitux URL must NOT render"
    );
    // The empty-state copy must quote the CLI command operator runs to fix this,
    // per CLAUDE.md "Every empty state must quote a literal CLI command".
    assert!(
        html.contains("scripts/import_from_subscription_server.py"),
        "empty-state must point operator at the import script to pin a device_id"
    );
    // Subscription section heading present.
    assert!(html.contains("Subscription"));
}

// ────────────────────────────────────────────────────────────────────────
//  Phase C-3 — write handlers (Users) — first chunk: regenerate sub-token
//
//  These tests exercise the full mutation contract from §"Phase C-3 write
//  handlers" in `daemon/src/handlers/admin.rs`:
//   1. validate target exists → 404 if not
//   2. perform mutation
//   3. write audit row (best-effort; warn-log on failure)
//   4. redirect 303 to the relevant page
//
//  The detail page button is also pinned: it must POST to the right URL
//  so the form keeps wiring together as separate edits land.
// ────────────────────────────────────────────────────────────────────────

/// Happy path: POST regenerate → 303 to /admin/users/{id}; the user's
/// sub_token in the inventory is different from before; an audit row
/// `user.sub_token.regen` lands with target=user-id, actor=admin.
#[tokio::test]
async fn admin_user_regen_sub_token_mutates_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;

    // Snapshot the original token so we can assert it changed.
    let before = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .expect("open() backfilled a token");

    let app = router(s.clone());
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/sub-token/regenerate"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "expected 303 (POST-redirect-GET), got {:?}",
        resp.status()
    );
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/admin/users/u0/overview",
        "redirect target must be the user-detail page"
    );

    // The mutation actually happened.
    let after = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .expect("token still present");
    assert_ne!(
        before, after,
        "sub_token must be different after regenerate"
    );

    // The audit row landed.
    let entries = s.inv.recent_audit(10).await.unwrap();
    let regen = entries
        .iter()
        .find(|e| e.action == "user.sub_token.regen")
        .expect("audit row for user.sub_token.regen missing");
    assert_eq!(regen.actor, "admin");
    assert_eq!(regen.target.as_deref(), Some("u0"));
    assert!(
        regen.payload.is_none(),
        "regen audit row should carry no payload (token MUST NOT be logged)"
    );
}

/// Unknown user path: POST regenerate against an id that doesn't exist
/// must return the canonical 404 + `vpnctl admin: no such user '<id>'`
/// body. Without the explicit existence-check this would surface as a
/// generic 500 from the inventory's `rows_affected == 0` path.
#[tokio::test]
async fn admin_user_regen_sub_token_404_for_unknown_user() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let body = body_of(
        app,
        "POST",
        "/admin/users/no-such/sub-token/regenerate",
        None,
        None,
    )
    .await;
    assert_eq!(
        body, "vpnctl admin: no such user 'no-such'\n",
        "404 body for missing user drifted from the copy contract"
    );
}

/// On the user-detail page, the rotate-button form must POST to the
/// canonical regenerate URL — keeps the markup in sync with the route
/// after either side is touched independently.
#[tokio::test]
async fn admin_user_detail_renders_rotate_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let app = router(s);

    let html = fetch_html(app, "/admin/users/u0/overview").await;
    assert!(
        html.contains(r#"action="/admin/users/u0/sub-token/regenerate""#),
        "rotate-button form must POST to /admin/users/u0/sub-token/regenerate"
    );
    // Wording contract: the button text is "rotate sub-token" — short,
    // mono, fits the editorial voice. Pinned so a casual UI-rewrite
    // can't accidentally rename it to "Refresh" or "New token".
    assert!(
        html.contains(">rotate sub-token<"),
        "rotate-button label drifted from 'rotate sub-token'"
    );
}

/// After a successful regenerate, GET on /admin/users/u0 renders the
/// NEW token (full token appears EXACTLY ONCE — only inside the
/// canonical sub URL), not the previous one. Validates the
/// "redirect-to-canonical-page" pattern end-to-end.
#[tokio::test]
async fn admin_user_detail_after_regen_shows_new_token() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let before = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    // Trigger regenerate.
    let app = router(s.clone());
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/sub-token/regenerate"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();

    let after = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    let html = fetch_html(app, "/admin/users/u0/overview").await;
    assert!(
        html.contains(&after),
        "detail page must render the NEW sub_token after regenerate"
    );
    assert!(
        !html.contains(&before),
        "detail page must NOT render the previous sub_token after regenerate \
         (would be a stale-token leak)"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase Track-1 — subscription-access section on user-detail
//
//  Pin the UI surface that surfaces abuse signals:
//   * empty state (no fetches yet) shows the "no fetches recorded" copy,
//     never an empty table that looks broken;
//   * with fetches, distinct-IP counters render and the recent table
//     contains the IP / UA / status / bytes columns;
//   * heat flag fires at the documented threshold (5 distinct IPs/24h).
// ────────────────────────────────────────────────────────────────────────

/// Empty state: a freshly-created user with no fetches must show the
/// "Subscription access" eyebrow + the friendly nudge, NOT an empty
/// HTML table that looks like a render error.
#[tokio::test]
async fn admin_user_detail_track1_empty_state_renders_nudge() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let app = router(s);

    let html = fetch_html(app, "/admin/users/u0/activity").await;
    // R2: the v2 4c surface — tiles + geo-log — replaced the legacy
    // Track-1 block; a fresh user shows the no-data verdict tile, not
    // a broken-looking empty table.
    assert!(
        html.contains("Sub-access log"),
        "v2 geo-log eyebrow missing"
    );
    assert!(
        html.contains("no real-client fetches in 30d"),
        "no-data verdict note missing on a fresh user"
    );
    assert!(
        html.contains("sharing verdict"),
        "verdict tile must render from day 1"
    );
}

/// With logged fetches the counters reflect the data, the recent table
/// renders rows newest-first, and the per-row IP / UA / status / bytes
/// land in the right columns.
#[tokio::test]
async fn admin_user_detail_track1_renders_counters_and_recent_table() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;

    // Three fetches from two distinct IPs. UAs differ so the operator
    // could spot a roaming pattern.
    s.inv
        .log_sub_access(
            &UserId("u0".into()),
            "192.0.2.10",
            Some("Hiddify/Android/2.5.0"),
            200,
            1500,
        )
        .await
        .unwrap();
    s.inv
        .log_sub_access(
            &UserId("u0".into()),
            "192.0.2.10",
            Some("Hiddify/Android/2.5.0"),
            200,
            1500,
        )
        .await
        .unwrap();
    s.inv
        .log_sub_access(
            &UserId("u0".into()),
            "198.51.100.42",
            Some("sing-box/1.10.0"),
            200,
            1500,
        )
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/u0/activity").await;

    // Counters reflect the data: 2 distinct IPs in both windows
    // (24h and 7d), 3 recent fetches.
    // The counter values render in big-serif <div>s; literal numbers
    // are present somewhere on the page.
    assert!(html.contains(">2<"), "distinct-IP counter 2 missing");
    assert!(html.contains(">3<"), "recent-fetches counter 3 missing");

    // Recent table holds both IPs.
    assert!(
        html.contains("192.0.2.10") && html.contains("198.51.100.42"),
        "recent table missing one of the logged IPs"
    );
    // UAs land in their column.
    assert!(html.contains("Hiddify/Android/2.5.0"));
    assert!(html.contains("sing-box/1.10.0"));
    // Status code rendered.
    assert!(html.contains(">200<"));
    // Empty-state nudge MUST NOT appear when we have data.
    assert!(
        !html.contains("No subscription fetches recorded yet"),
        "empty-state nudge leaked into populated render"
    );
    // Heat flag must NOT fire under the 5-IP threshold.
    assert!(
        !html.contains("abuse signal"),
        "heat flag fired below threshold ({} distinct IPs)",
        2
    );
}

/// Per-user isolation: alice's fetches must NOT show on bob's detail.
#[tokio::test]
async fn admin_user_detail_track1_does_not_leak_other_users_access() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 2, &[]).await;

    s.inv
        .log_sub_access(
            &UserId("u0".into()),
            "10.10.10.10",
            Some("UA-FOR-U0"),
            200,
            100,
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/u1/activity").await;
    // u1 has no fetches — the v2 verdict tile says so.
    assert!(
        html.contains("no real-client fetches in 30d"),
        "u1 should show the no-data verdict note"
    );
    // u0's row must NOT appear on u1's page.
    assert!(
        !html.contains("10.10.10.10"),
        "leaked u0's IP onto u1's detail page"
    );
    assert!(
        !html.contains("UA-FOR-U0"),
        "leaked u0's UA onto u1's detail page"
    );
}

// ════════════════════════════════════════════════════════════════════
//  ui-audit Phase 2 — user_detail split into 5 sub-route tabs
//  (overview / delivery / access / activity / traffic). Each tab renders
//  ONLY its own sections; bare /admin/users/{id} == overview.
// ════════════════════════════════════════════════════════════════════

/// Each tab route → 200, renders the `.ed-tabs` bar, marks the right tab
/// active, shows a section unique to that tab, and does NOT leak a
/// foreign tab's section. (`Server access` text also appears in a Flow B
/// card on delivery, so the access marker is the `id="server-access"`
/// anchor, which is unique to the access tab.)
#[tokio::test]
async fn user_detail_tabs_render_gate_and_mark_active() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0)]).await; // u0 granted s0
    let app = router(s);
    let cases = [
        (
            "/admin/users/u0/overview",
            "overview",
            "Access state",
            "WireGuard keypair",
        ),
        (
            "/admin/users/u0/delivery",
            "delivery",
            "WireGuard keypair",
            r#"id="server-access""#,
        ),
        (
            "/admin/users/u0/access",
            "access",
            r#"id="server-access""#,
            "WireGuard keypair",
        ),
        (
            "/admin/users/u0/activity",
            "activity",
            "Sub-access log",
            "WireGuard keypair",
        ),
        (
            "/admin/users/u0/traffic",
            "traffic",
            "Live VPN stats",
            "WireGuard keypair",
        ),
    ];
    for (path, slug, present, absent) in cases {
        let html = fetch_html(app.clone(), path).await;
        assert!(
            html.contains(r#"class="ed-tabs""#),
            "{path}: tab bar (.ed-tabs) missing"
        );
        let active = format!(r#"ed-tab--on" href="/admin/users/u0/{slug}""#);
        assert!(
            html.contains(&active),
            "{path}: {slug} tab not marked active"
        );
        assert!(
            html.contains(present),
            "{path}: missing its own section marker {present:?}"
        );
        assert!(
            !html.contains(absent),
            "{path}: leaked a foreign tab's section {absent:?}"
        );
    }
}

/// Bare `/admin/users/{id}` renders the overview tab directly.
#[tokio::test]
async fn user_detail_bare_url_renders_overview_tab() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(
        html.contains(r#"ed-tab--on" href="/admin/users/u0/overview""#),
        "bare URL must mark the overview tab active"
    );
    assert!(
        html.contains("Access state"),
        "bare URL must render the overview tab's sections"
    );
    assert!(
        !html.contains("WireGuard keypair"),
        "bare URL (overview) must not render the delivery tab"
    );
}

/// Copy-contract — pin the 5 user-detail tab labels in both locales.
#[tokio::test]
async fn user_detail_tab_labels_copy_contract() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[]).await;
    let app = router(s);
    let en = fetch_html(app.clone(), "/admin/users/u0").await;
    for label in [
        ">Overview</a>",
        ">Delivery</a>",
        ">Access · 0</a>",
        ">Activity</a>",
        ">Traffic</a>",
    ] {
        assert!(en.contains(label), "EN tab label drifted: {label:?}");
    }
    let ru = fetch_html_with_cookie(app, "/admin/users/u0", "vpnctl_lang=ru").await;
    for label in [
        ">Обзор</a>",
        ">Выдача</a>",
        ">Доступ · 0</a>",
        ">Активность</a>",
        ">Трафик</a>",
    ] {
        assert!(ru.contains(label), "RU tab label drifted: {label:?}");
    }
}

// ────────────────────────────────────────────────────────────────────────
// Phase Track-4 — UA fingerprint section on user-detail.
//
// Backed by `inventory::ua_clusters_for_user`. Three behaviors covered:
//   1. Empty case — the section silently disappears (no headline, no
//      empty-state copy). Operators only see the section when there's
//      something to read; an empty table on a fresh user would just be
//      noise.
//   2. Populated case — one row per distinct UA, with the verdict
//      column rendering "likely shared URL" for /16 spread ≥ 3.
//   3. Roaming verdict — distinct_ips ≥ 3, distinct_slash16 ≤ 1 →
//      "likely roaming". This is the operator's "one device hopping
//      ISPs" tell, opposite of the shared-URL signal.
//
// Per-section copy contract: the headline reads "UA fingerprint · last
// 24h"; the deck contains the word "Heuristic" so the operator knows
// not to treat the verdict as authoritative.

#[tokio::test]
async fn admin_user_detail_track4_ua_section_hidden_when_empty() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(
        !html.contains("UA fingerprint"),
        "UA section must be hidden for users with no /sub fetches"
    );
}

#[tokio::test]
async fn admin_user_detail_track4_ua_section_renders_likely_shared() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    // Same UA hitting from three different /16 networks — classic
    // "subscription URL got shared with friends in different ISPs".
    for ip in ["192.0.2.1", "203.0.113.7", "198.51.100.5"] {
        s.inv
            .log_sub_access(
                &UserId("u0".into()),
                ip,
                Some("Hiddify/Android/2.5.0"),
                200,
                100,
            )
            .await
            .unwrap();
    }

    let html = fetch_html(router(s), "/admin/users/u0/activity").await;

    // Section headline + deck (copy contract).
    assert!(
        html.contains("UA fingerprint"),
        "UA section headline missing"
    );
    assert!(
        html.contains("Heuristic"),
        "UA section deck must caveat the verdict"
    );
    // Verdict label shows up.
    assert!(
        html.contains("likely shared URL"),
        "expected 'likely shared URL' verdict; html (truncated): {}",
        &html[..html.len().min(800)]
    );
    // The UA renders in its column.
    assert!(html.contains("Hiddify/Android/2.5.0"));
    // Counters per row: hits=3, ips=3, /16=3 — they all show as ">3<"
    // somewhere; this just confirms the row data wired through.
    assert!(
        html.matches(">3<").count() >= 3,
        "expected at least 3 columns rendering '3' (hits/ips/slash16); got {}",
        html.matches(">3<").count()
    );
}

#[tokio::test]
async fn admin_user_detail_track4_ua_section_detects_roaming() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    // Three distinct IPs but all in the same /16 — one device whose
    // carrier reassigned its IP a few times.
    for ip in ["192.0.2.10", "192.0.2.11", "192.0.2.12"] {
        s.inv
            .log_sub_access(&UserId("u0".into()), ip, Some("sing-box/1.10.0"), 200, 100)
            .await
            .unwrap();
    }

    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(
        html.contains("likely roaming"),
        "expected 'likely roaming' verdict for 3 IPs in 1 /16; html (truncated): {}",
        &html[..html.len().min(800)]
    );
    // Must NOT misclassify as shared.
    assert!(
        !html.contains("likely shared URL"),
        "roaming pattern should not trip the shared-URL verdict"
    );
}

#[tokio::test]
async fn admin_user_detail_track3_empty_state_quotes_chunk4_status() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let html = fetch_html(router(s), "/admin/users/u0/traffic").await;
    assert!(
        html.contains("Live VPN stats"),
        "section headline must appear even in empty state"
    );
    // Empty-state copy must mention chunk 4 + the SSH key path.
    assert!(
        html.contains("No live stats yet"),
        "empty-state nudge missing"
    );
    // Copy refreshed 2026-06-10: the scheduler is LIVE — empty state
    // now explains why a covered user can still be blank.
    assert!(
        html.contains("every 5 minutes"),
        "empty-state must state the live poller cadence"
    );
    assert!(
        html.contains("/var/lib/vpnctl/.ssh"),
        "empty-state must quote the SSH key path the operator needs to populate"
    );
}

#[tokio::test]
async fn admin_user_detail_track3_renders_kpis_and_per_server_breakdown() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[]).await; // s0, s1, u0

    // Simulate two ticks worth of poller output.
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[
                VpnStatsDelta {
                    user_id: Some(UserId("u0".into())),
                    upload_bytes: 1_000_000,   // 976 KiB
                    download_bytes: 5_000_000, // ~4.77 MiB
                    active_connections: 3,
                },
                // Server-wide row — must NOT appear in user query.
                VpnStatsDelta {
                    user_id: None,
                    upload_bytes: 99_999_999,
                    download_bytes: 99_999_999,
                    active_connections: 99,
                },
            ],
        )
        .await
        .unwrap();
    s.inv
        .record_vpn_stats(
            &ServerId("s1".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 500_000,
                download_bytes: 2_000_000,
                active_connections: 1,
            }],
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/u0/traffic").await;

    // Aggregated totals appear (rendered via humanize_bytes — KiB/MiB).
    // Sum of u0's bytes: up = 1_500_000 (~1.4 MiB), dn = 7_000_000 (~6.7 MiB).
    assert!(html.contains("uploaded"), "uploaded KPI label missing");
    assert!(html.contains("downloaded"), "downloaded KPI label missing");
    assert!(html.contains("peak conns"), "peak conns KPI label missing");
    // Per-server breakdown table must list both servers.
    assert!(html.contains("s0"), "server s0 row missing");
    assert!(html.contains("s1"), "server s1 row missing");
    // Server-wide totals (99,999,999) MUST NOT appear — that row was
    // user_id=NULL and recent_vpn_stats_for_user filters those out.
    assert!(
        !html.contains("99.9 MiB") && !html.contains("99,999,999"),
        "server-wide row must not leak into per-user view"
    );
    // The empty-state nudge must NOT render when there's data.
    assert!(
        !html.contains("No live stats yet"),
        "empty-state copy leaked into populated render"
    );
    // Aggregation footer mentions the snapshot count.
    assert!(
        html.contains("Aggregated from 2 snapshots"),
        "snapshot count footer missing or wrong"
    );
}

#[tokio::test]
async fn admin_user_detail_track3_does_not_leak_other_users_stats() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 2, &[]).await; // s0, u0, u1

    // u0 has stats, u1 has none.
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 1234,
                download_bytes: 5678,
                active_connections: 1,
            }],
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/u1/traffic").await;
    // u1 must show empty state, not u0's bytes.
    assert!(
        html.contains("No live stats yet"),
        "u1 must show empty state when only u0 has data"
    );
}

#[tokio::test]
async fn admin_user_detail_wireguard_section_shows_pubkey_and_rotate_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    // Create via the new auto-gen path.
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=carol"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let pk = inv
        .get_user(&UserId("carol".into()))
        .await
        .unwrap()
        .unwrap()
        .wireguard_pubkey
        .unwrap();

    // Detail page must show that pubkey verbatim + a rotate form.
    let html = fetch_html(app, "/admin/users/carol/delivery").await;
    assert!(html.contains("WireGuard keypair"), "section heading");
    assert!(
        html.contains(pk.as_str()),
        "pubkey must render verbatim — operator wants to see what's deployed"
    );
    assert!(
        html.contains("/admin/users/carol/wireguard/regenerate"),
        "rotate-keypair form must POST to the regenerate route"
    );
    // Private value MUST NOT leak into the HTML — only the marker.
    // maud escapes `<` → `&lt;` in attribute-free text, so check
    // the unambiguous substring before the escape.
    assert!(
        html.contains("✓ stored — served via /sub/"),
        "private must be marker-only ('✓ stored'), never the value itself"
    );
    // Hard assertion: actual private bytes are NEVER in the HTML.
    let priv_ = inv
        .get_user(&UserId("carol".into()))
        .await
        .unwrap()
        .unwrap()
        .wireguard_private
        .unwrap();
    assert!(
        !html.contains(priv_.as_str()),
        "PRIVATE LEAK: detail HTML contains the raw private bytes"
    );
    // Distribution-panel guidance for THREE client personas.
    // Pavel's "Flow A / Flow B / Flow C" pattern: ALWAYS show all
    // three labels even when no WG-enabled server is granted, so the
    // operator knows every option exists + sees why B/C are empty.
    // 2026-05-17: Flow B + Flow C split — pre-split Flow B claimed
    // to cover both AmneziaVPN and the WG app, but AmneziaVPN rejects
    // `wireguard://?conf=` with ErrorCode 900. Honest labels now.
    assert!(
        html.contains("Flow A — Hiddify / Sing-box"),
        "user-detail must teach the sing-box/Hiddify recipient flow"
    );
    assert!(
        html.contains("Flow B — official WireGuard app / Hiddify"),
        "Flow B label must NOT claim AmneziaVPN — that's Flow C now"
    );
    assert!(
        html.contains("Flow C — AmneziaVPN"),
        "user-detail must teach the AmneziaVPN-native recipient flow"
    );
    // No grants → Case A empty state ("grant a server"). Pinned
    // so the no-grant message can't drift into the case-B/C wording.
    assert!(
        html.contains("No servers granted to this user yet"),
        "case A empty-state (no grants) copy missing"
    );
    // 2026-05-17 — Pavel: «Flow A не показывает QR-код, говорит
    // про "above"». Symmetric `share_link_card` is the fix: Flow A
    // now renders its OWN QR + readonly copy textarea. The old
    // "Recipient scans the QR in the Subscription block above"
    // wording must be GONE.
    assert!(
        !html.contains("scans the QR in the"),
        "Flow A must not reference 'above' anymore — it has its own QR"
    );
    // The Flow A card renders the sub URL inside a readonly textarea
    // with the click-to-select-all hook.
    assert!(
        html.contains("Recommended default — one URL covers everything"),
        "Flow A footnote (Recommended default) missing — copy regressed"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Pavel's "main-brat" confusion: user HAS WG keys, granted to a server
// that does NOT declare wireguard → empty-state must say so explicitly
// rather than the misleading "grant a server with WG" wording.

#[tokio::test]
async fn admin_user_detail_wireguard_flow_b_empty_state_case_b_grants_no_wg() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    // Seed: a server that explicitly does NOT run wireguard (mimics
    // vps-is-01 post-bash-import: vless+reality, tuic-v5, hysteria2
    // only).
    inv.add_server(&Server {
        id: ServerId("nowg".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("tuic-v5".into()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();

    // Create user via the auto-gen path → WG keypair populated.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=brat"))
            .unwrap(),
        )
        .await
        .unwrap();
    // Grant to the non-WG server.
    inv.grant(&UserId("brat".into()), &ServerId("nowg".into()))
        .await
        .unwrap();

    let html = fetch_html(app, "/admin/users/brat/delivery").await;
    // The misleading message MUST NOT appear (case A copy).
    assert!(
        !html.contains("No servers granted to this user yet"),
        "case A wording leaked into case B — user IS granted but to a non-WG server"
    );
    // The actually-correct case-B explanation MUST be present.
    assert!(
        html.contains("Keys exist, but no granted server runs WireGuard"),
        "case B headline missing — operator won't understand why no QR"
    );
    // The granted server's id must be name-dropped so the operator
    // knows WHICH server needs the protocol added.
    assert!(
        html.contains("nowg"),
        "case B body must name the actually-granted servers"
    );
    // No WG-capable server in inventory either → tail message points
    // at the web workaround (operator-action policy: no CLI in copy).
    assert!(
        html.contains("Settings page"),
        "case B must point at the server's Settings page when inventory has zero WG-capable nodes"
    );
    assert!(
        !html.contains("vpnctl server add"),
        "case B must not instruct a CLI command"
    );
}

#[tokio::test]
async fn admin_user_detail_wireguard_flow_b_namedrops_other_wg_servers() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    // Two servers: one without WG (granted), one WITH WG (not granted).
    // Case-B copy should point at the second as a suggestion.
    inv.add_server(&Server {
        id: ServerId("nowg".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.add_server(&Server {
        id: ServerId("wg-de-01".into()),
        address: "198.51.100.5".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("amneziawg".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=brat"))
            .unwrap(),
        )
        .await
        .unwrap();
    inv.grant(&UserId("brat".into()), &ServerId("nowg".into()))
        .await
        .unwrap();

    let html = fetch_html(app, "/admin/users/brat/delivery").await;
    assert!(
        html.contains("WG-capable servers in the inventory you could grant"),
        "suggestion line missing"
    );
    assert!(
        html.contains("wg-de-01"),
        "the WG-capable server id must be name-dropped: {html:.300}"
    );
}

#[tokio::test]
async fn admin_user_regen_wireguard_rotates_pair_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    // Seed via creation.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=dave"))
            .unwrap(),
        )
        .await
        .unwrap();
    inv.add_server(&Server {
        id: ServerId("wg-regen-node".into()),
        address: "203.0.113.41".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.grant(&UserId("dave".into()), &ServerId("wg-regen-node".into()))
        .await
        .unwrap();
    inv.audit("admin", "server.deploy", Some("wg-regen-node"), None)
        .await
        .unwrap();
    let before = inv.get_user(&UserId("dave".into())).await.unwrap().unwrap();

    // Rotate.
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/dave/wireguard/regenerate"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let after = inv.get_user(&UserId("dave".into())).await.unwrap().unwrap();
    assert_ne!(
        before.wireguard_pubkey, after.wireguard_pubkey,
        "pubkey must change on rotate"
    );
    assert_ne!(
        before.wireguard_private, after.wireguard_private,
        "private must change on rotate"
    );
    // Audit row exists with the new pubkey + provenance marker.
    let audit = inv.recent_audit(5).await.unwrap();
    let row = audit
        .iter()
        .find(|a| a.action == "user.wireguard.regen")
        .expect("audit row for wireguard.regen");
    let payload = row
        .payload
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_default();
    assert!(payload.contains("server-generated"));
    assert!(payload.contains(after.wireguard_pubkey.as_deref().unwrap()));
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    assert!(rows.iter().any(|row| {
        row.target.as_deref() == Some("dave")
            && row
                .payload
                .as_ref()
                .and_then(|p| p.get("trigger"))
                .and_then(|v| v.as_str())
                == Some("user.wireguard.regen")
    }));
    assert_eq!(
        inv.servers_pending_deploy_for_user(
            &UserId("dave".into()),
            &[ServerId("wg-regen-node".into())],
        )
        .await
        .unwrap(),
        vec![ServerId("wg-regen-node".into())],
        "failed auto-deploy must leave the regenerated key pending",
    );
}

// ─── Pavel iter D.6c: traffic limit + alert UI ──────────────────────────

#[tokio::test]
async fn admin_user_detail_shows_traffic_limit_section() {
    use vpnctl_core::{User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "uuid-a".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/users/alice/overview").await;
    // Section heading + the form's action URL + default threshold.
    assert!(html.contains("Traffic limit"), "section heading missing");
    assert!(
        html.contains(r#"action="/admin/users/alice/traffic-limit""#),
        "form action missing"
    );
    assert!(
        html.contains(r#"name="limit_gib""#),
        "limit_gib input missing"
    );
    assert!(
        html.contains(r#"name="threshold_pct""#),
        "threshold_pct input missing"
    );
}

#[tokio::test]
async fn admin_user_set_traffic_limit_persists_and_audits() {
    use vpnctl_core::{User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "uuid-a".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/alice/traffic-limit")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("limit_gib=5.0&threshold_pct=75"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let (lim, thr) = inv
        .get_user_traffic_limit(&UserId("alice".into()))
        .await
        .unwrap();
    // 5 GiB = 5 * 1_073_741_824 = 5_368_709_120 bytes
    assert_eq!(lim, Some(5_368_709_120));
    assert_eq!(thr, Some(75));
    // Audit row with the new payload.
    let audit = inv.recent_audit(5).await.unwrap();
    let row = audit
        .iter()
        .find(|a| a.action == "user.traffic_limit.set")
        .expect("audit row");
    let payload = row
        .payload
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_default();
    assert!(payload.contains("75"));
    assert!(payload.contains("5368709120"));
}

#[tokio::test]
async fn admin_user_set_traffic_limit_zero_clears_cap() {
    use vpnctl_core::{User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "uuid-a".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // Pre-state: cap of 10 GiB.
    inv.set_user_traffic_limit(&UserId("alice".into()), Some(10_737_418_240), Some(80))
        .await
        .unwrap();
    // POST with limit_gib=0 → cap cleared.
    let app = router(s);
    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/users/alice/traffic-limit")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from("limit_gib=0&threshold_pct=80"))
        .unwrap(),
    )
    .await
    .unwrap();
    let (lim, _) = inv
        .get_user_traffic_limit(&UserId("alice".into()))
        .await
        .unwrap();
    assert!(lim.is_none(), "limit must be NULL after limit_gib=0");
}

// ────────────────────────────────────────────────────────────────────────
// 2026-05-17 UX fixes from Pavel's review of user-detail + server-detail:
//   * Flow A + Flow B must use the SAME `share_link_card` DOM shape
//     (QR + readonly textarea + footnote). No more "above" reference.
//   * Flow B's QR card must include a click-to-select-all textarea
//     with the FULL wireguard:// link (so the operator can copy it).
//   * deploy → button caption must spell out the full SSH push effect
//     (ensure_installed + apply_config + restart), not just secrets.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_user_detail_flow_a_card_uses_share_link_card_with_copy_textarea() {
    // Need: a user with a sub_token AND wireguard keypair so the
    // distribution panel renders (Flow A + Flow B both visible).
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();

    // Seed a WG-capable server so Flow B is populated too.
    inv.add_server(&Server {
        id: ServerId("wg1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    // Server-side WG keypair so the share_link can render.
    inv.set_server_secret(
        &ServerId("wg1".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wg1".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("flowtest".into()),
        uuid: "11111111-1111-1111-1111-111111111111".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".into()),
        wireguard_private: Some("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=".into()),
        sub_token: Some("subtok-flowtest-abc123".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("flowtest".into()), &ServerId("wg1".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/flowtest/delivery").await;

    // Flow A card MUST carry the click-to-select marker that admin.js
    // wires up (the old inline `onclick` was CSP-dead — polish pass
    // 2026-07-10 moved it to a data-attribute + delegated listener).
    assert!(
        html.contains("data-select-on-click"),
        "share_link_card textarea must carry data-select-on-click for the admin.js wiring"
    );
    assert!(
        !html.contains("onclick="),
        "no inline event handlers — the CSP refuses them silently"
    );
    // The sub URL goes inside a <textarea readonly>. The user-detail
    // page renders the sub-token TWICE: once in the Subscription
    // block at the top (as plain text), once inside the Flow A
    // card's textarea below. We want to assert the SECOND occurrence
    // is the one wrapped in a textarea — use `rfind` to walk back
    // from the last occurrence.
    //
    // This catches a regression where Flow A loses its textarea
    // but Flow B still has 2+ (operator with multiple WG grants
    // would push the count() ≥ 2 assertion through even with Flow
    // A broken).
    let token_substr = "/sub/subtok-flowtest-abc123";
    let token_at = html
        .rfind(token_substr)
        .unwrap_or_else(|| panic!("sub-token substring missing from page: {token_substr}"));
    // Walk back up to 800 chars and confirm a `<textarea` tag
    // opens before the token — proves the LAST occurrence (i.e.
    // the Flow A card) lives INSIDE a textarea. The window is
    // wide enough to clear the textarea's inline style string
    // (~500 chars).
    let window_start = token_at.saturating_sub(800);
    let before = &html[window_start..token_at];
    assert!(
        before.contains("<textarea readonly"),
        "Flow A sub-token must appear inside a `<textarea readonly>` block — got window before token: {before:?}"
    );
    // Flow A footnote stays.
    assert!(
        html.contains("Sing-box / Hiddify pulls the full config"),
        "Flow A footnote regressed"
    );
}

#[tokio::test]
async fn admin_user_detail_flow_b_card_includes_full_wireguard_link_in_textarea() {
    // Same seeding as the previous test — we want the FULL
    // wireguard:// link to appear inside a readonly textarea, not
    // just the masked preview.
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("wg2".into()),
        address: "203.0.113.8".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wg2".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wg2".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("flowtest2".into()),
        uuid: "22222222-2222-2222-2222-222222222222".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".into()),
        wireguard_private: Some("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=".into()),
        sub_token: Some("subtok-flowtest2".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("flowtest2".into()), &ServerId("wg2".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/flowtest2/delivery").await;

    // The wireguard:// link must appear in full inside the page —
    // this is the operator's only way to copy the conf to AmneziaVPN.
    // Don't check the exact URL (build-host dependent) — assert that
    // the scheme prefix shows up inside a textarea tag.
    assert!(
        html.contains("wireguard://"),
        "Flow B must include the wireguard:// link verbatim somewhere on the page"
    );
    // The new copy-hint text in the Flow B footnote.
    assert!(
        html.contains("Click the box above to select-all + copy"),
        "Flow B footnote must teach the click-to-copy interaction"
    );
}

// ────────────────────────────────────────────────────────────────────────
// 2026-05-17 — AmneziaVPN-native Flow C + universal .conf download.
//
// Pre-2026-05-17 the user-detail page claimed `wireguard://?conf=...`
// worked in AmneziaVPN. Pavel hit ErrorCode 900 («нет контейнеров»):
// AmneziaVPN actually wants `vpn://<base64url(qCompress(json))>`,
// a different URI scheme entirely. Fix is a NEW Flow C card that
// emits that link, plus a `.conf` download as a universal fallback.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_user_detail_flow_c_card_emits_vpn_scheme_link() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("amzwg".into()),
        address: "203.0.113.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("amzwg".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("amzwg".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("amztest".into()),
        uuid: "44444444-4444-4444-4444-444444444444".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-amztest".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("amztest".into()), &ServerId("amzwg".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/amztest/delivery").await;

    // Flow C label is present even when empty; with a granted WG
    // server + secrets it now has a real vpn:// link.
    assert!(
        html.contains("Flow C — AmneziaVPN"),
        "Flow C label missing on user-detail"
    );
    assert!(
        html.contains("vpn://"),
        "Flow C card must include a `vpn://<...>` link for AmneziaVPN"
    );
    // The Flow C link must be inside a textarea like Flow B.
    let vpn_at = html.find("vpn://").expect("vpn:// substring missing");
    let window_start = vpn_at.saturating_sub(800);
    let before = &html[window_start..vpn_at];
    assert!(
        before.contains("<textarea readonly"),
        "Flow C vpn:// link must appear inside a `<textarea readonly>` block"
    );
}

/// Flow F — AmneziaWG `awg://` card for the operator's sing-box-lx app.
/// Renders only for a granted server running the `amneziawg` kernel
/// (obfs minted), and the link carries the per-server obfs (with s3=s4=0
/// since vpnctl serves AWG 1.x) + the server-generated client key.
#[tokio::test]
async fn admin_user_detail_flow_f_card_emits_awg_scheme_link() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("awgnode".into()),
        address: "203.0.113.11".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("amneziawg".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    for (k, v) in [
        (
            "wireguard.server_public_key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        (
            "wireguard.server_private_key",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        ),
        ("amneziawg.jc", "7"),
        ("amneziawg.jmin", "60"),
        ("amneziawg.jmax", "140"),
        ("amneziawg.s1", "30"),
        ("amneziawg.s2", "90"),
        ("amneziawg.h1", "1111111111"),
        ("amneziawg.h2", "2022222222"),
        ("amneziawg.h3", "333333333"),
        ("amneziawg.h4", "444444444"),
    ] {
        inv.set_server_secret(&ServerId("awgnode".into()), k, v)
            .await
            .unwrap();
    }
    inv.add_user(&User {
        id: UserId("awgtest".into()),
        uuid: "55555555-5555-5555-5555-555555555555".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-awgtest".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("awgtest".into()), &ServerId("awgnode".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/awgtest/delivery").await;
    // Dash-agnostic label match (the card eyebrow is "Flow F — AmneziaWG
    // (awg://)" with an em-dash).
    assert!(
        html.contains("AmneziaWG (awg://)"),
        "Flow F AmneziaWG card label missing"
    );
    assert!(
        html.contains("awg://"),
        "Flow F card must include an awg:// link"
    );
    // The link carries the per-server obfs (substrings survive maud's
    // `&` → `&amp;` query escaping) + the always-zero s3/s4 (1.x server).
    // Use rfind: the FIRST "awg://" is the label «(awg://)»; the actual
    // link is in the textarea after the QR.
    let at = html.rfind("awg://").expect("awg:// link missing");
    let win = &html[at..(at + 700).min(html.len())];
    assert!(
        win.contains("jc=7") && win.contains("s1=30") && win.contains("h1=1111111111"),
        "obfs params missing in awg:// link: {win}"
    );
    assert!(
        win.contains("s3=0") && win.contains("s4=0"),
        "s3/s4 must be 0 (vpnctl serves AWG 1.x): {win}"
    );
}

/// A WG server on the sing-box kernel (no amneziawg obfs minted) must
/// NOT show Flow F — the awg:// link is meaningless without obfs.
#[tokio::test]
async fn admin_user_detail_no_flow_f_without_amneziawg_obfs() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("sbwg".into()),
        address: "203.0.113.12".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    // server keys but NO amneziawg.* obfs.
    inv.set_server_secret(
        &ServerId("sbwg".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("sbwguser".into()),
        uuid: "66666666-6666-6666-6666-666666666666".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-sbwg".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("sbwguser".into()), &ServerId("sbwg".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/sbwguser/delivery").await;
    assert!(
        !html.contains("AmneziaWG (awg://)"),
        "Flow F must not render without minted AmneziaWG obfs"
    );
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_serves_attachment() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("dlsrv".into()),
        address: "203.0.113.11".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("dlsrv".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("dlsrv".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("dltest".into()),
        uuid: "55555555-5555-5555-5555-555555555555".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-dltest".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("dltest".into()), &ServerId("dlsrv".into()))
        .await
        .unwrap();

    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/dltest/wireguard/conf/dlsrv")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cd = resp
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cd.contains("attachment") && cd.contains("dltest-dlsrv.conf"),
        "Content-Disposition must declare attachment with the <user>-<server>.conf filename, got {cd:?}"
    );
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/plain"),
        "Content-Type should be text/plain for .conf, got {ct:?}"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("[Interface]"),
        ".conf must contain [Interface]"
    );
    assert!(text.contains("[Peer]"), ".conf must contain [Peer]");
    assert!(
        text.contains("Endpoint = 203.0.113.11:51820"),
        ".conf must reference the right server endpoint"
    );
    // Private bytes MUST be inlined in the .conf so the operator's
    // recipient can import without a second action.
    assert!(
        text.contains("PrivateKey = 0000000000000000000000000000000000000000000="),
        ".conf must inline the user's private key (server-generated default)"
    );
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_404_on_unknown_user() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/nope/wireguard/conf/whatever")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_404_on_unknown_server_when_user_exists() {
    use vpnctl_core::{User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("u".into()),
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            tuic_password: None,
            wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
            wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
            sub_token: Some("st".into()),
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/u/wireguard/conf/nosuch")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("no such server 'nosuch'"),
        "expected canonical 'no such server' body, got {text:?}"
    );
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_refuses_when_user_not_granted_server() {
    // Both user and server exist; server has wireguard enabled; but
    // there's NO grant linking them. The endpoint must 404, not leak
    // the .conf — otherwise a stale browser tab keeps working past
    // a revoke (review-agent 2026-05-17).
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("ungranted-srv".into()),
        address: "203.0.113.200".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("ungranted-srv".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("ungranted-user".into()),
        uuid: "88888888-8888-8888-8888-888888888888".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    // NB: NO grant.

    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/ungranted-user/wireguard/conf/ungranted-srv")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "ungranted (user, server) pair must 404, not serve the .conf"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("not granted on server"),
        "expected canonical 'not granted' body, got {text:?}"
    );
}

#[tokio::test]
async fn admin_user_wg_conf_peer_octet_differs_per_user_index() {
    // Two users granted to the same WG server. Their .conf files
    // must claim different /32 addresses (10.66.0.2 + 10.66.0.3).
    // Pre-fix both claimed 10.66.0.2 — review-agent 2026-05-17.
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("multi".into()),
        address: "203.0.113.150".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("multi".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    // Two users — `alex` < `bob` by lex sort (matches the
    // inv.users_for_server ORDER BY id).
    for (uid, uuid, pubk) in [
        (
            "alex",
            "11111111-1111-1111-1111-111111111111",
            "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=",
        ),
        (
            "bob",
            "22222222-2222-2222-2222-222222222222",
            "AbcDefGhIjKlMnOpQrStUvWxYz0123456789AbCdEf=",
        ),
    ] {
        inv.add_user(&User {
            id: UserId(uid.into()),
            uuid: uuid.into(),
            tuic_password: None,
            wireguard_pubkey: Some(pubk.into()),
            wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
            sub_token: Some(format!("st-{uid}")),
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        inv.grant(&UserId(uid.into()), &ServerId("multi".into()))
            .await
            .unwrap();
    }

    let app = router(s);
    let alex_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users/alex/wireguard/conf/multi")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bob_resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/bob/wireguard/conf/multi")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(alex_resp.status(), StatusCode::OK);
    assert_eq!(bob_resp.status(), StatusCode::OK);
    let alex_conf = std::str::from_utf8(&alex_resp.into_body().collect().await.unwrap().to_bytes())
        .unwrap()
        .to_string();
    let bob_conf = std::str::from_utf8(&bob_resp.into_body().collect().await.unwrap().to_bytes())
        .unwrap()
        .to_string();
    assert!(
        alex_conf.contains("Address = 10.66.0.2/32"),
        "alex (index 0) must claim 10.66.0.2; got: {alex_conf}"
    );
    assert!(
        bob_conf.contains("Address = 10.66.0.3/32"),
        "bob (index 1) must claim 10.66.0.3 (NOT 10.66.0.2 — that's the regression); got: {bob_conf}"
    );
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_400_when_server_lacks_wg_protocol() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    // Server that doesn't declare wireguard.
    inv.add_server(&Server {
        id: ServerId("nowg2".into()),
        address: "203.0.113.99".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("u1".into()),
        uuid: "66666666-6666-6666-6666-666666666666".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-u1".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/u1/wireguard/conf/nowg2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("does not enable the 'wireguard' protocol"),
        "expected the canonical 'wireguard protocol not enabled' message, got {text:?}"
    );
}

#[tokio::test]
async fn admin_user_detail_flow_b_links_to_conf_download() {
    // Operator should see a `.conf` link next to each Flow B server
    // (universal fallback that imports into AmneziaVPN via its
    // "File with settings" picker even if the user can't paste
    // the vpn:// link directly).
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("wgX".into()),
        address: "203.0.113.55".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wgX".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("wgX".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("conftest".into()),
        uuid: "77777777-7777-7777-7777-777777777777".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-conf".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("conftest".into()), &ServerId("wgX".into()))
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/users/conftest/delivery").await;
    assert!(
        html.contains("/admin/users/conftest/wireguard/conf/wgX"),
        "Flow B server header must link to the .conf download endpoint"
    );
    assert!(
        html.contains("download=\"conftest-wgX.conf\""),
        "anchor must set the download filename to <user>-<server>.conf"
    );
}

#[tokio::test]
async fn tooltips_user_detail_traffic_limit_fields_explain_units() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("tip".into()),
            uuid: "00000000-0000-0000-0000-000000000020".to_string(),
            sub_token: Some("ttip".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/tip/overview").await;
    assert!(
        html.contains("Monthly cap in GiB"),
        "limit_gib input must explain unit + 0=no cap semantic"
    );
    assert!(
        html.contains("Fire a dashboard alert"),
        "threshold_pct input must explain alert semantic"
    );
}

#[tokio::test]
async fn track_1_2_geo_log_renders_country_and_asn() {
    // Pin that the migration-0019 chips render on the
    // /admin/users/{id} Subscription-access table when columns
    // are present. Without this assertion, a maud template
    // refactor that drops the chip rendering would silently
    // ship without breaking a test.
    use vpnctl_core::{User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&User {
        id: UserId("zoidberg".into()),
        uuid: "z0".into(),
        sub_token: Some("ztok".into()),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();

    // Use log_sub_access_rich directly so we can populate the new
    // metadata columns without a real HTTP roundtrip (the writer
    // task path is exercised live, not in this smoke).
    inv.log_sub_access_rich(
        &UserId("zoidberg".into()),
        "8.8.8.8",
        Some("Hiddify/Android/2.5.0"),
        200,
        4096,
        Some("ru-RU,ru;q=0.9"),
        Some("HTTP/2.0"),
        Some("Hiddify"),
        Some("US"),
        Some("AS15169 GOOGLE"),
        None,
        None,
    )
    .await
    .unwrap();

    let html = fetch_html(router(s), "/admin/users/zoidberg/activity").await;
    assert!(html.contains("8.8.8.8"), "raw IP must render");
    assert!(
        html.contains(">US<"),
        "geo_country chip 'US' must render alongside the IP"
    );
    assert!(
        html.contains("AS15169 GOOGLE"),
        "geo_asn chip 'AS15169 GOOGLE' must render"
    );
    // R2: the v2 geo-log has no http-version / device-class columns —
    // that metadata lives in the origins fingerprint line + the CSV
    // export. The UA column carries the raw string.
    assert!(
        html.contains("Hiddify/Android/2.5.0"),
        "raw UA must render in the UA column"
    );
}

#[tokio::test]
async fn track_1_2_subscription_access_legacy_row_renders_bare_ip() {
    // Symmetric: a row from BEFORE migration 0019 (no new metadata)
    // renders the IP without exploding and without spurious empty
    // chips.
    use vpnctl_core::{User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&User {
        id: UserId("nibbler".into()),
        uuid: "n0".into(),
        sub_token: Some("ntok".into()),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.log_sub_access(&UserId("nibbler".into()), "1.2.3.4", None, 200, 0)
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/nibbler/activity").await;
    assert!(html.contains("1.2.3.4"), "raw IP must render");
    // No geo_country / geo_asn chips since both are NULL — render
    // must NOT emit empty `>` `<` placeholders.
    assert!(
        !html.contains(r#"border: 1px solid var(--acc-good, #2c5f2d); color: var(--acc-good, #2c5f2d); margin-left: 2px;" title="Country"#),
        "no country chip when geo_country is None — currently no such substring"
    );
}

#[tokio::test]
async fn track_1_4_subscription_access_omits_ja_chips_when_null() {
    // Symmetric: rows with NULL tls_ja3 + tls_ja4 (default today;
    // nginx-side module not installed) render WITHOUT the JA chips.
    use vpnctl_core::{User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&User {
        id: UserId("bender".into()),
        uuid: "be0".into(),
        sub_token: Some("betok".into()),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.log_sub_access(&UserId("bender".into()), "1.2.3.4", None, 200, 0)
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/bender/activity").await;
    assert!(
        !html.contains("JA3 ") && !html.contains("JA4 "),
        "JA chips must not render when columns are NULL"
    );
}

#[tokio::test]
async fn user_detail_mint_tuic_button_shows_when_absent_and_mints_on_post() {
    // A user without tuic_password silently loses naive/HY2/TUIC links
    // (cdn 2026-06-07). The user-detail page must surface a one-click
    // mint when absent, hide it when present, and the POST must mint +
    // audit. Regression guard for the durable fix.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_user(&User {
            id: UserId("notuic".into()),
            uuid: "00000000-0000-0000-0000-0000000000aa".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(st.clone());

    // Missing → page shows the mint form + button.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users/notuic")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains(r#"action="/admin/users/notuic/tuic-password/mint""#),
        "missing-tuic user must show the mint form"
    );
    assert!(
        html.contains("mint tuic password"),
        "mint button label must render"
    );

    // POST mints it → 303, password now present, audit row written.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/notuic/tuic-password/mint")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let u = st
        .inv
        .get_user(&UserId("notuic".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        u.tuic_password.as_deref().is_some_and(|p| !p.is_empty()),
        "tuic_password must be minted after POST"
    );
    let audit = st.inv.recent_audit(20).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|e| e.action == "user.mint_tuic_password" && e.target.as_deref() == Some("notuic")),
        "audit row user.mint_tuic_password required"
    );

    // A user WITH a tuic_password must NOT show the mint form.
    st.inv
        .add_user(&User {
            id: UserId("hastuic".into()),
            uuid: "00000000-0000-0000-0000-0000000000bb".into(),
            tuic_password: Some("already-set-pw".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users/hastuic")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("/admin/users/hastuic/tuic-password/mint"),
        "user WITH tuic_password must NOT show the mint form"
    );

    // Idempotent no-op: POST mint on a user that already HAS a password
    // must NOT rotate it and must NOT write an audit row (NM-10
    // audit-on-actual-mutation contract).
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/hastuic/tuic-password/mint")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let h = st
        .inv
        .get_user(&UserId("hastuic".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        h.tuic_password.as_deref(),
        Some("already-set-pw"),
        "no-op mint must NOT rotate an existing password"
    );
    let n = st
        .inv
        .recent_audit(50)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.action == "user.mint_tuic_password" && e.target.as_deref() == Some("hastuic"))
        .count();
    assert_eq!(n, 0, "no-op mint must NOT write an audit row");
}

#[tokio::test]
async fn user_detail_page_shows_amber_banner_when_disabled() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_user(&User {
            id: UserId("paused".into()),
            uuid: "00000000-0000-0000-0000-000000000062".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: true,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/paused")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("user is DISABLED") || html.contains("пользователь ОТКЛЮЧЁН"),
        "amber banner must announce disabled state on user-detail"
    );
    // Must show the enable button (the inverse action), NOT the disable one.
    assert!(
        html.contains(r#"action="/admin/users/paused/enable""#),
        "must offer enable button for a disabled user"
    );
    assert!(
        !html.contains(r#"action="/admin/users/paused/disable""#),
        "must NOT also show disable button (already disabled)"
    );
}

/// abuse-origins — empty-state: a user with no external (non-egress)
/// fetches still renders the "Subscription origins" eyebrow + the
/// no-data copy, never a bare rule.
#[tokio::test]
async fn admin_user_detail_origins_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(
        html.contains(r#"id="origins""#),
        "origins anchor must always render"
    );
    assert!(
        html.contains("Subscription origins"),
        "origins eyebrow must render even when empty"
    );
    assert!(
        html.contains("No external subscription fetches recorded"),
        "origins empty-state copy missing"
    );
}

/// abuse-origins — a multi-ASN / multi-country / multi-IP pattern for a
/// user renders all three breakdown tables with the seeded values, the
/// device-count line, and the per-table sub-eyebrows.
#[tokio::test]
async fn admin_user_detail_origins_renders_country_isp_ip_breakdown() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    // Three countries, three ISPs, three IPs, two device classes.
    let rows = [
        (
            "203.0.113.10",
            "US",
            "AS8359 MTS PJSC",
            "Hiddify",
            "Hiddify/1",
        ),
        ("198.51.100.20", "DE", "AS3320 DTAG", "v2rayNG", "v2rayNG/2"),
        (
            "192.0.2.30",
            "RU",
            "AS12389 Rostelecom",
            "Hiddify",
            "Hiddify/3",
        ),
    ];
    for (ip, cc, asn, dev, ua) in rows {
        s.inv
            .log_sub_access_rich(
                &UserId("u0".into()),
                ip,
                Some(ua),
                200,
                512,
                None,
                Some("HTTP/2"),
                Some(dev),
                Some(cc),
                Some(asn),
                None,
                None,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;

    // Section + per-table sub-eyebrows.
    assert!(
        html.contains("Subscription origins"),
        "section eyebrow missing"
    );
    assert!(
        html.contains("By country"),
        "by-country sub-eyebrow missing"
    );
    assert!(html.contains("By ISP"), "by-ISP sub-eyebrow missing");
    assert!(html.contains("By IP"), "by-IP sub-eyebrow missing");

    // Country codes show in the by-country table.
    for cc in ["US", "DE", "RU"] {
        assert!(
            html.contains(cc),
            "country {cc} missing from origins breakdown"
        );
    }
    // ISP labels render verbatim (the descriptive geo_asn string).
    assert!(
        html.contains("AS8359 MTS PJSC"),
        "ISP label must render in the by-ISP table"
    );
    // Each IP renders in the by-IP table.
    for ip in ["203.0.113.10", "198.51.100.20", "192.0.2.30"] {
        assert!(html.contains(ip), "IP {ip} missing from by-IP table");
    }
    // Device-count line (TT-5): two distinct device_classes present →
    // leads with «client families» + a raw-UA breakout (was the
    // false-precision «≈N devices» + a dead «0 TLS-fingerprints» term).
    assert!(
        html.contains("client families"),
        "device-count line must lead with 'client families' when device_class is populated"
    );
    assert!(
        !html.contains("TLS-fingerprints") && !html.contains("0 TLS"),
        "dead JA4/TLS-fingerprint term must be gone from the device line"
    );
    // No empty-state when rows are present.
    assert!(
        !html.contains("No external subscription fetches recorded"),
        "empty-state must NOT render when origin rows exist"
    );
}

/// abuse-origins — egress-only history yields the empty-state (egress
/// rows are excluded from every breakdown).
#[tokio::test]
async fn admin_user_detail_origins_empty_state_when_only_egress() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // s0's address is 10.0.0.0 (see `seed`); a fetch from that IP is
    // flagged is_vpn_egress by the migration-0021 trigger.
    s.inv
        .log_sub_access_rich(
            &UserId("u0".into()),
            "10.0.0.0",
            Some("Hiddify/1"),
            200,
            512,
            None,
            None,
            Some("Hiddify"),
            Some("DE"),
            Some("AS1 Egress"),
            None,
            None,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(
        html.contains("No external subscription fetches recorded"),
        "egress-only history must render the origins empty-state"
    );
}

/// user#1 — with a snapshot seeded into the AppState's snapshot_cache
/// that attributes a live connection to the user, the presence badge
/// flips to the 🟢-online branch and names the server.
#[tokio::test]
async fn pr_user_online_badge_green_when_snapshot_attributes_connection() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // s0, u0, granted

    // Seed a snapshot on s0 with one connection attributed to u0 via
    // metadata.user (the patched sing-box clash-api), which the online
    // badge reads directly.
    let mut conn = pr_user_conn("9.9.9.9", "40000");
    conn.metadata.user = Some("u0".into());
    let snap = vpnctld::clash_api::Snapshot {
        upload_total: conn.upload,
        download_total: conn.download,
        connections: vec![conn],
    };
    s.snapshot_cache.store(ServerId("s0".into()), snap);

    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(html.contains("Presence"), "presence eyebrow missing");
    assert!(
        html.contains(r#"class="ed-stat ed-stat--active""#),
        "online badge must use the active status marker"
    );
    assert!(html.contains("online"), "online badge must read 'online'");
    // The server the connection landed on is named.
    assert!(html.contains("s0"), "online badge must name the server");
    assert!(
        !html.contains("offline"),
        "must not show 'offline' when online"
    );
}

/// user#1 — with NO snapshot in the cache the badge degrades to the
/// offline branch. No panic on an empty cache.
#[tokio::test]
async fn pr_user_online_badge_offline_when_no_snapshot() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // No snapshot stored — cache is empty.
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(html.contains("Presence"), "presence eyebrow missing");
    assert!(
        html.contains("offline"),
        "badge must read 'offline' with an empty snapshot cache"
    );
    // Never connected (no sub-access history) → explicit copy.
    assert!(
        html.contains("never connected"),
        "offline badge must say 'never connected' for a user with no history"
    );
    assert!(
        !html.contains("🟢"),
        "must not show the green dot when offline"
    );
}

/// user#2 — populated: a per-user VPN tick lands a per-server row.
#[tokio::test]
async fn pr_user_traffic_by_server_renders_per_server_rows() {
    use vpnctl_inventory::VpnStatsDelta;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 3_000_000,
                download_bytes: 9_000_000,
                active_connections: 2,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0/traffic").await;
    // R2: the fixed-24h duplicate table was removed — the window-driven
    // live-stats table (now carrying a «total» column) is the one
    // per-server surface on this tab.
    assert!(
        html.contains("Live VPN stats"),
        "live-stats eyebrow missing"
    );
    assert!(html.contains("peak conns"), "peak-conns column missing");
    assert!(html.contains("total"), "total column missing (R2)");
    // s0 row present with humanized totals.
    assert!(html.contains("s0"), "per-server row for s0 missing");
    assert!(
        html.contains("11.4 MiB"),
        "total column must humanize up+down (3 MB + 9 MB)"
    );
}

/// user#3 — with a monthly cap set + month-to-date usage, the section
/// renders the progress bar copy AND the month-end projection.
#[tokio::test]
async fn pr_user_quota_renders_progress_and_projection_with_limit() {
    use vpnctl_inventory::VpnStatsDelta;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // 5 GiB cap.
    s.inv
        .set_user_traffic_limit(&UserId("u0".into()), Some(5_368_709_120), Some(80))
        .await
        .unwrap();
    // Some month-to-date usage so the projection is non-zero.
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 500_000_000,
                download_bytes: 500_000_000,
                active_connections: 1,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(
        html.contains("Traffic limit"),
        "traffic-limit eyebrow missing"
    );
    // Progress copy from fmt_traffic_progress: "X / Y (Z%)".
    assert!(
        html.contains("5 GiB") || html.contains("5.0 GiB"),
        "progress bar must show the configured cap"
    );
    // Projection line.
    assert!(
        html.contains("projected"),
        "month-end projection line missing when a cap is set"
    );
    assert!(
        html.contains("by month-end"),
        "projection copy contract drifted"
    );
}

/// user#3 — with NO cap set, the section shows just the usage + form,
/// and NO projection line (projection is only meaningful with a cap).
#[tokio::test]
async fn pr_user_quota_no_limit_shows_form_no_projection() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(
        html.contains("Traffic limit"),
        "traffic-limit eyebrow missing"
    );
    // The form is still present.
    assert!(
        html.contains(r#"name="limit_gib""#),
        "limit form must still render with no cap"
    );
    // No projection line without a cap.
    assert!(
        !html.contains("by month-end"),
        "projection must not render when no cap is set"
    );
}

/// user#4 — a high-ASN-spread access pattern flips the sharing verdict
/// to "likely shared".
#[tokio::test]
async fn pr_user_sharing_verdict_flags_likely_shared_on_asn_spread() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // Three fetches, each from a distinct ASN + country + /16 — the
    // classic "subscription URL got shared across ISPs" pattern. The
    // enrichment columns are set directly via the richer logger.
    for (ip, cc, asn) in [
        ("192.0.2.1", "US", "AS111 Alpha"),
        ("203.0.113.7", "DE", "AS222 Beta"),
        ("198.51.100.5", "FR", "AS333 Gamma"),
    ] {
        s.inv
            .log_sub_access_rich(
                &UserId("u0".into()),
                ip,
                Some("Hiddify/Android/2.5.0"),
                200,
                100,
                None,
                None,
                None,
                Some(cc),
                Some(asn),
                None,
                None,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(
        html.contains("Sharing verdict"),
        "sharing-verdict eyebrow missing"
    );
    assert!(
        html.contains("likely shared"),
        "high-ASN-spread access must produce 'likely shared' verdict"
    );
    // The verdict line names the distinct counts.
    assert!(html.contains("ASNs"), "verdict must report the ASN count");
}

/// user#5 — lifecycle section renders the created / last-seen / last-
/// fetch / age facts.
#[tokio::test]
async fn pr_user_lifecycle_section_renders_facts() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(html.contains("Lifecycle"), "lifecycle eyebrow missing");
    for label in ["created", "last seen", "last fetch", "age"] {
        assert!(html.contains(label), "lifecycle label '{label}' missing");
    }
}

/// user#6 — the live-VPN-stats section folds in a window picker scoped
/// to THIS user's detail page (24h/7d/30d/all) so the trend is one
/// click away.
#[tokio::test]
async fn pr_user_live_stats_folds_in_user_scoped_window_picker() {
    use vpnctl_inventory::VpnStatsDelta;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 1_000_000,
                download_bytes: 2_000_000,
                active_connections: 1,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0/traffic").await;
    // The window picker links are scoped to the user's detail page.
    assert!(
        html.contains("/admin/users/u0/traffic?vpn_window=7d"),
        "window picker must offer a 7d link scoped to this user"
    );
    assert!(
        html.contains("/admin/users/u0/traffic?vpn_window=30d"),
        "window picker must offer a 30d link scoped to this user"
    );
    // The trend sub-heading renders when there's traffic.
    assert!(
        html.contains("traffic trend · "),
        "folded sparkline trend heading missing"
    );
}

/// user#7 — the UA-cluster section carries the additive geo + last-seen
/// footer (country / ASN / last-seen) once the user has /sub history.
#[tokio::test]
async fn pr_user_ua_section_carries_geo_and_last_seen_footer() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .log_sub_access_rich(
            &UserId("u0".into()),
            "192.0.2.10",
            Some("Hiddify/Android/2.5.0"),
            200,
            100,
            None,
            None,
            None,
            Some("US"),
            Some("AS111 Alpha"),
            None,
            None,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(
        html.contains("UA fingerprint"),
        "UA section must render with /sub history"
    );
    // Additive geo + last-seen footer labels.
    assert!(
        html.contains("countries · 30d"),
        "UA geo footer (countries) missing"
    );
    assert!(html.contains("ASNs · 30d"), "UA geo footer (ASNs) missing");
    assert!(html.contains("last seen "), "UA last-seen footer missing");
}

/// Copy-contract (EN) — pin every new PR-User headline so a rename has
/// to update this test in the same PR.
#[tokio::test]
async fn pr_user_info_cards_headlines_en() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // Give the user /sub history so the UA + verdict cards render.
    s.inv
        .log_sub_access(
            &UserId("u0".into()),
            "192.0.2.10",
            Some("Hiddify/Android/2.5.0"),
            200,
            100,
        )
        .await
        .unwrap();
    // ui-audit §4 — these cards span tabs: Presence (chrome, every tab),
    // verdict/lifecycle/traffic-limit on overview, traffic-by-server on
    // the traffic tab. Fetch each and pin its subset.
    let app = router(s);
    let overview = fetch_html(app.clone(), "/admin/users/u0").await;
    let traffic = fetch_html(app, "/admin/users/u0/traffic").await;
    for (html, needle) in [
        (&overview, "Presence"),        // user#1 (chrome)
        (&traffic, "Live VPN stats"),   // user#2 (R2: merged table)
        (&overview, "Sharing verdict"), // user#4
        (&overview, "Lifecycle"),       // user#5
        (&overview, "Traffic limit"),   // user#3
    ] {
        assert!(
            html.contains(needle),
            "PR-User EN headline drifted — missing: {needle:?}"
        );
    }
}

/// Copy-contract (RU) — pin the Russian arm of each new PR-User card.
/// Extends the i18n RU walker coverage onto the user-detail page.
#[tokio::test]
async fn pr_user_info_cards_headlines_ru() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .log_sub_access(
            &UserId("u0".into()),
            "192.0.2.10",
            Some("Hiddify/Android/2.5.0"),
            200,
            100,
        )
        .await
        .unwrap();
    let app = router(s);
    let overview = fetch_html_with_cookie(app.clone(), "/admin/users/u0", "vpnctl_lang=ru").await;
    let traffic = fetch_html_with_cookie(app, "/admin/users/u0/traffic", "vpnctl_lang=ru").await;
    for (html, needle) in [
        (&overview, "Присутствие"),             // user#1 (chrome)
        (&traffic, "Живая статистика VPN"),     // user#2 (R2: merged table)
        (&overview, "Вердикт по расшариванию"), // user#4
        (&overview, "Жизненный цикл"),          // user#5
        (&overview, "Лимит трафика"),           // user#3
    ] {
        assert!(
            html.contains(needle),
            "PR-User RU headline drifted — missing: {needle:?}"
        );
    }
}

/// Design v2 4c — the user Activity tab opens with the four fact
/// tiles and the GeoIP-resolved fetch log (row per fetch incl. the
/// geo/asn/ua columns and the egress ⚠ flag path).
#[tokio::test]
async fn v2_user_activity_renders_tiles_and_geo_log() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .log_sub_access(
            &UserId("u0".into()),
            "5.5.5.5",
            Some("Hiddify/2.5 android"),
            200,
            500,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(html.contains("sharing verdict"), "verdict tile missing");
    // TT-3 — the distinct-IP tile is labelled "client IPs · 30d" and
    // counts only real client IPs (proxy/reserved excluded), matching the
    // verdict + Source-IP origins.
    assert!(
        html.contains("client IPs · 30d") && html.contains("sub fetches · 30d"),
        "count tiles missing"
    );
    // TT-3 — log scope caption describes the log's own scope (all sources,
    // incl. proxy-masked + egress) so it reads as a deliberately-different
    // view from the real-client «client IPs» tile.
    assert!(
        html.contains(
            "includes proxy-masked and VPN-egress fetches the «client IPs» tile excludes"
        ) || html.contains(
            "включая proxy-masked и VPN-egress обращения, которые плитка «клиентских IP» исключает"
        ),
        "log scope caption missing"
    );
    assert!(
        html.contains("Sub-access log · GeoIP-resolved"),
        "geo log eyebrow missing"
    );
    assert!(html.contains("5.5.5.5"), "fetch row IP missing");
    assert!(html.contains("Hiddify/2.5 android"), "fetch row UA missing");
}

/// Design v2 4a — Delivery opens with the compact subscription recap
/// (URL + Overview QR link + legacy /sub fallback note).
#[tokio::test]
async fn v2_user_delivery_renders_subscription_recap() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/users/u0/delivery").await;
    assert!(
        html.contains("QR on Overview →") || html.contains("QR на Обзоре →"),
        "recap must link the Overview QR"
    );
    assert!(
        html.contains("LAN-only fallback"),
        "legacy /sub fallback note missing"
    );
}

/// v2 4c gap-close — the Activity sub-access log shows a «showing N of M»
/// pager with an older→ link and a CSV export link; the CSV endpoint
/// returns a text/csv attachment.
#[tokio::test]
async fn v2_user_activity_log_pagination_and_csv() {
    use vpnctl_core::UserId;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // 30 fetches → 2 pages of 25.
    for i in 0..30 {
        s.inv
            .log_sub_access(
                &UserId("u0".into()),
                &format!("5.5.5.{i}"),
                Some("Hiddify"),
                200,
                100,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(s.clone()), "/admin/users/u0/activity").await;
    assert!(
        html.contains("showing ") && html.contains(" of "),
        "log must show the «showing N of M» counter"
    );
    assert!(
        html.contains("older →") || html.contains("старше →"),
        "page 1 of 2 must offer an older→ link"
    );
    assert!(
        html.contains("/admin/users/u0/access.csv"),
        "log must offer a CSV export link"
    );
    // CSV endpoint.
    let resp = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/users/u0/access.csv")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/csv"), "CSV must be text/csv, got {ct}");
    let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let csv = std::str::from_utf8(&body).unwrap();
    assert!(
        csv.starts_with("ts,ip,country,asn,user_agent,status,is_vpn_egress"),
        "CSV header drifted"
    );
    assert_eq!(csv.lines().count(), 31, "header + 30 data rows");
}
