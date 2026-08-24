use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::*;

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
/// `dns-tunnel://…uuid=user.uuid…` link.
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
    // JSON carrying `\"uuid\":\"<u0.uuid>\"`). Locate the link, decode it,
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
/// server.
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
    // per CLAUDE.md \"Every empty state must quote a literal CLI command\".
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
//  These tests exercise the full mutation contract from §\"Phase C-3 write
//  handlers\" in `daemon/src/handlers/admin.rs`:
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
    // Wording contract: the button text is \"rotate sub-token\" — short,
    // mono, fits the editorial voice. Pinned so a casual UI-rewrite
    // can't accidentally rename it to \"Refresh\" or \"New token\".
    assert!(
        html.contains(">rotate sub-token<"),
        "rotate-button label drifted from 'rotate sub-token'"
    );
}

/// After a successful regenerate, GET on /admin/users/u0 renders the
/// NEW token (full token appears EXACTLY ONCE — only inside the
/// canonical sub URL), not the previous one. Validates the
/// \"redirect-to-canonical-page\" pattern end-to-end.
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

#[tokio::test]
async fn admin_user_detail_flow_a_card_uses_share_link_card_with_copy_textarea() {
    // Need: a user with a sub_token AND wireguard keypair so the
    // distribution panel renders (Flow A + Flow B both visible).
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
    // Dash-agnostic label match (the card eyebrow is \"Flow F — AmneziaWG
    // (awg://)\" with an em-dash).
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
    // Use rfind: the FIRST \"awg://\" is the label «(awg://)»; the actual
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
async fn admin_user_detail_flow_b_links_to_conf_download() {
    // Operator should see a `.conf` link next to each Flow B server
    // (universal fallback that imports into AmneziaVPN via its
    // \"File with settings\" picker even if the user can't paste
    // the vpn:// link directly).
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
