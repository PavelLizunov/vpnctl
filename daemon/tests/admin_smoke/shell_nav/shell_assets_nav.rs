use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn admin_root_renders_editorial_shell() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200, got {:?}",
        resp.status()
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    // The chrome was rendered — design v2 topbar (single compact bar).
    assert!(html.contains(r#"class="ed-tb""#), "missing topbar in html");
    assert!(html.contains(r#"class="ed-tb__nav""#), "missing topbar nav");
    assert!(
        html.contains(r#"id="tb-search""#),
        "missing topbar search input"
    );
    assert!(html.contains("vpnctl"), "missing wordmark text");
    // Tweaks panel moved into /admin/settings (2026-05-17 — Pavel:
    // «Tweaks правильнее держать в settings»). The dashboard
    // chrome must NOT contain the panel chip or the collapse pill.
    assert!(
        !html.contains(">Tweaks<"),
        "dashboard must not carry the (deprecated) floating Tweaks chip"
    );
    assert!(
        !html.contains("↑ Tweaks"),
        "dashboard must not carry the (deprecated) collapse pill"
    );
    // Page-root class composition: default theme/accent (no cookies)
    // contributes nothing beyond `ed`. The old `ed-tweaks-open`
    // modifier is gone with the floating panel.
    assert!(
        html.contains(r#"class="ed""#),
        "expected default page class to be just 'ed', got: {}",
        &html[..html.len().min(500)]
    );
}

/// Design v2 topbar acceptance — one compact bar with a clickable
/// wordmark, an active pill on the current section, the LIVE unacked
/// alerts count as a warm chip, and the search input (`/`-hotkey wired
/// in admin.js).
#[tokio::test]
async fn v2_topbar_renders_active_pill_search_and_live_alert_count() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Two unacked alerts (no server FK) -> the ALERTS item shows the count.
    s.inv
        .insert_alert("server.unreachable", None, "critical", "down", None)
        .await
        .unwrap();
    s.inv
        .insert_alert(
            "sub_access.suspicious_local_ip:u0",
            None,
            "warning",
            "loop",
            None,
        )
        .await
        .unwrap();

    // On the monitoring page the MONITORING item is the active pill.
    let html = fetch_html(router(s), "/admin/monitoring").await;
    assert!(html.contains(r#"class="ed-tb""#), "topbar bar missing");
    assert!(
        html.contains(r#"class="ed-tb__logo" href="/admin/""#),
        "wordmark must link to /admin/"
    );
    assert!(
        html.contains(r#"<a class="on" href="/admin/monitoring">"#),
        "active nav item must carry the .on pill"
    );
    assert!(
        html.contains(r#"<span class="ct">2</span>"#),
        "ALERTS nav item must show the live unacked count (2)"
    );
    assert!(
        html.contains(r#"id="tb-search""#) && html.contains("search…  /"),
        "topbar search input with `/` hint missing"
    );
}

/// Symmetric quiet-state: zero unacked alerts -> no count chip.
#[tokio::test]
async fn v2_topbar_omits_alert_chip_when_none_unacked() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(html.contains(r#"class="ed-tb__nav""#), "topbar nav missing");
    assert!(
        !html.contains(r#"<span class="ct">"#),
        "no unacked alerts -> no count chip on the ALERTS item"
    );
}

#[tokio::test]
async fn admin_assets_admin_css_served() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/assets/admin.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body.len() > 10_000, "css too small: {} bytes", body.len());
    assert!(std::str::from_utf8(&body).unwrap().contains("--paper"));
}

/// The nav must render anchors that actually navigate. Previous version had
/// `<a class="...">` with no `href`, so clicks were silent no-ops.
#[tokio::test]
async fn admin_nav_anchors_have_hrefs() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    // Dashboard canonical URL is /admin/, others are /admin/<section>.
    for href in [
        "href=\"/admin/\"",
        "href=\"/admin/monitoring\"",
        "href=\"/admin/servers\"",
        "href=\"/admin/users\"",
        "href=\"/admin/audit\"",
        "href=\"/admin/settings\"",
    ] {
        assert!(html.contains(href), "missing nav href: {href}");
    }
}

/// Trailing-slash variant of every section route must also respond 200,
/// otherwise nav copies that get pasted with a trailing `/` (browsers,
/// share links, etc.) would 404. Dashboard already handles `/admin` and
/// `/admin/` — the section routes follow the same convention.
#[tokio::test]
async fn admin_section_routes_accept_trailing_slash() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for path in [
        "/admin/monitoring/",
        "/admin/servers/",
        "/admin/users/",
        "/admin/audit/",
        "/admin/settings/",
    ] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "expected 200 from {path}, got {:?}",
            resp.status()
        );
    }
}

/// Inactive nav anchors must NOT carry an empty `class=""` attribute —
/// the maud `.on[bool]` toggle drops the class entirely when inactive.
/// Catches accidental `class=(if … else "")` regressions.
#[tokio::test]
async fn admin_inactive_nav_anchors_have_no_empty_class() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    // The dashboard is active, so EXACTLY one anchor should carry class="on";
    // none should carry the wasteful class="" placeholder.
    assert!(
        !html.contains("class=\"\""),
        "inactive nav anchors leaked an empty class attribute"
    );
    assert_eq!(
        html.matches("class=\"on\"").count(),
        1,
        "expected exactly one active nav item on /admin/"
    );
}

/// Frontend voice contract: each section's headline + deck must read
/// in the editorial style we're committed to. Pin one canonical phrase
/// per page so a careless re-write can't flatten the voice into a
/// generic admin-panel default ("Users (1)" / "Click to add").
#[tokio::test]
async fn admin_frontend_section_headlines_match_voice() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let app = router(s);

    let dash = fetch_html(app.clone(), "/admin/").await;
    assert!(
        dash.contains("homelab "),
        "dashboard headline lost the 'homelab' wordmark"
    );
    assert!(
        dash.contains("at a glance"),
        "dashboard headline lost the 'at a glance' kicker"
    );

    let users = fetch_html(app.clone(), "/admin/users").await;
    assert!(
        users.contains("on file"),
        "users headline lost the 'on file' kicker"
    );
    assert!(
        users.contains("Open a row for the QR you'll point a phone at"),
        "users deck lost the QR call-to-action"
    );

    let servers = fetch_html(app.clone(), "/admin/servers").await;
    assert!(
        servers.contains("in inventory"),
        "servers headline lost the 'in inventory' kicker"
    );

    let detail = fetch_html(app.clone(), "/admin/users/u0").await;
    assert!(
        detail.contains("Subscription"),
        "user-detail subscription section heading drifted"
    );
    // Post-Phase-5 (2026-05-19): u0 in seed() has no `vpn_router_device_id`
    // pinned → renders the legacy fallback subscription block. Pre-Phase-5
    // this nudge was "Point a Hiddify-style client at the URL once" — that
    // copy moved into the ninitux-primary branch (which u0 doesn't reach
    // without a device_id) and was rewritten to mention nginx + ninitux.com.
    // The fallback copy must keep pointing the operator at the import
    // script — the action they need to upgrade this user from LAN-only
    // to production.
    assert!(
        detail.contains("Legacy")
            && detail.contains("LAN-only")
            && detail.contains("scripts/import_from_subscription_server.py"),
        "user-detail legacy-fallback copy drifted (no-device_id branch)"
    );
    // abuse-origins — pin the "Subscription origins" headline (EN) so a
    // copy edit has to update this contract in lockstep. Lives on the
    // activity tab now (ui-audit §4).
    let detail_activity = fetch_html(app.clone(), "/admin/users/u0/activity").await;
    assert!(
        detail_activity.contains("Subscription origins"),
        "user-detail 'Subscription origins' section headline drifted"
    );
}

/// Empty-state contract (operator-action policy): when there are no
/// users (or no servers), the page points the operator at the WEB action
/// — NOT a terminal command. The admin UI creates both via web (the
/// add-user form + the server wizard), so the copy that used to quote
/// `vpnctl user create` / `vpnctl grant` / `vpnctl bootstrap` now
/// describes the web path instead.
#[tokio::test]
async fn admin_empty_states_point_at_web_actions() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let users = fetch_html(app.clone(), "/admin/users").await;
    assert!(
        users.contains("create"),
        "empty users page must point at the web create form"
    );
    for bad in ["vpnctl user create", "vpnctl grant"] {
        assert!(
            !users.contains(bad),
            "empty users page must not quote CLI command «{bad}»"
        );
    }

    let servers = fetch_html(app.clone(), "/admin/servers").await;
    assert!(
        servers.contains("wizard"),
        "empty servers page must point at the web wizard"
    );
    assert!(
        !servers.contains("vpnctl bootstrap"),
        "empty servers page must not quote `vpnctl bootstrap`"
    );
}

/// Favicon contract: every page links to the SVG favicon, and the SVG
/// is served. Without this the browser tab shows a blank square — a
/// tell-tale "unfinished" signal even when the page chrome is polished.
#[tokio::test]
async fn admin_pages_link_favicon_and_asset_is_served() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let html = fetch_html(app.clone(), "/admin/").await;
    assert!(
        html.contains(r#"<link rel="icon" type="image/svg+xml" href="/admin/assets/favicon.svg">"#),
        "favicon <link> missing from page <head>"
    );

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/assets/favicon.svg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "favicon.svg must serve 200, got {:?}",
        resp.status()
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert!(
        body.starts_with("<?xml") || body.starts_with("<svg"),
        "favicon body must look like SVG, got {:?}",
        &body[..body.len().min(80)]
    );
    assert!(
        body.contains("circle") || body.contains("path"),
        "favicon SVG must draw the [•] glyph (circle + paths)"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase D — audit timeline UI
//
//  Pin the contract end-to-end: empty state, filtered rows, pagination
//  links, CSV export shape + Content-Disposition.
// ────────────────────────────────────────────────────────────────────────

/// Empty audit log → friendly nudge, NOT a blank page or "0 rows".
#[tokio::test]
async fn admin_audit_empty_state_renders_nudge() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/audit").await;
    assert!(
        html.contains("No audit rows yet"),
        "empty-state nudge missing"
    );
    // Filter form must still render so operator can come back later.
    assert!(
        html.contains(r#"action="/admin/audit""#),
        "filter form action drifted"
    );
    assert!(html.contains(">filter<"), "filter button label drifted");
    assert!(html.contains(">export csv<"), "csv export link missing");
}

/// With rows from two actors, the actor=admin filter narrows. Pinned
/// via the response HTML: a row with action `user.sub_token.regen`
/// (cli-actor) seeded in the inventory must NOT appear when filter
/// is actor=admin.
#[tokio::test]
async fn admin_audit_filter_by_actor_narrows() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .audit("admin", "user.add", Some("alice"), None)
        .await
        .unwrap();
    s.inv
        .audit("cli", "server.deploy", Some("stg"), None)
        .await
        .unwrap();
    let app = router(s);

    // Unfiltered: both rows.
    let html = fetch_html(app.clone(), "/admin/audit").await;
    assert!(html.contains("user.add"));
    assert!(html.contains("server.deploy"));

    // actor=admin: only the user.add row.
    let html = fetch_html(app, "/admin/audit?actor=admin").await;
    assert!(
        html.contains("user.add"),
        "admin actor's row must remain after filter"
    );
    assert!(
        !html.contains("server.deploy"),
        "cli actor's row must be filtered out"
    );
}

/// v2 polish (R2 default flip) — the hourly `backup.snapshot`
/// housekeeping rows are hidden BY DEFAULT (they drowned the first
/// screen); `?hide=none` shows everything and the chip toggles
/// between the two states.
#[tokio::test]
async fn admin_audit_hides_snapshots_by_default_with_show_chip() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    for _ in 0..2 {
        s.inv
            .audit("admin", "backup.snapshot", None, None)
            .await
            .unwrap();
    }
    s.inv
        .audit("admin", "user.grant", Some("alice"), None)
        .await
        .unwrap();
    let app = router(s);

    // Default view: housekeeping HIDDEN, real mutation visible, the
    // way back offered, and the counts line marks the active filter.
    let html = fetch_html(app.clone(), "/admin/audit").await;
    assert!(
        !html.contains("backup.snapshot"),
        "default view must hide snapshot rows"
    );
    assert!(html.contains("user.grant"), "real mutations must survive");
    assert!(
        html.contains("hide=none"),
        "default view must offer the show-snapshots chip"
    );
    assert!(
        html.contains("match the filter"),
        "default hiding counts as an active filter in the counts line"
    );

    // ?hide=none: snapshots visible, chip flips back to hiding.
    let html = fetch_html(app, "/admin/audit?hide=none").await;
    assert!(
        html.contains("backup.snapshot"),
        "?hide=none must render snapshot rows"
    );
    assert!(
        html.contains("hide snapshots"),
        "show-all view must offer the hide chip"
    );
}

/// Action prefix filter: `?action=user.` matches `user.add` and
/// `user.sub_token.regen` but NOT `grant` or `server.deploy`.
#[tokio::test]
async fn admin_audit_filter_by_action_prefix_narrows() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .audit("admin", "user.add", Some("alice"), None)
        .await
        .unwrap();
    s.inv
        .audit("admin", "user.sub_token.regen", Some("alice"), None)
        .await
        .unwrap();
    s.inv
        .audit("admin", "grant", Some("stg"), None)
        .await
        .unwrap();
    let app = router(s);

    let html = fetch_html(app, "/admin/audit?action=user.").await;
    assert!(html.contains("user.add"));
    assert!(html.contains("user.sub_token.regen"));
    assert!(
        !html.contains(">grant<"),
        "grant action must be filtered out by user. prefix"
    );
}

/// Pagination: with > PAGE_SIZE rows seeded, the prev/next links
/// render in the right enabled/disabled states. Pinning behavior
/// rather than the exact PAGE_SIZE constant so changing the cap
/// later doesn't break this test.
#[tokio::test]
async fn admin_audit_pagination_links_render_correctly() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // 60 audit rows ensures we cross the default 50/page boundary.
    for i in 0..60 {
        s.inv
            .audit("admin", "user.add", Some(&format!("u{i}")), None)
            .await
            .unwrap();
    }
    let app = router(s);

    // Page 0 (default): 50 rows visible, prev disabled, next enabled.
    let html = fetch_html(app.clone(), "/admin/audit").await;
    assert!(
        html.contains(r#"href="/admin/audit?page=1""#),
        "page 0 must link forward to page=1"
    );
    assert!(
        !html.contains("page=-1"),
        "disabled prev must not produce a page=-1 link"
    );
    // Row-count assertion (per review-agent finding): without this an
    // impl that ignored OFFSET and returned all 60 rows on every page
    // would still pass the link-presence checks above.
    let row_count_p0 = html.matches("class=\"ed-time-row\"").count();
    assert_eq!(
        row_count_p0, 50,
        "page 0 must show exactly PAGE_SIZE=50 rows, got {row_count_p0}"
    );

    // Page 1: prev enabled (back to 0), next disabled (60 rows fit
    // in 2 pages of 50: page 1 has 10 rows, no next).
    let html = fetch_html(app, "/admin/audit?page=1").await;
    assert!(
        html.contains(r#"href="/admin/audit?page=0""#),
        "page 1 must link back to page=0"
    );
    assert!(
        !html.contains(r#"href="/admin/audit?page=2""#),
        "page 1 (last) must NOT have a page=2 link"
    );
    let row_count_p1 = html.matches("class=\"ed-time-row\"").count();
    assert_eq!(
        row_count_p1, 10,
        "page 1 must show the remaining 10 rows, got {row_count_p1}"
    );
}

/// CSV export: 200 + Content-Disposition attachment + RFC 4180 header
/// row + at least one body row that escapes a payload field with
/// embedded comma + double-quote.
#[tokio::test]
async fn admin_audit_csv_export_returns_well_formed_csv() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .audit(
            "admin",
            "user.add",
            Some("alice"),
            Some(&serde_json::json!({"uuid": "uuid-with-\"quote\", and-comma"})),
        )
        .await
        .unwrap();
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/audit.csv")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.starts_with("text/csv"),
        "content-type must be text/csv*, got {ct:?}"
    );
    let cd = resp
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        cd.starts_with("attachment; filename=\"vpnctl-audit-"),
        "Content-Disposition must trigger download with stamped filename, got {cd:?}"
    );

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = std::str::from_utf8(&body).unwrap();

    let mut lines = s.lines();
    assert_eq!(
        lines.next(),
        Some("ts,actor,action,target,payload"),
        "header row drifted"
    );
    let row = lines.next().expect("at least one body row");
    assert!(
        row.contains(",admin,user.add,alice,"),
        "row body shape drifted"
    );
    // Payload must be quoted because it contains both `"` and `,`.
    // The expected form layers two escapings: serde_json escapes the
    // operator's literal `"` as `\"` inside its JSON string, then
    // csv_field RFC-4180-doubles the JSON string's `"` chars to `""`.
    // The single expected literal pins exactly that output — no
    // alternation, so a divergent impl can't slip through (per the
    // review-agent finding that the previous `||` masked ambiguity).
    let expected_payload = r#""{""uuid"":""uuid-with-\""quote\"", and-comma""}""#;
    assert!(
        row.contains(expected_payload),
        "payload not RFC4180-escaped as expected;\n  expected to contain: {expected_payload}\n  got row:             {row}"
    );
}

// Audit timeline payload summary — Pavel UX bug 2026-05-16: row
// said "server.protocol.enable stg by admin" with no hint that
// the protocol was wireguard. Summary now renders key=value.

#[tokio::test]
async fn admin_audit_timeline_shows_payload_summary_with_protocol() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .audit(
            "admin",
            "server.protocol.enable",
            Some("stg"),
            Some(&serde_json::json!({
                "protocol": "wireguard",
                "newly_added": true,
            })),
        )
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/audit").await;
    assert!(
        html.contains("protocol=wireguard"),
        "timeline must show what protocol was enabled"
    );
    assert!(
        html.contains("newly_added=true"),
        "timeline must show added flag"
    );
}

// ─── Tooltip coverage spec (bug-audit-agent 2026-05-21) ──────────────
//
// Pavel: «сделал подсказки по каждому пункту, чтоб всем было понятно
// как пользоваться». The bug-audit agent walked the live UI and found
// ~30 actionable elements / dense tables without explainer tooltips.
// These tests pin the most-trafficked ones so a future maud refactor
// can't silently strip them.

#[tokio::test]
async fn tooltips_audit_filter_form_carries_explainers() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/audit").await;
    // Placeholder refreshed 2026-06-10 (post grant-audit rename):
    // `user.grant` replaces the stale bare `grant.` hint, which matched
    // neither the new `user.grant` rows nor legacy `grant` ones.
    assert!(
        html.contains("server. / user.grant / user. / settings."),
        "audit filter placeholder must list concrete dot-prefixes"
    );
    assert!(
        html.contains("admin = web UI"),
        "actor select must explain the 3 actor values"
    );
    assert!(
        html.contains("dot-separated domain.subdomain.verb"),
        "action input must surface the audit naming convention"
    );
    assert!(
        html.contains("Apply actor + action-prefix filters"),
        "filter button must carry its purpose tooltip"
    );
}

#[tokio::test]
async fn tooltips_footer_drops_htmx_lie() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("axum + maud"),
        "footer should claim the stack we actually ship"
    );
    assert!(
        !html.contains("axum + maud + htmx"),
        "footer must NOT claim htmx — we don't ship it"
    );
}
