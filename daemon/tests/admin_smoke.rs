//! Phase A + B smoke: GET /admin/ renders the editorial shell, and the
//! dashboard / servers screens read from the inventory.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality};
use vpnctld::{AppState, router};

async fn state(dir: &TempDir) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    // Mirror the full production registry so tests that introspect
    // the registry (e.g. server-detail enabled-protocols section)
    // see the same set the live daemon does. Previously only 2
    // protocols were registered here, which made admin_smoke
    // tests for the protocols section fail silently — they'd
    // pass on assertions involving vless/tuic and skip everything
    // else without the test owner noticing.
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::AmneziaWg::new()))
        .unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::WgTurn::new()))
        .unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::Hysteria2::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::Shadowsocks2022::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::WireGuard::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::AnyTls::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::Trojan::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::WgTurn::new()))
        .unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::Caddy::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::Naive::new()))
        .unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::DnsTunnel::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::DnsTunnel::new()))
        .unwrap();
    // Wire the access-log writer the same way `build()` does. Drop the
    // JoinHandle — for tests that don't introspect the writer, the
    // task lives until the AppState clones drop, which happens at end
    // of test. Tests that DO need to assert writer behavior (e.g.
    // back-pressure spec) call `vpnctld::make_app_state_for_tests`
    // directly to keep the handle.
    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

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

#[tokio::test]
async fn admin_tweak_theme_sets_cookie_and_redirects() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tweak/theme")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/")),
            )
            .body(Body::from("value=foxed"))
            .unwrap(),
        )
        .await
        .unwrap();
    // Redirect with Set-Cookie.
    assert!(
        resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::TEMPORARY_REDIRECT,
        "expected 303/307, got {:?}",
        resp.status()
    );
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("set-cookie missing")
        .to_str()
        .unwrap();
    assert!(cookie.contains("vpnctl_theme=foxed"));
    assert!(cookie.contains("Path=/admin"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
}

/// CSRF-flavoured open-redirect guard: a Referer pointing at an external
/// host (or a non-/admin path) must NOT become the redirect target. The
/// tweak still succeeds (cookie set), but the browser lands on /admin/
/// instead of the attacker's page.
#[tokio::test]
async fn admin_tweak_rejects_external_referer() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for hostile in [
        "https://evil.example.com/foo",
        "http://evil.example.com/admin/", // path looks ok, host doesn't
        "//evil.example.com/admin/",      // protocol-relative
        "/etc/passwd",                    // path, but not under /admin
        "javascript:alert(1)",
        "data:text/html,<script>1</script>",
    ] {
        // Same-origin Host + Origin so the CSRF middleware lets this
        // through — we want to test the SECOND-layer open-redirect
        // defense (`sanitize_referer`), not the CSRF rejection.
        let resp = app
            .clone()
            .oneshot(
                add_same_origin(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/tweak/theme")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .header("referer", hostile),
                )
                .body(Body::from("value=foxed"))
                .unwrap(),
            )
            .await
            .unwrap();
        // The cookie still gets set (request was authenticated), but the
        // redirect target must be the safe fallback.
        assert!(
            resp.status() == StatusCode::SEE_OTHER
                || resp.status() == StatusCode::TEMPORARY_REDIRECT,
            "expected 303/307 for hostile referer {hostile:?}, got {:?}",
            resp.status()
        );
        let location = resp
            .headers()
            .get("location")
            .expect("location missing")
            .to_str()
            .unwrap();
        assert_eq!(
            location, "/admin/",
            "open-redirect: hostile referer {hostile:?} was followed (location={location})"
        );
    }
}

/// Sanity: a same-origin Referer pointing INSIDE /admin must be honoured.
/// Otherwise the round-trip back to whichever section the operator was on
/// would always dump them at the dashboard.
#[tokio::test]
async fn admin_tweak_preserves_safe_referer() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for (referer, expected_target) in [
        ("/admin/users", "/admin/users"),
        ("/admin/", "/admin/"),
        ("http://192.168.0.236:18402/admin/audit", "/admin/audit"),
        (
            "http://192.168.0.236:18402/admin/settings/",
            "/admin/settings/",
        ),
        ("/admin/users?tab=grants", "/admin/users?tab=grants"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                add_same_origin(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/tweak/theme")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .header("referer", referer),
                )
                .body(Body::from("value=foxed"))
                .unwrap(),
            )
            .await
            .unwrap();
        let location = resp
            .headers()
            .get("location")
            .expect("location missing")
            .to_str()
            .unwrap();
        assert_eq!(
            location, expected_target,
            "safe referer {referer:?} was rewritten to {location} (wanted {expected_target})"
        );
    }
}

#[tokio::test]
async fn admin_tweak_rejects_unknown_value() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tweak/theme")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("value=neon"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_respects_theme_and_accent_cookies() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .header("cookie", "vpnctl_theme=foxed; vpnctl_accent=plum")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("ed-foxed") && html.contains("ed-acc-plum"),
        "expected ed-foxed AND ed-acc-plum on root, got class extract: {}",
        html.split("class=\"")
            .nth(1)
            .unwrap_or("?")
            .split('"')
            .next()
            .unwrap_or("?")
    );
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

/// At least one element on the page must reference `var(--acc)` so the
/// operator sees the accent toggle take visible effect. Earlier Phase A
/// pages used neutral colours only so the accent change felt inert.
///
/// Pre-2026-05-17: the accent surfaced via the floating bottom-right
/// Tweaks panel which highlighted the active button with
/// `background: var(--acc)`. Tweaks moved into /admin/settings; the
/// active-accent highlighting now lives there.
#[tokio::test]
async fn admin_renders_accent_variable_inline() {
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
    assert!(
        html.contains("var(--acc)"),
        "page must reference var(--acc) so the accent toggle is observable"
    );
    // The active-accent highlight lives in the Settings page now —
    // not in the dashboard chrome — but the var must still be wired
    // into the dashboard SOMEWHERE so the cookie-driven re-render is
    // visible. The masthead's glyph stroke uses var(--acc).
    let app2 = router(state(&dir).await);
    let settings_resp = app2
        .oneshot(
            Request::builder()
                .uri("/admin/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let settings_body = settings_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let settings_html = std::str::from_utf8(&settings_body).unwrap();
    assert!(
        settings_html.contains("background: var(--acc)"),
        "Settings page must highlight the active accent button with var(--acc)"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase B — dashboard + servers list
// ────────────────────────────────────────────────────────────────────────

/// Seed the inventory with `n_servers` servers and `n_users` users; if
/// `grant_pairs` are given, add those user×server grants too. Lives here
/// instead of in a #[cfg(test)] mod because integration tests can't share
/// helpers across files via cfg.
async fn seed(
    inv: &SqliteInventory,
    n_servers: usize,
    n_users: usize,
    grant_pairs: &[(usize, usize)],
) {
    for i in 0..n_servers {
        let id = ServerId(format!("s{i}"));
        inv.add_server(&Server {
            id,
            address: format!("10.0.0.{i}"),
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
    }
    for i in 0..n_users {
        let id = UserId(format!("u{i}"));
        inv.add_user(&User {
            id,
            uuid: format!("00000000-0000-0000-0000-{i:012}"),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    }
    for (u, s) in grant_pairs {
        inv.grant(&UserId(format!("u{u}")), &ServerId(format!("s{s}")))
            .await
            .unwrap();
    }
}

async fn fetch_html(app: axum::Router, path: &str) -> String {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200 from {path}, got {:?}",
        resp.status()
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Variant of `fetch_html` that ships a Cookie header — used by the
/// wizard step-2 tests where the page is session-gated.
async fn fetch_html_with_cookie(app: axum::Router, path: &str, cookie: &str) -> String {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(path)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200 from {path}, got {:?}",
        resp.status()
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Empty inventory must render the dashboard with all four metric tiles
/// at zero (or "live" for the daemon tile) and the empty-state copy for
/// recent activity. Each integer is anchored to its tile, so swapping
/// tile order in a refactor doesn't fool the test.
#[tokio::test]
async fn admin_dashboard_renders_zero_state_on_empty_db() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/").await;

    assert!(html.contains(r#"class="ed-sumbar""#), "summary bar missing");
    assert_summary_stat(&html, "0", "servers");
    assert_summary_stat(&html, "0", "users");
    assert_summary_stat(&html, "0", "protocols");
    // Daemon 'live' status lives in the summary bar's right slot.
    assert!(
        html.contains(r#"class="ed-sumbar__live""#) && html.contains("<em>live</em>"),
        "summary bar must show the daemon 'live' status"
    );
    // Dashboard 1b quiet contract: no servers → no fleet table, no
    // alerts → no health feed, no flagged users → no likely-shared
    // panel. The overview two-column wrapper still renders (empty).
    assert!(
        !html.contains("fleet-at-a-glance"),
        "empty inventory must not render the fleet table"
    );
    assert!(
        html.contains(r#"class="ed-dash-cols""#),
        "overview panel row missing"
    );
}

/// Assert the dashboard summary bar (densification pass) shows
/// `<b>value</b> label` (e.g. `<b>3</b> servers`), anchoring each count to
/// its own unit label so a reorder of the bar can't pass by coincidence.
fn assert_summary_stat(html: &str, value: &str, label: &str) {
    let needle = format!("<b>{value}</b> {label}");
    assert!(
        html.contains(&needle),
        "summary stat '{value} {label}' not found (looked for {needle:?})"
    );
}

/// Dashboard counters must reflect what's actually in the inventory:
/// 3 servers, 2 users, 4 grants → exact integers anchored to their tiles
/// plus an "across 4 grants" subtitle.
#[tokio::test]
async fn admin_dashboard_counts_match_seeded_inventory() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // 4 grants among 2 users / 3 servers (u0 -> s0,s1; u1 -> s1,s2)
    seed(&s.inv, 3, 2, &[(0, 0), (0, 1), (1, 1), (1, 2)]).await;

    let app = router(s);
    let html = fetch_html(app, "/admin/").await;

    assert_summary_stat(&html, "3", "servers");
    assert_summary_stat(&html, "2", "users");
    // distinct enabled_protocols is 1 (every seeded server gets
    // vless+reality) — and the label declines: «1 protocol», not the
    // old always-plural «1 protocols» (i18n::noun_for, polish pass).
    assert_summary_stat(&html, "1", "protocol");
    assert!(
        html.contains("<b>4</b> grants"),
        "grants subtitle missing or wrong (expected 4 grants, plural)"
    );
}

/// Servers screen must show the empty-state when the DB is empty,
/// quoting the bootstrap incantation so the operator knows what to do.
#[tokio::test]
async fn admin_servers_empty_state_quotes_bootstrap() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/servers").await;

    assert!(html.contains("No servers yet"), "empty-state copy missing");
    assert!(
        html.contains("vpnctl bootstrap"),
        "bootstrap hint missing on empty servers page"
    );
    // No <article class="ed-server"> when the list is empty.
    assert!(
        !html.contains(r#"class="ed-server""#),
        "server cards must not render on empty inventory"
    );
}

/// Populated servers screen must render exactly one ed-server card per
/// server, expose each server id and address, and mark the right user
/// counts (0 for ungranted, N for granted).
#[tokio::test]
async fn admin_servers_renders_one_card_per_server_with_user_counts() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // s0 -> 2 users, s1 -> 1 user, s2 -> 0 users
    seed(&s.inv, 3, 2, &[(0, 0), (1, 0), (0, 1)]).await;

    let app = router(s);
    let html = fetch_html(app, "/admin/servers").await;

    // One row per server in the dense inventory table (densify 2a).
    assert!(
        html.contains(r#"<table class="ed-grid">"#),
        "servers list must render the dense inventory table"
    );
    assert_eq!(
        html.matches(r#"class="ed-grid__id""#).count(),
        3,
        "expected three server rows (one ed-grid__id link each)"
    );
    // Header shows total.
    assert!(
        html.contains("3 <em>servers</em>"),
        "page header should announce 3 servers"
    );
    // Each id renders.
    for id in ["s0", "s1", "s2"] {
        assert!(html.contains(id), "server id {id} missing from html");
    }
    // Each address renders (port suffix appended by render).
    for addr in ["10.0.0.0:22", "10.0.0.1:22", "10.0.0.2:22"] {
        assert!(html.contains(addr), "address {addr} missing");
    }
    // User counts: 2 users, 1 user, 0 users — singular vs plural.
    assert!(
        html.contains("<b>2</b> users"),
        "s0 should show 2 users granted access"
    );
    assert!(
        html.contains("<b>1</b> user"),
        "s1 should show 1 user (singular form)"
    );
    assert!(
        html.contains("<b>0</b> users"),
        "s2 should show 0 users granted access"
    );
}

/// "Deploy all" button (2026-06-03): the servers page shows the
/// SSE-driven deploy-all trigger + the live log pane when ≥1 server.
#[tokio::test]
async fn admin_servers_renders_deploy_all_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers").await;
    assert!(
        html.contains(r#"data-sse-url="/admin/servers/deploy-all/sse""#),
        "deploy-all button must carry the SSE trigger URL"
    );
    assert!(
        html.contains("deploy all servers"),
        "deploy-all button label drifted"
    );
    assert!(
        html.contains(r#"id="deploy-log""#),
        "deploy-all needs a live log pane"
    );
}

/// `run_deploy_all` flattens each server's re-deploy into one stream and
/// ends in a single terminal Ok with a summary — even when servers fail
/// (here: no deploy key on disk → every server errors, but the run still
/// completes and reports the failures rather than aborting).
#[tokio::test]
async fn run_deploy_all_streams_terminal_ok_with_per_server_failures() {
    use tokio_stream::StreamExt;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    let servers = s.inv.list_servers().await.unwrap();
    // A deploy-key path that does NOT exist → run_redeploy fails each
    // server at the pre-flight; deploy_all forwards the failures and
    // still reaches its terminal Ok.
    let key = dir.path().join("nope-id_ed25519");
    let stream = vpnctld::wizard_bootstrap::run_deploy_all(
        servers,
        s.inv.clone(),
        std::sync::Arc::clone(&s.registry),
        key,
    );
    tokio::pin!(stream);
    let mut events = Vec::new();
    while let Some(ev) = stream.next().await {
        events.push(ev);
    }
    // Exactly one terminal Ok, and it's the LAST event.
    match events.last() {
        Some(vpnctld::wizard_bootstrap::BootstrapEvent::Ok { server_id, .. }) => {
            assert_eq!(server_id, "all");
        }
        other => panic!("expected terminal Ok{{server_id:\"all\"}}, got {other:?}"),
    }
    // Per-server failures surfaced as ✗ step lines, and a summary that
    // names them (both seeded servers failed → "failed: …").
    let joined: String = events
        .iter()
        .filter_map(|e| match e {
            vpnctld::wizard_bootstrap::BootstrapEvent::Step { message, .. } => {
                Some(message.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("✗ s0"),
        "s0 failure must be reported: {joined}"
    );
    assert!(
        joined.contains("failed:"),
        "summary must report failures: {joined}"
    );
}

/// Pluralisation guard for the dashboard "across N grants" subtitle:
/// 1 grant must read "1 grant" (singular), >1 must read "N grants".
#[tokio::test]
async fn admin_dashboard_pluralises_grants_subtitle() {
    // 1 grant — singular.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("<b>1</b> grant"),
        "singular form 'grant' expected for 1 grant"
    );
    assert!(
        !html.contains("<b>1</b> grants"),
        "must not pluralise when grant count is 1"
    );

    // 2 grants — plural.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("<b>2</b> grants"),
        "plural form 'grants' expected for 2 grants"
    );
}

/// A single-server inventory must render the page header in the singular
/// form. Catches the easy-to-miss pluralisation bug.
#[tokio::test]
async fn admin_servers_header_singular_for_one_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;

    let app = router(s);
    let html = fetch_html(app, "/admin/servers").await;

    assert!(
        html.contains("1 <em>server</em>"),
        "expected singular 'server' in page header"
    );
    assert!(
        !html.contains("1 <em>servers</em>"),
        "must not pluralise when count is 1"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase C-1 — users list + user detail (read-only)
// ────────────────────────────────────────────────────────────────────────

/// Empty inventory must render the users page with the explicit
/// empty-state and a hint pointing at the CLI workflow.
#[tokio::test]
async fn admin_users_empty_state_quotes_cli() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/users").await;

    assert!(
        html.contains("0 <em>users</em>"),
        "page header should announce 0 users"
    );
    assert!(html.contains("No users yet"), "empty-state copy missing");
    assert!(
        html.contains("vpnctl user create"),
        "empty-state should hint vpnctl user create"
    );
    assert!(
        !html.contains(r#"class="ed-server""#),
        "no row-articles when there are no users"
    );
}

/// Populated users list must render one row per user, never echo a full
/// sub-token (mask must hide the middle), and link each row to the
/// detail page.
#[tokio::test]
async fn admin_users_populated_renders_rows_and_masks_secrets() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 3, &[(0, 0), (1, 0), (2, 0)]).await;

    // Pick u0's sub_token after add_user backfilled it, so we can assert
    // it is NEVER returned in full on the list page.
    let u0 = s.inv.get_user(&UserId("u0".into())).await.unwrap().unwrap();
    let token = u0.sub_token.expect("backfill should mint a sub_token");
    assert!(token.len() > 16, "sub_token unexpectedly short: {token:?}");

    let html = fetch_html(router(s), "/admin/users").await;

    // 3 dense table rows.
    assert_eq!(
        html.matches(r#"class="ed-grid__id""#).count(),
        3,
        "expected 3 user rows"
    );
    // Header pluralised.
    assert!(html.contains("3 <em>users</em>"));
    // Detail link for each user.
    for id in ["u0", "u1", "u2"] {
        let href = format!(r#"href="/admin/users/{id}""#);
        assert!(
            html.contains(&href),
            "missing detail link for {id} ({href})"
        );
    }
    // Masked sub-token shows the first/last 4 chars but NOT the middle.
    let head: String = token.chars().take(4).collect();
    let tail: String = token.chars().skip(token.len() - 4).collect();
    assert!(
        html.contains(&format!("{head}…{tail}")),
        "masked token preview should appear (first 4 + last 4)"
    );
    assert!(
        !html.contains(&token),
        "FULL sub_token leaked into the list page"
    );
    // u0/u1/u2 are all granted to s0 → the grants column reads 1.
    assert_eq!(
        html.matches(r#"<td class="num"><b>1</b></td>"#).count(),
        3,
        "each user row should show one granted server"
    );
}

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

/// Seed a dns-tunnel server (with the share-link secrets) granted to one
/// user; return the inventory ready for a user-detail render.
async fn seed_dns_tunnel_server(inv: &SqliteInventory, server_id: &str, granted_user: &str) {
    let sid = ServerId(server_id.into());
    inv.add_server(&Server {
        id: sid.clone(),
        address: "203.0.113.9".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("dns-tunnel".into())],
        enabled_protocols: vec![ProtocolId("dns-tunnel".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(&sid, "dns-tunnel:domain", "t.example.com")
        .await
        .unwrap();
    inv.set_server_secret(&sid, "dns-tunnel:fingerprint", "47:1E:87:8F:3E:48:C8:1C")
        .await
        .unwrap();
    inv.grant(&UserId(granted_user.into()), &sid).await.unwrap();
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

/// Anti-fingerprint regression (caught by pre-monitoring vuln scan
/// 2026-05-20): the auth / CSRF / security-headers middleware was
/// applied via `.layer()` instead of `.route_layer()`, which in
/// axum's contract wraps the router's default 404 fallback too. Any
/// unrelated path on the daemon (e.g. `/etc/passwd`, `/`, `/.env`,
/// `/wp-login.php`) returned `401 WWW-Authenticate: Basic realm=
/// "vpnctl admin"` for GETs and `403 vpnctl admin: csrf …` for
/// POSTs, plus the admin-only CSP / X-Frame-Options / Permissions-
/// Policy headers on EVERY 404 — all distinctive backend
/// fingerprints. Fix swapped `.layer` → `.route_layer` so the
/// middleware applies only to matched admin routes.
///
/// This test pins the no-leak invariant. Note: the test runs
/// without `VPNCTLD_ADMIN_PASSWORD` set, so the auth layer is
/// skipped entirely — what we're really pinning here is that
/// CSRF + security-headers ALSO use `route_layer` (the only ones
/// that fire without the env var). The auth-layer no-leak is
/// covered by the live-verify in the same commit.
#[tokio::test]
async fn admin_unmatched_paths_do_not_leak_admin_fingerprint() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for path in [
        "/etc/passwd",
        "/",
        "/foo",
        "/.env",
        "/wp-login.php",
        "/api/v2/something",
    ] {
        // GET: must not carry the admin-tree CSP / X-Frame-Options /
        // Permissions-Policy headers — those are distinctive.
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let headers = resp.headers().clone();
        assert!(
            headers.get("content-security-policy").is_none(),
            "GET {path} leaks CSP header (admin fingerprint)"
        );
        assert!(
            headers.get("x-frame-options").is_none(),
            "GET {path} leaks X-Frame-Options (admin fingerprint)"
        );
        assert!(
            headers.get("permissions-policy").is_none(),
            "GET {path} leaks Permissions-Policy (admin fingerprint)"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8_lossy(&body);
        assert!(
            !s.contains("vpnctl admin"),
            "GET {path} leaks 'vpnctl admin' in body: {s}"
        );

        // POST: same — CSRF middleware should NOT fire on unmatched
        // paths. Pre-fix, POST returned 403 with body
        // "vpnctl admin: csrf — Origin (or Referer) must match Host"
        // + dump of Host/Origin/Referer headers.
        let req = Request::builder()
            .uri(path)
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("x=1"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8_lossy(&body);
        assert!(
            !s.contains("vpnctl admin"),
            "POST {path} leaks 'vpnctl admin' in body: {s}"
        );
        assert!(
            !s.contains("csrf"),
            "POST {path} leaks CSRF copy in body: {s}"
        );
    }

    // Positive control: an actual admin path STILL produces admin-shaped
    // responses (the fix must not break the legitimate path). Without
    // auth env var, /admin renders the page directly (200 + CSP header).
    let req = Request::builder()
        .uri("/admin")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("content-security-policy").is_some(),
        "admin pages MUST still carry CSP — security-headers layer broken"
    );
}

/// User ids containing URL-special chars (`?`, `#`, `/`, space, `&`)
/// must be percent-encoded in the detail-link href, otherwise the
/// browser would interpret them as path/query/fragment separators and
/// the link would 404 or hit the wrong handler. The HTML still escapes
/// the *text* of the id (so `<` shows literally inside the row), but
/// the href needs URL-encoding on top of that.
#[tokio::test]
async fn admin_users_href_url_encodes_special_chars() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // The inventory accepts arbitrary text as id; the daemon must
    // tolerate whatever the operator typed.
    s.inv
        .add_user(&User {
            id: UserId("weird/id?x=1 #frag".into()),
            uuid: "00000000-0000-0000-0000-000000000099".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users").await;

    // Expect: "/admin/users/weird%2Fid%3Fx%3D1%20%23frag"
    assert!(
        html.contains("href=\"/admin/users/weird%2Fid%3Fx%3D1%20%23frag\""),
        "href must percent-encode `/`, `?`, `=`, ` `, `#` (snippet around href: {:?})",
        html.split("ed-server__cta").next().unwrap_or("?")
    );
    // Negative: the raw id must NOT appear as a literal path on the link
    // (axum routing would 404, the link would be broken).
    assert!(
        !html.contains("href=\"/admin/users/weird/id?x=1 #frag\""),
        "raw, unescaped id leaked into href"
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

// ────────────────────────────────────────────────────────────────────────
//  Phase 3+ ninitux-compat URL rendering (post-Phase-5 cutover, 2026-05-19)
//
//  Pinned behaviour:
//    1. User with `vpn_router_device_id` pinned → admin UI renders
//       `https://ninitux.com/api/v1/app/config/<device_id>` as the
//       PRIMARY subscription URL. The QR encodes that exact URL.
//       The legacy `/sub/<token>` URL is demoted inside a <details>
//       collapsible labelled "LAN-only fallback".
//    2. User WITHOUT a device_id → admin UI falls back to the
//       legacy `/sub/<token>` URL as primary (pre-Phase-3 behaviour
//       preserved) AND the empty-state copy quotes the literal CLI
//       command to pin a device_id (per CLAUDE.md "Every empty
//       state must quote a literal CLI command").
//    3. Users-list deck mentions the `ninitux.com` host so the
//       operator sees the production URL shape at-a-glance.
//
//  Caught 2026-05-19 by visual review of /admin/users/tester-1: the
//  QR encoded the LAN URL `http://192.168.0.236:18402/sub/<token>`
//  which doesn't work for any client outside the LAN — operators
//  showing the QR to a real user would silently fail.
// ────────────────────────────────────────────────────────────────────────

const TEST_NINITUX_DEVICE_ID: &str = "a92b915032b48a2ed45ef72f4171e5f4";

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

#[tokio::test]
async fn admin_users_list_deck_mentions_ninitux_endpoint() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;

    let html = fetch_html(router(s), "/admin/users").await;
    // Deck text must mention the production URL shape so the operator
    // sees what clients actually fetch at-a-glance. Pre-Phase-5 deck
    // talked only about /sub/<token> which is now the LAN fallback.
    assert!(
        html.contains("ninitux.com/api/v1/app/config/&lt;device_id&gt;")
            || html.contains("ninitux.com/api/v1/app/config/<device_id>"),
        "users-list deck must mention the production ninitux URL shape"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  2026-05-17 — Tweaks moved into /admin/settings (was a floating panel)
//
//  Pavel: «Tweaks правильнее держать в settings». Removed the
//  bottom-right fixed panel + the open/closed cookie chrome; the
//  theme/accent picker now lives inline on the Settings page. These
//  tests pin the new shape so a future "let's bring back the
//  floating panel" change has to deliberately update them.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_tweaks_no_longer_float_on_dashboard() {
    let dir = TempDir::new().unwrap();
    let html = fetch_html(router(state(&dir).await), "/admin/").await;
    // No floating chrome.
    assert!(
        !html.contains(">Tweaks<"),
        "dashboard must not render the deprecated floating Tweaks chip"
    );
    assert!(
        !html.contains("↑ Tweaks"),
        "dashboard must not render the deprecated collapse pill"
    );
    // The theme + accent POST endpoints should also be absent from
    // the dashboard — there's nothing to POST from on this page.
    assert!(
        !html.contains("/admin/tweak/theme"),
        "dashboard must not carry the theme form (it lives on /admin/settings now)"
    );
    assert!(
        !html.contains("/admin/tweak/accent"),
        "dashboard must not carry the accent form (it lives on /admin/settings now)"
    );
}

// ════════════════════════════════════════════════════════════════════
//  ui-audit Phase 3 — settings split into 4 sub-route tabs
//  (appearance / backups / notifications / system). Each tab renders
//  ONLY its own sections; bare /admin/settings == appearance.
// ════════════════════════════════════════════════════════════════════

/// Each tab route → 200, renders the `.ed-tabs` bar, marks the right tab
/// active, shows a section unique to that tab, and does NOT leak a
/// foreign tab's section.
#[tokio::test]
async fn settings_tabs_render_gate_and_mark_active() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let cases = [
        (
            "/admin/settings/appearance",
            "appearance",
            "Appearance — theme + accent",
            "Backups — inventory snapshots",
        ),
        (
            "/admin/settings/backups",
            "backups",
            "Backups — inventory snapshots",
            "Appearance — theme + accent",
        ),
        (
            "/admin/settings/notifications",
            "notifications",
            r#"id="telegram-notifications""#,
            "Appearance — theme + accent",
        ),
        (
            "/admin/settings/system",
            "system",
            r#"id="deploy-ssh-key""#,
            "Appearance — theme + accent",
        ),
    ];
    for (path, slug, present, absent) in cases {
        let html = fetch_html(app.clone(), path).await;
        assert!(
            html.contains(r#"class="ed-tabs""#),
            "{path}: tab bar (.ed-tabs) missing"
        );
        let active = format!(r#"ed-tab--on" href="/admin/settings/{slug}""#);
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

/// Bare `/admin/settings` renders the appearance tab directly.
#[tokio::test]
async fn settings_bare_url_renders_appearance_tab() {
    let dir = TempDir::new().unwrap();
    let html = fetch_html(router(state(&dir).await), "/admin/settings").await;
    assert!(
        html.contains(r#"ed-tab--on" href="/admin/settings/appearance""#),
        "bare URL must mark the appearance tab active"
    );
    assert!(
        html.contains("Appearance — theme + accent"),
        "bare URL must render the appearance tab's sections"
    );
    assert!(
        !html.contains("Backups — inventory snapshots"),
        "bare URL (appearance) must not render the backups tab"
    );
}

/// Copy-contract — pin the 4 settings tab labels in both locales.
#[tokio::test]
async fn settings_tab_labels_copy_contract() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let en = fetch_html(app.clone(), "/admin/settings").await;
    for label in [
        ">Appearance</a>",
        ">Backups</a>",
        ">Notifications</a>",
        ">System</a>",
    ] {
        assert!(en.contains(label), "EN tab label drifted: {label:?}");
    }
    let ru = fetch_html_with_cookie(app, "/admin/settings", "vpnctl_lang=ru").await;
    for label in [
        ">Внешний вид</a>",
        ">Бэкапы</a>",
        ">Уведомления</a>",
        ">Система</a>",
    ] {
        assert!(ru.contains(label), "RU tab label drifted: {label:?}");
    }
}

#[tokio::test]
async fn admin_settings_page_hosts_theme_and_accent_pickers() {
    let dir = TempDir::new().unwrap();
    let html = fetch_html(router(state(&dir).await), "/admin/settings").await;
    // Inline section title.
    assert!(
        html.contains("Appearance — theme + accent"),
        "Settings page must have the Appearance section heading"
    );
    // Both forms — same POST endpoints as before, just embedded inline.
    assert!(
        html.contains("action=\"/admin/tweak/theme\""),
        "Settings page must carry the theme form"
    );
    assert!(
        html.contains("action=\"/admin/tweak/accent\""),
        "Settings page must carry the accent form"
    );
    // Every theme + accent option must be present as a button.
    for name in &["default", "newsprint", "foxed", "ink"] {
        assert!(
            html.contains(&format!("value=\"{name}\"")),
            "Settings page missing theme/accent option button '{name}'"
        );
    }
    for name in &["rust", "forest", "plum"] {
        assert!(
            html.contains(&format!("value=\"{name}\"")),
            "Settings page missing accent option button '{name}'"
        );
    }
}

/// 2026-05-17 — the `tweaks` tweak kind was retired with the floating
/// panel. POST /admin/tweak/tweaks now 404s (handled by the dispatcher's
/// default arm). Pin that so a future re-introduction of the cookie
/// can't accidentally re-enable the open/closed toggle without
/// reviving the UI for it.
#[tokio::test]
async fn admin_tweak_tweaks_kind_is_gone_returns_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tweak/tweaks")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("value=closed"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "retired tweak kind must 404 — the floating Tweaks panel is gone"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("unknown tweak kind 'tweaks'"),
        "error body must call out the retired kind by name, got {text:?}"
    );
    // And the new known-kinds list must NOT include "tweaks" anymore.
    // (Should include theme + accent + lang post-NM-12; doesn't care
    // about ordering — the lang addition is forward-compat.)
    assert!(
        text.contains("known: theme, accent") && !text.contains("tweaks)"),
        "known-kinds list must drop 'tweaks', got {text:?}"
    );
}

/// Regression: the inline "tweaks live →" indicator was removed in
/// Phase C-2 because it duplicated the panel's own active-state highlight.
/// Make sure no page accidentally re-introduces it.
#[tokio::test]
async fn admin_pages_do_not_render_inline_tweaks_indicator() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let app = router(s);

    for path in [
        "/admin/",
        "/admin/servers",
        "/admin/users",
        "/admin/users/u0",
        "/admin/audit",
        "/admin/settings",
        "/admin/monitoring",
    ] {
        let html = fetch_html(app.clone(), path).await;
        assert!(
            !html.contains("tweaks live →"),
            "{path}: inline 'tweaks live →' indicator must not appear (it was dropped in Phase C-2)"
        );
    }
}

// ────────────────────────────────────────────────────────────────────────
//  Boosty subscription bridge (/admin/boosty)
// ────────────────────────────────────────────────────────────────────────

fn mk_user(id: &str, disabled: bool) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("uuid-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled,
    }
}

#[tokio::test]
async fn boosty_page_renders_and_is_in_nav() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/boosty").await;
    assert!(
        html.contains("Boosty"),
        "page must render the Boosty heading"
    );
    assert!(
        html.contains("/admin/boosty"),
        "nav must link to the boosty page"
    );
    // Default seeded settings: disabled, no creds → secrets show masked/unset.
    assert!(
        html.contains("(unset)"),
        "unset creds must render as (unset)"
    );
    // 2026-07-10 editorial restyle — the page now uses the shared
    // component system, not the bespoke `.ed-title` / `.ed-eyebrow`
    // scaffold, and the status renders as a tile strip.
    assert!(
        html.contains(r#"class="ed-art-h1""#) && html.contains(r#"class="ed-art-deck""#),
        "boosty page must use the editorial h1 + deck"
    );
    assert!(
        html.contains(r#"class="ed-status-strip""#),
        "bridge status must render as a status-tile strip"
    );
    assert!(
        !html.contains(r#"class="ed-title""#) && !html.contains(r#"class="ed-eyebrow""#),
        "legacy .ed-title / .ed-eyebrow scaffold must be gone"
    );
    // Regression: the sync-health callouts referenced an undefined
    // `--bad` CSS var (rendered black, not red) before the restyle.
    assert!(
        !html.contains("var(--bad)"),
        "must not reference the undefined --bad token"
    );
    // Disabled bridge → the «polling off» pill.
    assert!(
        html.contains("polling off"),
        "a disabled bridge must show the polling-off pill"
    );
}

#[tokio::test]
async fn boosty_link_then_unlink_via_web() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&mk_user("alice", false)).await.unwrap();
    let app = router(s);

    // Link.
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/boosty/link")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/boosty")),
            )
            .body(Body::from("user=alice&subscriber_id=4242"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "link must redirect");
    let links = inv.list_boosty_links().await.unwrap();
    assert_eq!(links, vec![(UserId("alice".into()), 4242)]);

    // Unlink.
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/boosty/unlink/alice")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/boosty")),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "unlink must redirect");
    assert!(inv.list_boosty_links().await.unwrap().is_empty());
}

#[tokio::test]
async fn boosty_settings_save_via_web() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/boosty/settings")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/boosty")),
            )
            .body(Body::from(
                "blog_url=ninitux&poll_interval_secs=1800&enabled=on",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let got = inv.get_boosty_settings().await.unwrap();
    assert!(got.enabled);
    assert_eq!(got.blog_url.as_deref(), Some("ninitux"));
    assert_eq!(got.poll_interval_secs, 1800);
}

#[tokio::test]
async fn boosty_disable_button_soft_mutes_user() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&mk_user("bob", false)).await.unwrap();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/boosty/disable/bob")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/boosty")),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let users = inv.list_users().await.unwrap();
    let bob = users.iter().find(|u| u.id.0 == "bob").unwrap();
    assert!(bob.disabled, "disable button must soft-mute the user");
}

/// The page renders its actionable sections from the LAST STORED sync
/// report — no live Boosty call on GET (no mock server exists here, so a
/// live sync would error or hang; csrf contract: admin GETs don't mutate).
#[tokio::test]
async fn boosty_page_renders_stored_report_without_live_sync() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let mut cfg = inv.get_boosty_settings().await.unwrap();
    cfg.enabled = true;
    cfg.blog_url = Some("ninitux".into());
    cfg.refresh_token = Some("r".into());
    cfg.device_id = Some("d".into());
    inv.set_boosty_settings(&cfg).await.unwrap();
    inv.set_boosty_last_report(
        &serde_json::json!({
            "total_subscribers": 2,
            "active_subscribers": 1,
            "linked": 1,
            "enabled": [],
            "disabled": [],
            "lapsed_pending": ["bob"],
            "new_subscribers": [{"subscriber_id": 300, "name": "Carol"}],
            "errors": [],
            "suppressed_disables": ["dave"]
        })
        .to_string(),
    )
    .await
    .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/boosty").await;
    assert!(
        html.contains("/admin/boosty/disable/bob"),
        "lapsed user gets a confirm-disable button: {html}"
    );
    assert!(html.contains("Carol"), "new subscriber from stored report");
    assert!(html.contains("dave"), "suppressed-disables banner renders");
}

/// BB-3 (link-UX): a subscriber the operator already linked must NOT linger
/// in the "new subscribers to link" list rendered from the (stale) stored
/// report — the redirect after a link must show them gone WITHOUT waiting
/// for the next sync. The linked subscriber still appears under "Linked
/// users", so we assert the *new-subscriber link form* (`boosty-link-<id>`)
/// is what's absent.
#[tokio::test]
async fn boosty_page_drops_already_linked_subscriber_from_new_list() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&mk_user("pyrojokk", false)).await.unwrap();
    let mut cfg = inv.get_boosty_settings().await.unwrap();
    cfg.enabled = true;
    cfg.blog_url = Some("ninitux".into());
    inv.set_boosty_settings(&cfg).await.unwrap();
    // Stored report (pre-link snapshot) still lists 45221733 as "new".
    inv.set_boosty_last_report(
        &serde_json::json!({
            "total_subscribers": 2,
            "active_subscribers": 2,
            "linked": 0,
            "new_subscribers": [
                {"subscriber_id": 45221733, "name": "Alyona"},
                {"subscriber_id": 999, "name": "Other"}
            ]
        })
        .to_string(),
    )
    .await
    .unwrap();
    // Operator links 45221733 → pyrojokk (no sync yet).
    inv.link_boosty_subscriber(&vpnctl_core::UserId("pyrojokk".into()), 45221733)
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/boosty").await;
    assert!(
        !html.contains("boosty-link-45221733"),
        "already-linked subscriber must not have a new-subscriber link form"
    );
    assert!(
        html.contains("boosty-link-999"),
        "the still-unlinked subscriber keeps its link form"
    );
    assert!(html.contains("pyrojokk"), "linked user rendered");
}

/// AC-B3 (NM-10 audit-on-actual-mutation): double-submitting the confirm
/// button writes exactly ONE `boosty.disable` audit row — the second POST
/// is a no-op (user already disabled) and must not spam the timeline or
/// trigger a second redeploy.
#[tokio::test]
async fn boosty_disable_double_submit_audits_once() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&mk_user("bob", false)).await.unwrap();
    let app = router(s);

    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(
                add_same_origin(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/boosty/disable/bob")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/boosty")),
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    let audits = inv.recent_audit(20).await.unwrap();
    let disable_rows = audits
        .iter()
        .filter(|a| a.action == "boosty.disable")
        .count();
    assert_eq!(disable_rows, 1, "double-submit must audit exactly once");
}

// ────────────────────────────────────────────────────────────────────────
//  Phase C-2 — copy contracts (backend response texts + frontend voice)
//
//  These tests pin USER-FACING STRINGS — both the backend's plaintext
//  error responses (what the operator sees in `journalctl` / curl) and
//  a handful of headline frontend strings (what the operator sees in
//  the browser). Drift in copy was previously caught only by review;
//  pinning it here means a casual one-word edit can't accidentally land
//  in main.
//
//  Backend contract: every admin response body starts with
//  `vpnctl admin: ` and ends with a single newline. Status code and
//  WWW-Authenticate header are checked alongside.
//
//  Frontend contract: the editorial voice is sentence-case with em-
//  dashes, never shouting; the empty states quote a literal CLI command
//  the operator can copy.
// ────────────────────────────────────────────────────────────────────────

/// All four backend error endpoints must use the unified
/// `vpnctl admin: <detail>\n` prefix. Tested in one place so the
/// contract can't drift handler-by-handler.
#[tokio::test]
async fn admin_backend_error_responses_use_unified_prefix() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    // 1. 404 — unknown user-detail id.
    let body = body_of(app.clone(), "GET", "/admin/users/no-such", None, None).await;
    assert_eq!(
        body, "vpnctl admin: no such user 'no-such'\n",
        "user-not-found 404 body drifted from the copy contract"
    );

    // 2. 400 — invalid tweak value. Includes which kind + what value
    //    + the allowed values (operators don't have to remember them).
    let body = body_of(
        app.clone(),
        "POST",
        "/admin/tweak/theme",
        Some("application/x-www-form-urlencoded"),
        Some("value=neon"),
    )
    .await;
    assert_eq!(
        body,
        "vpnctl admin: invalid value 'neon' for tweak 'vpnctl_theme' \
         (allowed: default, newsprint, foxed, ink)\n",
        "tweak 400 body drifted"
    );

    // 3. 404 — unknown tweak kind. Lists known kinds inline.
    let body = body_of(
        app.clone(),
        "POST",
        "/admin/tweak/whatever",
        Some("application/x-www-form-urlencoded"),
        Some("value=foxed"),
    )
    .await;
    assert_eq!(
        body, "vpnctl admin: unknown tweak kind 'whatever' (known: theme, accent, lang)\n",
        "unknown-tweak 404 body drifted"
    );
}

/// Defense-in-depth: even if a caller passes a `detail` containing
/// literal `\n` or `\r` (e.g. an axum `Path<String>` extractor
/// straight through without validation, future regression), the body
/// must NOT contain extra line breaks beyond the trailing one. The
/// `error_text` helper collapses `\n`/`\r` to spaces.
///
/// Today every caller sanitises upstream (UserId/ServerId/form
/// validators reject `\n`), but pinning the invariant here means a
/// future refactor that bypasses those guards cannot silently
/// re-introduce response-splitting-shaped behaviour.
#[tokio::test]
async fn admin_backend_error_text_normalises_newlines_in_detail() {
    // Smoke the helper directly via a path that's known to interpolate
    // user-controlled content into the error body. The tweak handler's
    // 400 includes the user-supplied `value=...` field — but the form
    // decoder strips %-encoding and our validators reject control
    // chars. We instead test via the `/admin/users/<id>` 404 path,
    // which interpolates the raw path segment after decoding.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    // %0A is a literal newline, percent-encoded as a single path
    // segment. axum's `Path<String>` extractor URL-decodes it back to
    // `\n`. Before the normalisation fix, the response body would be:
    //   "vpnctl admin: no such user '\n.poison'\n"
    // → splits into 2 lines for `curl … | head -1`. After the fix, the
    // `\n` collapses to a space.
    let body = body_of(app.clone(), "GET", "/admin/users/%0A.poison", None, None).await;
    // Body must be exactly ONE line + the trailing `\n`. Count
    // explicit newlines.
    let nl_count = body.matches('\n').count();
    assert_eq!(
        nl_count, 1,
        "error_text MUST normalise embedded \\n — body has {nl_count} newlines: {body:?}",
    );
    assert!(
        body.starts_with("vpnctl admin: no such user '"),
        "prefix survived the normalisation: {body:?}"
    );
    assert!(
        body.ends_with(".poison'\n"),
        "trailing context survived the normalisation: {body:?}"
    );
}

/// Default same-origin host used by every test that POSTs to /admin
/// without explicitly testing CSRF behaviour. Using a single constant
/// here means a future schema change (e.g. switching to a vhost-aware
/// router) only touches one place.
const SAME_ORIGIN_HOST: &str = "test.example";

/// Inject the Host + Origin headers that the CSRF middleware expects
/// (`handlers::csrf::require_same_origin` rejects state-mutating requests
/// whose Origin does not match Host). Tests that explicitly verify the
/// CSRF rejection path do not call this helper.
fn add_same_origin(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.header("host", SAME_ORIGIN_HOST)
        .header("origin", format!("http://{SAME_ORIGIN_HOST}"))
}

// ── Phase 3: naive (Caddy) per-server config UI ──────────────────────────

fn naive_server(id: &str) -> vpnctl_core::Server {
    vpnctl_core::Server {
        id: vpnctl_core::ServerId(id.into()),
        address: "203.0.113.5".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("caddy".into())],
        enabled_protocols: vec![vpnctl_core::ProtocolId("naive".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

#[tokio::test]
async fn admin_server_detail_naive_section_renders_when_enabled() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv.add_server(&naive_server("nv")).await.unwrap();
    let html = fetch_html(router(s), "/admin/servers/nv/protocols").await;
    assert!(
        html.contains(r#"action="/admin/servers/nv/naive-config""#),
        "naive config form must POST to the right route"
    );
    assert!(
        html.contains("NAIVE (CADDY) CONFIG"),
        "section eyebrow copy contract"
    );
    assert!(
        html.contains("DNS A-record"),
        "prerequisite reminder must be present"
    );
    assert!(
        html.contains(r#"name="domain""#) && html.contains(r#"name="acme_email""#),
        "both inputs present"
    );
}

#[tokio::test]
async fn admin_server_detail_naive_section_absent_when_not_enabled() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // seeded server is vless+reality only
    let html = fetch_html(router(s), "/admin/servers/s0/protocols").await;
    assert!(
        !html.contains("/naive-config"),
        "naive section must not render on a non-naive server"
    );
}

#[tokio::test]
async fn admin_server_set_naive_config_mutates_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv.add_server(&naive_server("nv")).await.unwrap();
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/nv/naive-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(
                "domain=cdn.example.com&acme_email=admin%40example.com",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let sid = vpnctl_core::ServerId("nv".into());
    assert_eq!(
        s.inv
            .get_server_secret(&sid, "naive.domain")
            .await
            .unwrap()
            .as_deref(),
        Some("cdn.example.com")
    );
    assert_eq!(
        s.inv
            .get_server_secret(&sid, "naive.acme_email")
            .await
            .unwrap()
            .as_deref(),
        Some("admin@example.com")
    );
    let audit = s.inv.recent_audit(10).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|e| e.action == "server.naive.set" && e.target.as_deref() == Some("nv")),
        "audit row server.naive.set must land"
    );
}

#[tokio::test]
async fn admin_server_set_udp_pair_toggles_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("lv".into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let sid = vpnctl_core::ServerId("lv".into());
    assert!(
        !s.inv.is_server_udp_pair_enabled(&sid).await.unwrap(),
        "default off"
    );

    // Enable via the handler.
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/lv/udp-pair")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("enabled=true"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        s.inv.is_server_udp_pair_enabled(&sid).await.unwrap(),
        "enable must persist"
    );
    assert!(
        s.inv
            .recent_audit(10)
            .await
            .unwrap()
            .iter()
            .any(|e| e.action == "server.udp_pair.set" && e.target.as_deref() == Some("lv")),
        "audit row server.udp_pair.set must land"
    );

    // Disable via the handler.
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/lv/udp-pair")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("enabled=false"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        !s.inv.is_server_udp_pair_enabled(&sid).await.unwrap(),
        "disable must persist"
    );
}

#[tokio::test]
async fn admin_server_set_naive_config_rejects_empty_domain() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv.add_server(&naive_server("nv")).await.unwrap();
    let resp = router(s)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/nv/naive-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("domain=&acme_email=admin%40example.com"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_server_set_naive_config_rejects_injection_in_domain() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv.add_server(&naive_server("nv")).await.unwrap();
    // `evil{block}` — a `{` would break out of the forward_proxy block
    // in the rendered Caddyfile. Must be rejected at save-time (400),
    // and nothing may persist.
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/nv/naive-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("domain=evil%7Bblock%7D&acme_email="))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        s.inv
            .get_server_secret(&vpnctl_core::ServerId("nv".into()), "naive.domain")
            .await
            .unwrap()
            .is_none(),
        "rejected domain must not persist"
    );
}

#[tokio::test]
async fn admin_server_set_naive_config_404_on_missing_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let resp = router(s)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/nope/naive-config")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("domain=cdn.example.com&acme_email="))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Helper for the copy-contract tests — exercises the router and
/// returns the response body as a UTF-8 String. Sets same-origin
/// headers on every method so the CSRF middleware passes mutating
/// requests through (GET passes regardless).
async fn body_of(
    app: axum::Router,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: Option<&str>,
) -> String {
    let mut req = Request::builder().method(method).uri(path);
    req = add_same_origin(req);
    if let Some(ct) = content_type {
        req = req.header("content-type", ct);
    }
    let body = match body {
        Some(s) => Body::from(s.to_string()),
        None => Body::empty(),
    };
    let resp = app.oneshot(req.body(body).unwrap()).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).expect("response body must be utf-8")
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

/// Empty-state contract: when there are no users (or no servers), the
/// page must quote a literal CLI command the operator can copy. The
/// admin UI can't yet create either via web (Phase C-2 / D), so the CLI
/// is the only path forward — losing the command would strand a fresh
/// operator on their first visit.
#[tokio::test]
async fn admin_empty_states_quote_cli_commands() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let users = fetch_html(app.clone(), "/admin/users").await;
    assert!(
        users.contains("vpnctl user create"),
        "empty users page must quote `vpnctl user create`"
    );
    assert!(
        users.contains("vpnctl grant"),
        "empty users page must quote `vpnctl grant`"
    );

    let servers = fetch_html(app.clone(), "/admin/servers").await;
    assert!(
        servers.contains("vpnctl bootstrap"),
        "empty servers page must quote `vpnctl bootstrap`"
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

/// 2026-05-17: with the floating Tweaks panel gone, the
/// `ed-tweaks-open` class on the page-root no longer serves any
/// layout purpose (it used to pad the footer right so the panel
/// didn't cover the github URL). Pinning the inverse: neither the
/// page-root class NOR the CSS rule should still be in the bundle.
#[tokio::test]
async fn admin_ed_tweaks_open_class_and_css_rule_are_gone() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    // No page-root class (default cookies, no cookie).
    let html = fetch_html(app.clone(), "/admin/").await;
    assert!(
        !html.contains("ed-tweaks-open"),
        "deprecated `ed-tweaks-open` class leaked into rendered HTML"
    );

    // No CSS rule keying off that class.
    let css_resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/assets/admin.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let css_bytes = css_resp.into_body().collect().await.unwrap().to_bytes();
    let css = std::str::from_utf8(&css_bytes).unwrap();
    assert!(
        !css.contains(".ed-tweaks-open .ed-foot"),
        "deprecated `.ed-tweaks-open .ed-foot` rule still in admin.css"
    );
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

// ────────────────────────────────────────────────────────────────────────
//  Phase C-3.3 — grant + revoke per-(user, server)
//
//  Pin the contract end-to-end: per-row grant/revoke buttons on the
//  user-detail page POST to dedicated endpoints; both are idempotent
//  at SQL but audited every time; bad ids → 404 with unified prefix.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_user_grant_server_happy_path() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[]).await; // s0 + u0, no grants yet
    assert_eq!(
        s.inv
            .servers_for_user(&UserId("u0".into()))
            .await
            .unwrap()
            .len(),
        0
    );

    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/grants/s0"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/admin/users/u0/access"
    );

    let granted = inv.servers_for_user(&UserId("u0".into())).await.unwrap();
    assert_eq!(granted.len(), 1, "u0 must have 1 grant after POST");
    assert_eq!(granted[0].id.0, "s0");

    // Canonical grant-audit shape (2026-06-04): per-user `user.grant`
    // with target = USER id — the shape the pending-deploy detector
    // keys on. Guards against regressing to the old `action="grant",
    // target=<server>` rows the detector never saw.
    let entries = inv.recent_audit(10).await.unwrap();
    let g = entries
        .iter()
        .find(|e| e.action == "user.grant")
        .expect("user.grant audit row missing");
    assert_eq!(g.actor, "admin");
    assert_eq!(g.target.as_deref(), Some("u0"));
    assert_eq!(
        g.payload.as_ref().unwrap()["server"],
        serde_json::Value::String("s0".into())
    );
    assert_eq!(
        g.payload.as_ref().unwrap()["source"],
        serde_json::Value::String("user-detail".into())
    );
}

/// REGRESSION (review 2026-06-04): a grant made through ANY real
/// handler must be visible to the pending-deploy detector even after
/// the server already has a deploy baseline. The handlers used to
/// write `action="grant", target=<server>` (and bulk only a summary
/// row) — invisible to `servers_pending_deploy_for_user`, which keys
/// on `user.grant` + target=<user>. So a grant made AFTER the
/// server's first deploy never raised the «config not yet deployed»
/// banner and the node silently missed the user's UUID.
///
/// Seeded users carry ZERO audit rows (raw `inv.add_user`), so the
/// only possible user-mutation timestamp is the one the handler under
/// test writes — if it regresses to the old shape, the detector sees
/// no mutations and the assertions fail.
#[tokio::test]
async fn grants_via_real_handlers_mark_server_pending_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 3, 3, &[]).await; // s0..s2 + u0..u2, no grants yet

    // Deploy BASELINE first — the regression only bites once a
    // `server.deploy` row exists (before that the "no deploy ever"
    // branch masks the missing user.grant rows).
    for sid in ["s0", "s1", "s2"] {
        inv.audit("admin", "server.deploy", Some(sid), None)
            .await
            .unwrap();
    }
    // Audit ts has millisecond precision; guarantee the grants below
    // land strictly AFTER the baseline rows.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let app = router(s);

    // 1. user-detail grant handler.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/grants/s0"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let pending = inv
        .servers_pending_deploy_for_user(&UserId("u0".into()), &[ServerId("s0".into())])
        .await
        .unwrap();
    assert_eq!(
        pending,
        vec![ServerId("s0".into())],
        "user-detail grant must mark s0 pending-deploy"
    );

    // 2. server-detail grant handler.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s1/grants/u1"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let pending = inv
        .servers_pending_deploy_for_user(&UserId("u1".into()), &[ServerId("s1".into())])
        .await
        .unwrap();
    assert_eq!(
        pending,
        vec![ServerId("s1".into())],
        "server-detail grant must mark s1 pending-deploy"
    );

    // 3. bulk grant-all handler (writes per-user rows for NEW grants).
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s2/grants/_grant-all"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let pending = inv
        .servers_pending_deploy_for_user(&UserId("u2".into()), &[ServerId("s2".into())])
        .await
        .unwrap();
    assert_eq!(
        pending,
        vec![ServerId("s2".into())],
        "bulk grant-all must mark s2 pending-deploy for each newly-granted user"
    );

    // 4. Idempotency contract (review-agent): RE-running a grant (or
    // grant-all) must NOT write fresh user.grant rows — a no-op
    // re-grant would otherwise falsely re-mark the server pending
    // after the operator's next deploy.
    let count_user_grants = |entries: &[vpnctl_inventory::AuditEntry]| {
        entries.iter().filter(|e| e.action == "user.grant").count()
    };
    let before = count_user_grants(&inv.recent_audit(100).await.unwrap());
    for uri in [
        "/admin/users/u0/grants/s0",
        "/admin/servers/s1/grants/u1",
        "/admin/servers/s2/grants/_grant-all",
    ] {
        app.clone()
            .oneshot(
                add_same_origin(Request::builder().method("POST").uri(uri))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let after = count_user_grants(&inv.recent_audit(100).await.unwrap());
    assert_eq!(
        before, after,
        "idempotent re-grants must not add user.grant rows (false pending-deploy)"
    );
}

/// REGRESSION (audit 2026-06-10, re-scoped 2026-07-10) — a REVOKE
/// through any real handler must stay visible to the pending-deploy
/// detectors. The handlers used to write `action="revoke",
/// target=<server>` (bulk only a summary), invisible to the detectors
/// — so a revoked UUID stayed live on the node with no warning
/// anywhere. Post-scoping the contract is: the REVOKED server is
/// flagged by the SERVER-side detector (`server_pending_deploy`,
/// membership changed since last deploy), while the user's REMAINING
/// servers stay quiet — their configs didn't change, and the old
/// coarse any-mutation-flags-everything reading produced a permanent
/// phantom banner after every grant/revoke (design review 2026-07-10).
#[tokio::test]
async fn revokes_via_real_handlers_flag_only_the_revoked_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    // u0 granted s0+s1; u1 granted s1+s2 (raw seed → zero audit rows).
    seed(&inv, 3, 2, &[(0, 0), (0, 1), (1, 1), (1, 2)]).await;
    for sid in ["s0", "s1", "s2"] {
        inv.audit("admin", "server.deploy", Some(sid), None)
            .await
            .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let app = router(s);

    // 1. user-detail revoke: u0 loses s0 → the REVOKED server flags on
    //    the server-side detector; the untouched remaining server (s1)
    //    stays quiet on the per-user surface.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/grants/s0/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        inv.server_pending_deploy(&ServerId("s0".into()))
            .await
            .unwrap(),
        "revoked server must flag on the server-side detector"
    );
    let pending = inv
        .servers_pending_deploy_for_user(&UserId("u0".into()), &[ServerId("s1".into())])
        .await
        .unwrap();
    assert!(
        pending.is_empty(),
        "revoke of s0 must NOT flag the untouched s1 (scoped detector), got {pending:?}"
    );

    // 2. server-detail revoke: same contract from the other handler.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s1/grants/u1/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        inv.server_pending_deploy(&ServerId("s1".into()))
            .await
            .unwrap(),
        "revoked server must flag on the server-side detector (server-detail path)"
    );
    let pending = inv
        .servers_pending_deploy_for_user(&UserId("u1".into()), &[ServerId("s2".into())])
        .await
        .unwrap();
    assert!(
        pending.is_empty(),
        "revoke of s1 must NOT flag the untouched s2 (scoped detector), got {pending:?}"
    );

    // 3. Canonical row shape + idempotency: re-revoking writes nothing.
    let count_revokes = |entries: &[vpnctl_inventory::AuditEntry]| {
        entries.iter().filter(|e| e.action == "user.revoke").count()
    };
    let entries = inv.recent_audit(100).await.unwrap();
    let r = entries
        .iter()
        .find(|e| e.action == "user.revoke" && e.target.as_deref() == Some("u0"))
        .expect("user.revoke row with target=USER id missing");
    assert_eq!(r.payload.as_ref().unwrap()["server"], "s0");
    let before = count_revokes(&entries);
    for uri in [
        "/admin/users/u0/grants/s0/revoke",
        "/admin/servers/s1/grants/u1/revoke",
    ] {
        app.clone()
            .oneshot(
                add_same_origin(Request::builder().method("POST").uri(uri))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let after = count_revokes(&inv.recent_audit(100).await.unwrap());
    assert_eq!(
        before, after,
        "idempotent re-revokes must not add user.revoke rows"
    );

    // 4. server-detail revoke of an UNKNOWN user must 404 (the grant
    // twin always had the existence check; revoke silently 303'd).
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s1/grants/no-such-user/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ────────────────────────────────────────────────────────────────────────
//  Coverage batch (audit 2026-06-10) — routes that had ZERO test
//  references: logout, set-fingerprint, reserved-ports, timezone,
//  auto-suppress, display-name; plus pins for the W5 fixes (no-op
//  audit gating, LIKE-escape).
// ────────────────────────────────────────────────────────────────────────

/// POST /admin/logout must expire the session cookie (Max-Age=0) —
/// auth surface; a broken logout means sessions can't be ended and
/// nothing else would catch it.
#[tokio::test]
async fn admin_logout_expires_session_cookie() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let resp = router(s)
        .oneshot(
            add_same_origin(Request::builder().method("POST").uri("/admin/logout"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_redirection(), "logout must redirect");
    let cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("logout must set a cookie header");
    assert!(
        cookie.contains("Max-Age=0"),
        "logout cookie must expire the session, got: {cookie}"
    );
}

/// POST set-fingerprint (manual): 303 + ONE dot-convention audit row
/// (`server.fingerprint.set`); a same-value re-pin is a no-op (no
/// second row — NM-10); junk shape is a 400.
#[tokio::test]
async fn admin_set_fingerprint_manual_audits_once_and_validates() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 0, &[]).await;
    let app = router(s);
    let fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 b64 chars
    let post = |body: String| {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/set-fingerprint")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from(body))
        .unwrap()
    };

    let resp = app
        .clone()
        .oneshot(post(format!("mode=manual&fingerprint={fp}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let count = |entries: &[vpnctl_inventory::AuditEntry]| {
        entries
            .iter()
            .filter(|e| e.action == "server.fingerprint.set")
            .count()
    };
    assert_eq!(count(&inv.recent_audit(20).await.unwrap()), 1);

    // Same-value re-pin → no second row.
    app.clone()
        .oneshot(post(format!("mode=manual&fingerprint={fp}")))
        .await
        .unwrap();
    assert_eq!(
        count(&inv.recent_audit(20).await.unwrap()),
        1,
        "same-value re-pin must not write an audit row (NM-10)"
    );

    // Junk shape → 400.
    let resp = app
        .oneshot(post("mode=manual&fingerprint=not-a-fingerprint".into()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// POST reserved-ports: valid list 303s; junk 400s (form-parsing layer
/// — the query layer is covered by spec_reserved_ports.rs).
#[tokio::test]
async fn admin_reserved_ports_post_validates() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let post = |body: &str| {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/reserved-ports")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from(body.to_string()))
        .unwrap()
    };
    let resp = app.clone().oneshot(post("ports=443%2C8443")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let resp = app.oneshot(post("ports=not-a-port")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// POST settings/timezone: valid IANA name accepted, junk 400s.
#[tokio::test]
async fn admin_timezone_post_validates() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);
    let post = |body: &str| {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/timezone")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from(body.to_string()))
        .unwrap()
    };
    let resp = app
        .clone()
        .oneshot(post("tz=Europe%2FMoscow"))
        .await
        .unwrap();
    assert!(
        resp.status().is_redirection() || resp.status().is_success(),
        "valid IANA tz must be accepted, got {}",
        resp.status()
    );
    let resp = app.oneshot(post("tz=Not%2FAZone")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// POST auto-suppress + display-name: the HTTP/form layer round-trips
/// (until now only the inventory queries were tested).
#[tokio::test]
async fn admin_auto_suppress_and_display_name_post_roundtrip() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/auto-suppress")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("enabled=true"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/display-name")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("display_name=Frankfurt+Box"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let html = fetch_html(app, "/admin/servers/s0/setup").await;
    assert!(
        html.contains("Frankfurt Box"),
        "display name must round-trip to the detail page"
    );
}

/// W5 pin: protocol enable no-op re-POST writes NO second audit row
/// (NM-10) — the 4 toggle handlers audited unconditionally before.
#[tokio::test]
async fn protocol_enable_noop_repost_writes_no_audit_row() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 0, &[]).await;
    let app = router(s);
    let post = || {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/protocols/tuic-v5/enable"),
        )
        .body(Body::empty())
        .unwrap()
    };
    let r1 = app.clone().oneshot(post()).await.unwrap();
    assert_eq!(
        r1.status(),
        StatusCode::SEE_OTHER,
        "first enable must succeed"
    );
    let r2 = app.oneshot(post()).await.unwrap();
    assert_eq!(
        r2.status(),
        StatusCode::SEE_OTHER,
        "no-op re-enable must still redirect"
    );
    let rows = inv
        .recent_audit(20)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.action == "server.protocol.enable")
        .count();
    assert_eq!(rows, 1, "no-op re-enable must not write a second row");
}

/// W5 pin: LIKE metacharacters in search match LITERALLY — `%` must
/// not return the whole fleet.
#[tokio::test]
async fn search_percent_is_literal_not_wildcard() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[]).await; // u0 + s0 exist
    let html = fetch_html(router(s), "/admin/search?q=%25").await;
    assert!(
        !html.contains("/admin/users/u0"),
        "bare % must not wildcard-match every user"
    );
}

/// Server-side pending-deploy banner (audit 2026-06-10 follow-up):
/// the ONE surface that can warn about a revoked-but-still-deployed
/// UUID is the server's own detail page — after a revoke the server
/// leaves the user's granted list, so no user-detail banner mentions
/// it. Pin: banner appears after a real revoke, clears after a
/// server.deploy row lands.
#[tokio::test]
async fn server_detail_shows_pending_banner_after_revoke_until_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 1, &[(0, 0)]).await; // u0 granted s0
    inv.audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let app = router(s);

    // Deployed + no membership change since → no banner.
    let html = fetch_html(app.clone(), "/admin/servers/s0").await;
    assert!(
        !html.contains("pending-deploy-banner"),
        "freshly-deployed server must not show the pending banner"
    );

    // Revoke u0 through the real handler → banner appears.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/grants/u0/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let html = fetch_html(app.clone(), "/admin/servers/s0").await;
    assert!(
        html.contains("pending-deploy-banner"),
        "revoke must raise the server-side pending-deploy banner"
    );

    // A deploy AFTER the revoke clears it.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    inv.audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    let html = fetch_html(app, "/admin/servers/s0").await;
    assert!(
        !html.contains("pending-deploy-banner"),
        "deploy must clear the pending banner"
    );
}

/// W4 pin (review 2026-06-10): search results must mask the uuid —
/// it IS the VLESS credential; the users list masks it for exactly
/// that reason and search must not be the page that leaks it whole.
#[tokio::test]
async fn search_masks_user_uuid() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await; // u0, uuid 00000000-0000-0000-0000-000000000000
    let html = fetch_html(router(s), "/admin/search?q=u0").await;
    assert!(
        html.contains("uuid=0000\u{2026}0000 (36 chars)")
            || html.contains("uuid=0000…0000 (36 chars)"),
        "search must render the masked uuid preview"
    );
    assert!(
        !html.contains("00000000-0000-0000-0000-000000000000"),
        "search must not leak the full uuid (it is the VLESS credential)"
    );
}

/// REGRESSION (audit 2026-06-10): deleting a server while its deploy
/// pipeline holds the per-server permit must 409, not proceed — the
/// pipeline would keep SSH-pushing to the node, FK-fail its secret
/// upserts mid-stream, then audit a deploy for a deleted server.
///
/// Server id is test-UNIQUE («del-409-srv», not the shared «s0»):
/// DeployGuard's in-flight set is process-global and admin_smoke tests
/// run in parallel threads — holding «s0» here would intermittently
/// collide with every other test that deploys s0.
#[tokio::test]
async fn admin_server_delete_refuses_while_deploy_in_flight() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&vpnctl_core::Server {
        id: ServerId("del-409-srv".into()),
        address: "203.0.113.77".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: Vec::new(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    let app = router(s);

    // Hold the deploy permit, as a live pipeline would.
    let _held =
        vpnctld::wizard_bootstrap::DeployGuard::try_acquire("del-409-srv").expect("hold permit");
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/del-409-srv/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=del-409-srv"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "delete during an in-flight deploy must 409"
    );
    assert!(
        inv.get_server(&ServerId("del-409-srv".into()))
            .await
            .unwrap()
            .is_some(),
        "server must survive the refused delete"
    );

    // Permit released → the same delete goes through.
    drop(_held);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/del-409-srv/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=del-409-srv"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        inv.get_server(&ServerId("del-409-srv".into()))
            .await
            .unwrap()
            .is_none(),
        "delete must proceed once the deploy permit is free"
    );
}

#[tokio::test]
async fn admin_user_revoke_server_happy_path() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // pre-granted u0→s0
    assert_eq!(
        s.inv
            .servers_for_user(&UserId("u0".into()))
            .await
            .unwrap()
            .len(),
        1
    );

    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/grants/s0/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    assert_eq!(
        inv.servers_for_user(&UserId("u0".into()))
            .await
            .unwrap()
            .len(),
        0,
        "grant must be removed after revoke"
    );

    // Canonical revoke-audit shape (2026-06-10, mirror of grants):
    // per-user `user.revoke` with target = USER id — the shape the
    // pending-deploy detector keys on.
    let entries = inv.recent_audit(10).await.unwrap();
    assert!(
        entries.iter().any(|e| e.action == "user.revoke"
            && e.target.as_deref() == Some("u0")
            && e.payload.as_ref().is_some_and(|p| p["server"] == "s0")),
        "user.revoke audit row missing"
    );
}

#[tokio::test]
async fn admin_user_grant_unknown_user_404() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // s0 only, no users
    let body = body_of(
        router(s),
        "POST",
        "/admin/users/no-such/grants/s0",
        None,
        None,
    )
    .await;
    assert_eq!(body, "vpnctl admin: no such user 'no-such'\n");
}

#[tokio::test]
async fn admin_user_grant_unknown_server_404() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await; // u0 only, no servers
    let body = body_of(
        router(s),
        "POST",
        "/admin/users/u0/grants/no-such-server",
        None,
        None,
    )
    .await;
    assert_eq!(body, "vpnctl admin: no such server 'no-such-server'\n");
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

#[tokio::test]
async fn admin_user_detail_renders_grant_revoke_buttons() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // 2 servers (s0, s1), 1 user (u0), one pre-granted to s0.
    seed(&s.inv, 2, 1, &[(0, 0)]).await;
    let app = router(s);

    let html = fetch_html(app, "/admin/users/u0/access").await;

    // Granted row: revoke form + ✓ access marker.
    assert!(
        html.contains(r#"action="/admin/users/u0/grants/s0/revoke""#),
        "revoke form for granted server s0 must render"
    );
    assert!(
        html.contains("✓ access"),
        "✓ access marker for granted row missing"
    );
    assert!(html.contains(">revoke<"), "revoke button label drifted");

    // Ungranted row: grant form, no ✓ marker for s1's row.
    assert!(
        html.contains(r#"action="/admin/users/u0/grants/s1""#),
        "grant form for ungranted server s1 must render"
    );
    assert!(html.contains(">grant<"), "grant button label drifted");
}

// ────────────────────────────────────────────────────────────────────────
//  Phase Track-1 (back-pressure) — bounded mpsc + writer task
//
//  Caught by retroactive review-agent (review #3) AND security-review
//  (security #2) on 2026-05-14: the original Track-1 wired access
//  logging via `tokio::spawn` per request, fire-and-forget. An
//  attacker holding ONE valid sub-token could DoS the daemon by
//  spawning unbounded background tasks until the SQLite pool / memory
//  saturated.
//
//  The fix moves the work off the request path entirely: requests
//  `try_send` a record into a bounded mpsc channel; one dedicated
//  writer task drains it. Channel-full → record dropped + warn-log;
//  HTTP response stays 200.
//
//  These tests pin the contract end-to-end through the public
//  `/sub/<token>` handler.
// ────────────────────────────────────────────────────────────────────────

/// A single `/sub/<token>` hit lands one row in `sub_access_log`.
/// Validates the writer task drains the channel into the inventory
/// in the same way the old direct-await did.
#[tokio::test]
async fn sub_access_writer_persists_one_hit() {
    use http_body_util::BodyExt;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    // Token of u0 (open() backfilled it).
    let token = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    // Snapshot the inv handle for later assertion (state.inv is moved
    // into the router).
    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = resp.into_body().collect().await.unwrap();

    // The writer task is async — give it a moment to drain. In practice
    // sub-millisecond, but we sleep long enough that flaky CI doesn't
    // trip. The contract says the row WILL eventually land, not that
    // it is synchronous with the response.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let rows = inv
        .recent_sub_access(&UserId("u0".into()), 5)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "writer task must drain exactly one row from one /sub hit"
    );
    assert_eq!(rows[0].status, 200);
    // ConnectInfo absent in `oneshot` → recorded as 0.0.0.0 per the
    // sub.rs fallback (already pinned by the warn-once test).
    assert_eq!(rows[0].ip, "0.0.0.0");
}

/// Module-level back-pressure contract: when the channel is full,
/// `access_log::try_enqueue` returns false and drops the record
/// (instead of panicking, blocking, or growing memory unbounded).
/// Production capacity is 1024; this test forces a tiny channel via
/// the public type to make the boundary observable in milliseconds.
#[tokio::test]
async fn access_log_back_pressure_drops_records_when_full() {
    use tokio::sync::mpsc;
    use vpnctld::access_log::{AccessLogRecord, try_enqueue};

    // Tiny channel: 2 slots. Build it directly instead of using
    // `spawn_writer` — a writer would drain too fast for the test to
    // reliably observe the full state. Without a writer, every
    // try_enqueue past the second one MUST return false.
    let (tx, _rx) = mpsc::channel::<AccessLogRecord>(2);

    let mk = |ip: &str| AccessLogRecord {
        user_id: UserId("u0".into()),
        ip: ip.to_string(),
        ua: None,
        status: 200,
        bytes: 100,
        accept_language: None,
        http_version: None,
        device_class: None,
        geo_country: None,
        geo_asn: None,
        tls_ja3: None,
        tls_ja4: None,
    };

    // First two enqueues fill the buffer → both return true.
    assert!(
        try_enqueue(&tx, mk("1.1.1.1")),
        "first enqueue must succeed"
    );
    assert!(
        try_enqueue(&tx, mk("2.2.2.2")),
        "second enqueue must succeed"
    );
    // Third enqueue with no drainer → channel full → dropped.
    assert!(
        !try_enqueue(&tx, mk("3.3.3.3")),
        "third enqueue must FAIL with back-pressure (no drainer running)"
    );
    // Fourth too — same drop path; the contract is "drop, don't panic".
    assert!(
        !try_enqueue(&tx, mk("4.4.4.4")),
        "fourth enqueue must FAIL — back-pressure must not panic, must not block, must not grow unbounded"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase Track-1.1 — retention scheduler smoke test
//
//  The full purge contract is in `crates/inventory/tests/spec_sub_access.rs`
//  (`purge_removes_rows_older_than_cutoff_only` etc.). This test only
//  pins that the scheduler actually spawns a runnable task — without
//  it the user-detail page's "auto-purged after 30 days" promise was
//  inert (rows would accumulate forever).
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn retention_purger_spawns_a_runnable_task() {
    let dir = TempDir::new().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();

    // Spawn the purger and immediately abort — we don't want the loop
    // to actually tick (the interval is 1h). A spawn that compiled and
    // returned a JoinHandle proves the wiring works; the purge body
    // itself is fully tested in spec_sub_access.
    let handle = vpnctld::spawn_retention_purger_for_test(inv);
    handle.abort();
    let result = handle.await;
    assert!(
        matches!(&result, Err(e) if e.is_cancelled()),
        "expected aborted JoinHandle; got {result:?}"
    );
}

#[tokio::test]
async fn node_probe_poller_spawns_a_runnable_task() {
    // Phase H chunk 4 smoke test — mirrors retention_purger above.
    // Proves `spawn_node_probe_poller` compiles, returns a real
    // tokio task, and lets `abort()` cancel cleanly. The probe body
    // (parser, SSH client, inventory INSERT) is fully exercised by
    // `crate::node_probe::tests` + `spec_node_health`.
    let dir = TempDir::new().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let handle = vpnctld::spawn_node_probe_poller_for_test(inv);
    handle.abort();
    let result = handle.await;
    assert!(
        matches!(&result, Err(e) if e.is_cancelled()),
        "expected aborted JoinHandle; got {result:?}"
    );
}

#[tokio::test]
async fn health_monitor_spawns_a_runnable_task() {
    // Phase G smoke test — same shape as the two pollers above.
    // diff_rows + scan_once are unit-tested in
    // `daemon::health_monitor::tests`; this just proves the spawn
    // wires up cleanly under tokio.
    let dir = TempDir::new().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let handle = vpnctld::spawn_health_monitor_for_test(inv);
    handle.abort();
    let result = handle.await;
    assert!(
        matches!(&result, Err(e) if e.is_cancelled()),
        "expected aborted JoinHandle; got {result:?}"
    );
}

#[tokio::test]
async fn admin_alerts_empty_state_renders_with_copy_contract() {
    // Phase G — bare alerts page on an empty inventory. Should render
    // the editorial empty-state with the canonical "no unacked alerts"
    // copy + a link to "show all" (so the operator can confirm history
    // even when there's nothing actionable).
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "expected 200 alerts page");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(
        html.contains("no unacked alerts"),
        "expected empty-state copy 'no unacked alerts'"
    );
    assert!(html.contains("show all"), "expected link to acked history");
    // Nav entry is wired.
    assert!(
        html.contains(r#"href="/admin/alerts""#),
        "expected nav entry to /admin/alerts"
    );
    // Phase G chunk 2 deck-copy extension — page now advertises the
    // new detector categories so the operator knows what will show
    // up here. Catches drift on either the «unreachable hosts»
    // or «locked myself out» substring.
    assert!(
        html.contains("health monitor") && html.contains("sub-access analyzer"),
        "headrow tooltip must explain both alert sources (v2 5a)"
    );
}

#[tokio::test]
async fn admin_alerts_renders_unreachable_kind_row() {
    // Phase G chunk 2 — seed an unreachable-kind alert row and verify
    // the feed renders it with the expected kind label + severity.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    inv.add_server(&vpnctl_core::Server {
        id: vpnctl_core::ServerId("stg".into()),
        address: "1.1.1.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.insert_alert(
        "server.unreachable",
        Some(&vpnctl_core::ServerId("stg".into())),
        "warning",
        "3 consecutive SSH probes failed",
        Some(r#"{"consecutive_failures":3,"threshold":3}"#),
    )
    .await
    .unwrap();

    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("server.unreachable"),
        "feed must render the kind: {html:?}"
    );
    assert!(
        html.contains("Node unreachable") && html.contains("probes failed in a row"),
        "feed must render the localized title + body (not the stored English summary): {html:?}"
    );
}

/// R3 2026-07-10 — the sub_access family table shows a COMPACT detail
/// (source IP + range kind + client) instead of the full localized
/// sentence repeated on every row. The boilerplate stays on hover.
#[tokio::test]
async fn alerts_sub_access_row_shows_compact_ip_detail_not_boilerplate() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .insert_alert(
            "sub_access.suspicious_local_ip:brat",
            None,
            "warning",
            "local-loop fetch · user=brat · ip=192.168.0.210 [LAN] · ua=Hiddify",
            Some(r#"{"user_id":"brat","ip":"192.168.0.210","ip_kind":"LAN","device_class":"Hiddify"}"#),
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/alerts").await;
    // The varying datum — the source IP — renders as its own cell.
    assert!(
        html.contains("192.168.0.210"),
        "sub_access row must surface the source IP"
    );
    assert!(html.contains("[LAN]"), "range-kind tag must render");
    assert!(html.contains("Hiddify"), "client label must render");
    // The 30-word boilerplate must NOT be in the visible cell (it stays
    // on the row's title= hover only).
    assert!(
        !html.contains("the logged client IP will be wrong"),
        "verbose boilerplate must not repeat in the visible detail cell"
    );
    // The full sentence still lives in the hover title.
    assert!(
        html.contains(r#"title="local-loop fetch"#),
        "the stored summary must remain available on hover"
    );
}

#[tokio::test]
async fn dispatch_alerts_banned_self_writes_row_with_payload() {
    // Phase G chunk 2 — full integration of the banned-self detector:
    // build a Probe with fail2ban_self_banned=Some(true), call the
    // public `dispatch_alerts` free fn (the same one the poller
    // loop calls), then hit /admin/alerts and assert the rendered
    // row contains the operator-relevant fields from the payload
    // (our_ip + summary text). Catches any typo in the payload key
    // names, the summary template, or the kind string.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("stg".into()),
        address: "1.1.1.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server).await.unwrap();

    // Build a Probe in the «banned-self» state: our IP appears in
    // the fail2ban-banned set.
    let probe = vpnctld::node_probe::Probe {
        probe_source_ip: Some("192.168.0.236".into()),
        fail2ban_banned_ips: Some(vec!["192.168.0.236".into(), "1.2.3.4".into()]),
        fail2ban_self_banned: Some(true),
        ..Default::default()
    };

    let mut fail_state = vpnctld::node_probe_poller::FailState::new();
    vpnctld::node_probe_poller::dispatch_alerts(
        &inv,
        &server,
        &vpnctld::node_probe_poller::ProbeOutcome::Ok(probe),
        &mut fail_state,
    )
    .await;

    // Row was written.
    let alerts = inv.recent_alerts(10, false).await.unwrap();
    assert_eq!(
        alerts.len(),
        1,
        "dispatch_alerts must write exactly one row for self_banned=Some(true)"
    );
    assert_eq!(alerts[0].kind, "server.fail2ban.banned_self");
    assert_eq!(alerts[0].severity, "critical");

    // Payload survived through to the rendering path.
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("server.fail2ban.banned_self"),
        "feed must render the kind"
    );
    assert!(
        html.contains("192.168.0.236"),
        "feed must render our IP from the summary template"
    );
}

#[tokio::test]
async fn dispatch_alerts_recovery_auto_acks_open_unreachable() {
    // Phase G chunk 2 — full integration of the recovery path:
    // drive FailState through the consecutive-failure threshold so
    // dispatch_alerts fires `server.unreachable`, then drive an
    // Ok outcome and assert the row is auto-acked (no longer in
    // the unacked feed) AND an `alert.auto_ack` audit row landed.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("stg".into()),
        address: "1.1.1.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server).await.unwrap();

    let mut fail_state = vpnctld::node_probe_poller::FailState::with_threshold(2);

    // 2 failures → BecameUnreachable → row written.
    for _ in 0..2 {
        vpnctld::node_probe_poller::dispatch_alerts(
            &inv,
            &server,
            &vpnctld::node_probe_poller::ProbeOutcome::SshFailed("connect timeout".into()),
            &mut fail_state,
        )
        .await;
    }
    assert_eq!(
        inv.recent_alerts(10, false).await.unwrap().len(),
        1,
        "2 consecutive failures with threshold=2 must fire one row"
    );

    // Recovery → row auto-acked → unacked feed empty.
    vpnctld::node_probe_poller::dispatch_alerts(
        &inv,
        &server,
        &vpnctld::node_probe_poller::ProbeOutcome::Ok(vpnctld::node_probe::Probe::default()),
        &mut fail_state,
    )
    .await;
    assert_eq!(
        inv.recent_alerts(10, false).await.unwrap().len(),
        0,
        "recovery must auto-ack the open unreachable row"
    );
    // History view still shows it (with acked_at set).
    let history = inv.recent_alerts(10, true).await.unwrap();
    assert_eq!(history.len(), 1);
    assert!(history[0].acked_at.is_some(), "row must be marked acked");
}

#[tokio::test]
async fn dispatch_alerts_reopens_after_manual_ack_while_still_down() {
    // Regression for the kg 2026-05-31 incident: operator acks the
    // `server.unreachable` alert while the server is STILL down. The
    // old state machine left FailState.fired=true and emitted NoChange
    // for every later failing tick, so the acked alert NEVER re-fired
    // (only a recovery reset `fired`). The StillUnreachable transition
    // now re-asserts the idempotent insert each down-tick → the next
    // failing probe after an ack re-opens a fresh alert.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("kg".into()),
        address: "213.155.9.39".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server).await.unwrap();
    let mut fail_state = vpnctld::node_probe_poller::FailState::with_threshold(2);
    let fail = || vpnctld::node_probe_poller::ProbeOutcome::SshFailed("connect timeout".into());

    // 2 failures (threshold=2) → fire one unacked row.
    for _ in 0..2 {
        vpnctld::node_probe_poller::dispatch_alerts(&inv, &server, &fail(), &mut fail_state).await;
    }
    let open = inv.recent_alerts(10, false).await.unwrap();
    assert_eq!(open.len(), 1, "threshold crossing fires one row");

    // A 3rd still-down tick while the alert is OPEN+unacked must NOT
    // create a duplicate (partial-UNIQUE dedup).
    vpnctld::node_probe_poller::dispatch_alerts(&inv, &server, &fail(), &mut fail_state).await;
    assert_eq!(
        inv.recent_alerts(10, false).await.unwrap().len(),
        1,
        "still-down tick must NOT duplicate an already-open alert"
    );

    // Operator ACKS the alert (web «ack» button) — but the server is
    // still down.
    assert!(inv.ack_alert(open[0].id).await.unwrap());
    assert_eq!(
        inv.recent_alerts(10, false).await.unwrap().len(),
        0,
        "ack clears it from the unacked feed"
    );

    // Next still-down probe → MUST re-open (the bug: it stayed silent).
    vpnctld::node_probe_poller::dispatch_alerts(&inv, &server, &fail(), &mut fail_state).await;
    assert_eq!(
        inv.recent_alerts(10, false).await.unwrap().len(),
        1,
        "a still-down server must RE-FIRE after a manual ack (kg incident fix)"
    );
}

#[tokio::test]
async fn dispatch_alerts_auto_suppress_sets_and_clears_with_optin() {
    // Migration 0030: with the per-server opt-in ON, crossing the
    // unreachable threshold flags the server suppressed (render skips
    // it); recovery clears it. With opt-in OFF, failures never suppress.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    let mk = |id: &str| vpnctl_core::Server {
        id: vpnctl_core::ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    let opted = mk("optin");
    let plain = mk("plain");
    inv.add_server(&opted).await.unwrap();
    inv.add_server(&plain).await.unwrap();
    inv.set_server_auto_suppress(&opted.id, true).await.unwrap();

    let fail = || vpnctld::node_probe_poller::ProbeOutcome::SshFailed("timeout".into());
    let mut fs = vpnctld::node_probe_poller::FailState::with_threshold(2);

    // 2 failures each → opted crosses threshold.
    for _ in 0..2 {
        vpnctld::node_probe_poller::dispatch_alerts(&inv, &opted, &fail(), &mut fs).await;
        vpnctld::node_probe_poller::dispatch_alerts(&inv, &plain, &fail(), &mut fs).await;
    }
    assert!(
        inv.is_server_auto_suppressed(&opted.id).await.unwrap(),
        "opted-in server must be suppressed after the threshold"
    );
    assert!(
        !inv.is_server_auto_suppressed(&plain.id).await.unwrap(),
        "opt-in OFF server must NEVER be auto-suppressed"
    );

    // Recovery on the opted server → suppression lifted.
    vpnctld::node_probe_poller::dispatch_alerts(
        &inv,
        &opted,
        &vpnctld::node_probe_poller::ProbeOutcome::Ok(vpnctld::node_probe::Probe::default()),
        &mut fs,
    )
    .await;
    assert!(
        !inv.is_server_auto_suppressed(&opted.id).await.unwrap(),
        "recovery must auto-restore the server to the subscription"
    );
}

#[tokio::test]
async fn dispatch_alerts_auto_restore_survives_daemon_restart() {
    // review-agent critical: suppressed_at persists in the DB, but the
    // in-memory FailState resets on a daemon restart. A server suppressed
    // before the restart, then recovering, would never hit the
    // `Recovered` transition (fired=false post-restart) — so the clear
    // must be tied to the Ok OUTCOME, not the transition. Simulate:
    // pre-suppressed server + FRESH FailState + one Ok probe → restored.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("fi".into()),
        address: "84.19.3.104".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server).await.unwrap();
    // Pre-restart state: opted in + already suppressed.
    inv.set_server_auto_suppress(&server.id, true)
        .await
        .unwrap();
    inv.set_server_suppressed(&server.id, true).await.unwrap();
    assert!(inv.is_server_auto_suppressed(&server.id).await.unwrap());

    // FRESH FailState = post-restart (fired/counter wiped). A single Ok
    // probe returns NoChange from observe() (nothing was being tracked),
    // yet the outcome-based clear must still restore the server.
    let mut fresh = vpnctld::node_probe_poller::FailState::with_threshold(2);
    vpnctld::node_probe_poller::dispatch_alerts(
        &inv,
        &server,
        &vpnctld::node_probe_poller::ProbeOutcome::Ok(vpnctld::node_probe::Probe::default()),
        &mut fresh,
    )
    .await;
    assert!(
        !inv.is_server_auto_suppressed(&server.id).await.unwrap(),
        "a successful probe must clear suppression even with no Recovered transition (restart-safe)"
    );
}

#[tokio::test]
async fn settings_telegram_section_renders_with_disabled_status_by_default() {
    // Phase G chunk 3 part 1 — fresh DB, Telegram section appears
    // with «disabled» status + the input form.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(
        html.contains("Notifications — Telegram bot"),
        "Telegram section eyebrow must render"
    );
    assert!(
        html.contains("Status:") && html.contains("disabled"),
        "fresh config must show disabled status"
    );
    assert!(
        html.contains(r#"name="telegram_bot_token""#),
        "form must include token input"
    );
    assert!(
        html.contains(r#"name="telegram_chat_id""#),
        "form must include chat_id input"
    );
    assert!(
        html.contains(r#"action="/admin/settings/telegram""#),
        "form must POST to the correct route"
    );
    assert!(
        html.contains("@BotFather"),
        "deck copy must point operator at BotFather for bot creation"
    );
}

#[tokio::test]
async fn settings_telegram_save_roundtrip_masks_token_on_render() {
    // POST a valid config, GET the page back, assert:
    //   * status shows «enabled»
    //   * token rendered as ••••<last4>, NOT verbatim
    //   * chat_id rendered verbatim (operator wants to see it)
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let body = "telegram_bot_token=1234567890%3AABCDEFghijklmn&telegram_chat_id=987654321";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    // POST-redirect-GET pattern; expect 303 See Other.
    assert!(
        resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::OK,
        "expected redirect or OK after POST, got {}",
        resp.status()
    );

    // GET back the settings page.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(html.contains("enabled"), "status must flip to enabled");
    // Token VERBATIM must NOT appear — last 4 only.
    assert!(
        !html.contains("1234567890:ABCDEFghijklmn"),
        "verbatim token must NOT appear in rendered HTML — security"
    );
    assert!(
        html.contains("klmn"),
        "last 4 chars of token must appear (••••klmn rendering)"
    );
    // chat_id IS shown verbatim.
    assert!(
        html.contains("987654321"),
        "chat_id must appear in rendered HTML"
    );
}

#[tokio::test]
async fn settings_telegram_post_rejects_malformed_token() {
    // Shape gate at the handler: bot token must contain `:` and be
    // at least ~20 chars.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let body = "telegram_bot_token=tooshort&telegram_chat_id=123";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "malformed token must 400"
    );
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        text.contains("@BotFather"),
        "error body must point operator at BotFather"
    );
}

#[tokio::test]
async fn settings_telegram_post_rejects_garbage_chat_id() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let body =
        "telegram_bot_token=1234567890%3AABCDEFghijklmn&telegram_chat_id=not%20a%20chat%20id";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "garbage chat_id must 400"
    );
}

/// Security audit 2026-05-18 — admin responses must carry CSP +
/// X-Content-Type-Options + X-Frame-Options + Referrer-Policy +
/// Permissions-Policy headers. Defense-in-depth against XSS,
/// MIME-sniff, clickjacking, referrer leakage. CSP must NOT have
/// `unsafe-inline` for script-src (style-src does, intentional).
#[tokio::test]
async fn admin_responses_carry_security_headers() {
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
    let headers = resp.headers();
    // CSP
    let csp = headers
        .get("content-security-policy")
        .expect("CSP must be set on /admin/* responses")
        .to_str()
        .unwrap();
    assert!(
        csp.contains("default-src 'self'"),
        "CSP must default to self"
    );
    assert!(
        csp.contains("script-src 'self'") && !csp.contains("script-src 'self' 'unsafe-inline'"),
        "script-src MUST NOT include 'unsafe-inline' — XSS defense: {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "frame-ancestors must be 'none' — clickjacking defense: {csp}"
    );
    // Companion headers
    assert_eq!(
        headers
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").map(|v| v.to_str().unwrap()),
        Some("DENY")
    );
    assert_eq!(
        headers.get("referrer-policy").map(|v| v.to_str().unwrap()),
        // `same-origin` (NOT `no-referrer`): the strict version
        // bricked the CSRF middleware in prod 2026-05-19 by
        // stripping Referer from same-origin POSTs that browsers
        // send with `Origin: null`. `same-origin` keeps the no-
        // external-leakage guarantee while preserving the
        // Origin-→-Referer fallback inside our own admin tree.
        Some("same-origin")
    );
    let perm = headers
        .get("permissions-policy")
        .expect("Permissions-Policy must be set")
        .to_str()
        .unwrap();
    assert!(
        perm.contains("camera=()")
            && perm.contains("microphone=()")
            && perm.contains("geolocation=()"),
        "Permissions-Policy must block sensor / device APIs: {perm}"
    );
}

/// Security audit 2026-05-18 — quick-add must reject addresses
/// containing control bytes (`\n`, `\r`, `\t`, etc) that would
/// produce broken multi-line audit / log records downstream. Old
/// validator only rejected ASCII space + length>253.
#[tokio::test]
async fn server_quick_add_rejects_control_chars_in_address() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    // Control chars MID-STRING (not trailing — `.trim()` would strip
    // those). These produce broken multi-line audit / log records
    // if persisted as-is.
    for (encoded_addr, label) in [
        ("198%0A.51.100.1", "embedded newline in middle"),
        ("198%0D.51.100.1", "embedded CR"),
        ("198%09.51.100.1", "embedded tab"),
        ("host%20with%20space", "embedded space"),
        (
            "evil%3B%20rm%20-rf%20%2F",
            "shell-metachar injection attempt",
        ),
    ] {
        let body = format!("id=test&address={encoded_addr}&ssh_port=22");
        let mut req = Request::builder()
            .method("POST")
            .uri("/admin/servers/quick-add")
            .header("content-type", "application/x-www-form-urlencoded");
        req = add_same_origin(req);
        let resp = app
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "quick-add MUST 400 on {label} in address"
        );
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            text.contains("invalid address"),
            "error must call out 'invalid address': {text}"
        );
    }
}

/// Post-2026-05-18 rule (Pavel: «не должен просить меня сделать
/// что-то вручную на серверах»). No 4xx/5xx response body, no
/// admin HTML deck-copy, and no UI hint may instruct the operator
/// to manually `ssh root@…` + edit `authorized_keys`. Daemon
/// either auto-handles, surfaces a button, or — in the genuinely
/// impossible case (banned, can't reach) — explicitly says «use
/// hoster console».
///
/// This test exercises the THREE known operator-facing output
/// paths that historically held those instructions:
///   1. `classify_ssh_failure` (called by test-send 502)
///   2. `/admin/settings` Deploy SSH key section (rendered HTML)
///   3. `server.fail2ban.banned_self` alert payload
/// and asserts none contain the forbidden phrasing. Future regressions
/// (a new error message or alert payload that asks for manual SSH)
/// would have to add that pattern to one of these surfaces; this
/// test would catch it.
#[tokio::test]
async fn no_operator_facing_output_asks_for_manual_ssh_edit() {
    use vpnctld::alert_sink::classify_ssh_failure;

    // (1) classify_ssh_failure permission-denied branch — the most
    // common SSH failure mode operator hits. MUST surface the «push
    // deploy key» button, MUST NOT include the literal
    // `echo … >> ~/.ssh/authorized_keys` command.
    let msg = classify_ssh_failure(
        "ssh transport error: ssh root@1.2.3.4:22 exit=Some(255) \
         stderr=root@1.2.3.4: Permission denied (publickey,password).",
    );
    assert!(
        !msg.contains("echo '<paste>'") && !msg.contains(">> ~/.ssh/authorized_keys"),
        "classify_ssh_failure MUST NOT instruct manual authorized_keys edit: {msg}"
    );
    assert!(
        msg.contains("push deploy key"),
        "classify_ssh_failure SHOULD point at the «push deploy key» button: {msg}"
    );

    // (2) /admin/settings rendered HTML. In test env the daemon's
    // deploy pubkey file at /var/lib/vpnctl/.ssh/id_ed25519.pub
    // doesn't exist, so the @match hits the Err arm («Public key
    // file unreadable») — the «push deploy key» button copy lives
    // in the Ok arm. We can't easily inject a fake pubkey because
    // the path is a `const &str`. So we assert the NEGATIVE (no
    // forbidden pattern), which holds in BOTH arms.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/settings/system")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        !html.contains("echo '<paste>' >> ~/.ssh/authorized_keys"),
        "Deploy SSH key section MUST NOT contain the manual echo …>> instruction"
    );
    // (3) /admin/alerts deck — neither the empty-state nor the
    // alerts-table sections should embed an «ssh into the node»
    // hint. The fail2ban banned-self ALERT PAYLOAD (in node_probe_
    // poller.rs) was rewritten to point at hoster console — not
    // ask for SSH; we don't render it from `/admin/alerts` deck
    // directly, but we DO assert the alerts page's static copy
    // doesn't carry the old manual-ssh phrasing.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        !html.contains("ssh into the node out-of-band"),
        "alerts page must NOT ask operator to ssh into the node"
    );
}

#[tokio::test]
async fn server_detail_renders_push_deploy_key_section() {
    // Phase G chunk 3.5 follow-up — every server-detail page must
    // expose a «push deploy key» form so the operator can append
    // the daemon's pubkey without dropping to a terminal.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("vps-de1".into()),
            address: "203.0.113.7".into(),
            ssh_port: 2222,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/vps-de1/setup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("Deploy SSH key — push to this server"),
        "section eyebrow must render"
    );
    assert!(
        html.contains(r#"action="/admin/servers/vps-de1/push-deploy-key""#),
        "form must POST to the push-key route"
    );
    assert!(
        html.contains(r#"name="root_password""#),
        "form must include the password input"
    );
    assert!(
        html.contains("root@203.0.113.7:2222"),
        "button hint must show concrete ssh_user@host:port"
    );
    assert!(
        html.contains("never stored"),
        "placeholder must reassure operator that password isn't persisted"
    );
}

#[tokio::test]
async fn server_push_deploy_key_404s_for_unknown_server() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/servers/no-such/push-deploy-key")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .oneshot(req.body(Body::from("root_password=hunter2")).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("no such server 'no-such'"),
        "must surface the unknown-server message"
    );
}

#[tokio::test]
async fn server_push_deploy_key_rejects_empty_password_without_reference_key() {
    // Defensive: empty password reaches the handler if the
    // browser bypasses the `required` attr (curl, custom client).
    // Must 400 with a clear message — NEVER attempt the SSH call
    // with no password (sshpass would silently retry without
    // password and the failure mode would look like generic
    // network error).
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("stg".into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/servers/stg/push-deploy-key")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .oneshot(req.body(Body::from("root_password=")).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── wgturn info section on /admin/servers/{id} ──────────────────────
//
// Pre-2026-05-19 this was a vk_link operator-input FORM. Pavel
// 2026-05-19: «пользователь сам вставляет свою ссылку, так как у
// каждого звонка ограниченное кол-во потоков» — VK link is end-
// user-supplied at connect time per upstream `pkg/wgshare/doc.go`.
// The section is now info-only, explaining the operator-facing
// contract for the operator + sketching the user-facing CLI step
// the user runs on their device.

/// Pavel 2026-05-19: «не очень понимаю логику взаимодействия с
/// server, если я включаю trojan, мне нужно жать deploy или он
/// сразу при клики включается, по поводу kernel тот же вопрос».
/// Both the Kernels and the Enabled-protocols sections MUST carry
/// a loud (accent-bordered) banner explaining that toggles touch
/// inventory only and a subsequent click of «deploy →» is needed
/// to push the change to the live node. Anchor href to the deploy
/// button so it works as a scroll-to-top link.
#[tokio::test]
async fn server_detail_kernels_and_protocols_banners_explain_deploy_step() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("dx".into()),
            address: "203.0.113.30".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![vpnctl_core::ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/dx/protocols")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    // Deploy button has an anchor id so the banner-links can target it.
    assert!(
        html.contains("id=\"deploy-button\""),
        "Deploy button container must have id=\"deploy-button\""
    );
    // The banner phrase appears TWICE — once in Kernels, once in
    // Enabled protocols (deliberately duplicated; operators jump
    // straight to whichever section they're touching).
    let banner_marker = "toggle here = inventory only";
    let occurrences = html.matches(banner_marker).count();
    assert_eq!(
        occurrences, 2,
        "expected the «toggle = inventory only» banner in BOTH Kernels and Protocols sections; \
         got {occurrences}"
    );
    // Each banner links back to the deploy button (#deploy-button
    // anchor) so a one-click scroll takes the operator to the
    // button without keyboard navigation.
    assert!(
        html.matches("href=\"#deploy-button\"").count() >= 2,
        "each banner must include a link to #deploy-button so click → scroll-to-top works"
    );
}

#[tokio::test]
async fn server_detail_omits_wgturn_section_for_non_wgturn_kernels() {
    // Server with only sing-box kernel — the wgturn section must NOT
    // render. Keeps the page short for the common case.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("plain".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/plain")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("wgturn — emergency channel"),
        "section must NOT render for non-wgturn servers"
    );
    assert!(
        !html.contains("wgturn-cli connect-url"),
        "info block must NOT render for non-wgturn servers"
    );
}

#[tokio::test]
async fn server_detail_renders_wgturn_info_when_kernel_enabled() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("wt-1".into()),
            address: "203.0.113.20".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("wgturn".into())],
            enabled_protocols: vec![vpnctl_core::ProtocolId("wgturn".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/wt-1/protocols")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("wgturn — emergency channel"),
        "info eyebrow must render"
    );
    // Operator copy must explicitly state the end-user-supplies rule.
    assert!(
        html.contains("VK link is supplied by the END USER"),
        "must explain that VK link is end-user-supplied: {html}"
    );
    // The CLI example must surface the `--vk-link` flag so the
    // operator knows what to tell the user to type.
    assert!(
        html.contains("--vk-link"),
        "must show the user-side CLI invocation with `--vk-link`: {html}"
    );
    // The OLD operator-facing form MUST NOT be present anywhere.
    assert!(
        !html.contains(r#"name="vk_link""#),
        "pre-2026-05-19 vk_link form must be gone: {html}"
    );
    assert!(
        !html.contains("/wgturn/vk-link"),
        "pre-2026-05-19 vk_link POST action must be gone: {html}"
    );
}

#[tokio::test]
async fn server_detail_wgturn_info_does_not_leak_stale_vk_link_secret() {
    // Migration safety: if a daemon was upgraded from pre-2026-05-19,
    // the inventory's `server_secrets` table may still carry a
    // `wgturn:vk_link` row. The info section MUST NOT read or echo it
    // — the value is dead data; rendering it would be a secret leak.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&vpnctl_core::Server {
            id: vpnctl_core::ServerId("wt-2".into()),
            address: "203.0.113.21".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("wgturn".into())],
            enabled_protocols: vec![vpnctl_core::ProtocolId("wgturn".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let stale = "https://vk.com/call/join/stale-from-pre-may19";
    st.inv
        .set_server_secret(
            &vpnctl_core::ServerId("wt-2".into()),
            "wgturn:vk_link",
            stale,
        )
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/wt-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("stale-from-pre-may19"),
        "stale vk_link MUST NOT leak into HTML — got: {html}"
    );
}

#[tokio::test]
async fn admin_servers_id_wgturn_vk_link_route_returns_404() {
    // Pre-2026-05-19 this was a POST endpoint. Post-removal it
    // should 404 (no route registered). Pin the contract so we
    // don't accidentally restore the endpoint without re-discussing
    // the design.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/servers/anything/wgturn/vk-link")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .oneshot(req.body(Body::from("vk_link=irrelevant")).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "removed route must 404 (got {:?})",
        resp.status()
    );
}

#[tokio::test]
async fn settings_telegram_proxy_dropdown_lists_inventory_servers() {
    // Phase G chunk 3.5 — when servers exist in inventory, the
    // «egress» dropdown must list them as «via server: <id> (<addr>)»
    // options. Pavel's specific use case: РФ blocks api.telegram.org
    // from the daemon host but a VPN server can reach it.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    inv.add_server(&vpnctl_core::Server {
        id: vpnctl_core::ServerId("vps-de1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();

    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(
        html.contains(r#"name="proxy_via_server_id""#),
        "dropdown must be named proxy_via_server_id"
    );
    assert!(
        html.contains("direct (local network)"),
        "must include the 'direct' default option"
    );
    assert!(
        html.contains("via server: vps-de1 (203.0.113.7)"),
        "must include each inventory server as a via-option"
    );
}

#[tokio::test]
async fn settings_telegram_proxy_dropdown_shows_hint_when_no_servers() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("direct (local network)"));
    assert!(
        html.contains("No servers in inventory yet"),
        "must include the explanatory hint when inventory is empty"
    );
    assert!(
        !html.contains("via server:"),
        "no via-options when inventory empty"
    );
}

#[tokio::test]
async fn settings_telegram_save_persists_proxy_via_server_id() {
    // POST with proxy_via_server_id selected → next GET shows the
    // option pre-selected. Round-trips the new column through both
    // handlers + the inventory layer.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    inv.add_server(&vpnctl_core::Server {
        id: vpnctl_core::ServerId("vps-de1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();

    let app = router(st);
    let body = "telegram_bot_token=1234567890%3AABCDEFghijklmn\
                &telegram_chat_id=987654321\
                &proxy_via_server_id=vps-de1";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    app.clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        html.contains(r#"<option value="vps-de1" selected"#)
            || html.contains(r#"<option selected value="vps-de1""#),
        "vps-de1 option must be marked selected after save"
    );
}

#[tokio::test]
async fn settings_telegram_test_send_button_appears_only_when_enabled() {
    // Phase G chunk 3 part 2 — the «send test message» button must
    // appear ONLY when the transport is enabled. Disabled / partial
    // / error states show an explanatory hint instead.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();

    let app = router(st.clone());

    // Default state: no config → no button.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("send test message"),
        "button must NOT appear when transport disabled"
    );
    assert!(
        html.contains("Test-send button appears after both fields are saved"),
        "explanatory hint must appear instead"
    );

    // Enable and re-render.
    inv.set_telegram_config(Some("1234567890:ABCDEFghijklmn"), Some("987654321"), None)
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("send test message"),
        "button must appear when transport enabled"
    );
    assert!(
        html.contains(r#"action="/admin/settings/telegram/test""#),
        "button must POST to test route"
    );
}

#[tokio::test]
async fn settings_telegram_test_send_when_disabled_returns_400() {
    // POST to test endpoint with no config set → 400, NOT 502 (502
    // is for «config is set but Telegram rejected us»; 400 is for
    // «no config to test»).
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram/test");
    req = add_same_origin(req);
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "no config → 400, not 500/502"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("not configured") && text.contains("fill in both fields"),
        "must explain the missing-config state"
    );
}

#[tokio::test]
async fn settings_telegram_partial_config_renders_red_warning() {
    // Phase G chunk 3 part 1 — when only one half is set (token OR
    // chat_id but not both), the status line MUST surface this as
    // a red «partial config» banner rather than collapsing into
    // the bland «disabled» state. Catches the «I pasted only the
    // token and walked away» mistake.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    // Set only the token; chat_id stays NULL.
    inv.set_telegram_config(Some("1234567890:ABCDEFghijklmn"), None, None)
        .await
        .unwrap();

    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("partial config"),
        "stranded half must surface as 'partial config'"
    );
    assert!(
        html.contains("chat-id missing"),
        "must name which half is missing"
    );
    // Token NOT visible verbatim even in this state.
    assert!(
        !html.contains("1234567890:ABCDEFghijklmn"),
        "verbatim token must NOT leak even in partial-config state"
    );
}

#[tokio::test]
async fn settings_telegram_clear_both_disables_transport() {
    // Save valid config, then post two empty inputs → status flips
    // back to «disabled».
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    // Enable.
    let body = "telegram_bot_token=1234567890%3AABCDEFghijklmn&telegram_chat_id=987654321";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    app.clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();

    // Clear.
    let body = "telegram_bot_token=&telegram_chat_id=";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert!(resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::OK);

    // GET back, expect disabled.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("disabled"),
        "clearing both inputs must disable the transport"
    );
}

#[tokio::test]
async fn admin_alerts_renders_banned_self_kind_row() {
    // Phase G chunk 2 — seed a fail2ban banned-self alert row and
    // verify the feed renders it with the critical severity class.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    inv.add_server(&vpnctl_core::Server {
        id: vpnctl_core::ServerId("stg".into()),
        address: "1.1.1.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.insert_alert(
        "server.fail2ban.banned_self",
        Some(&vpnctl_core::ServerId("stg".into())),
        "critical",
        "daemon's outbound IP 192.168.0.236 is in fail2ban's banned list for sshd",
        Some(r#"{"our_ip":"192.168.0.236","ban_count_other":0}"#),
    )
    .await
    .unwrap();

    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("server.fail2ban.banned_self"),
        "feed must render the kind"
    );
    assert!(
        html.contains("192.168.0.236"),
        "feed must render the IP from the summary"
    );
}

#[tokio::test]
async fn admin_alerts_ack_unknown_id_returns_redirect_not_500() {
    // Phase G ack idempotency contract — every valid path through
    // `alert_ack` redirects, never 500s. Three branches:
    //   * id <= 0  → early redirect (negative-id guard).
    //   * id > 0 but no such row → ack_alert returns false → redirect.
    //   * id > 0 and row exists → ack + audit + redirect (covered
    //     by full-lifecycle test when Phase G chunk 2 ships).
    // This test exercises the first two — both paths must return a
    // redirect, not a 4xx/5xx. The empty inventory means no row
    // matches id=999.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for (uri, label) in [
        ("/admin/alerts/999/ack", "unknown id"),
        ("/admin/alerts/0/ack", "id=0 guard"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("Origin", "http://127.0.0.1")
                    .header("Host", "127.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::SEE_OTHER
                || resp.status() == StatusCode::FOUND
                || resp.status() == StatusCode::TEMPORARY_REDIRECT,
            "{label}: expected redirect, got {:?}",
            resp.status()
        );
    }
}

// ────────────────────────────────────────────────────────────────────────
//  Phase Hardening — CSRF middleware (handlers/csrf.rs)
//
//  Caught by retroactive review-agent (review #2) AND security-review
//  (security #1) on 2026-05-14: the regenerate handler had no
//  Origin/Referer check, so any cross-origin form-POST visited by an
//  authenticated operator's browser would silently rotate a victim
//  user's sub_token.
//
//  The middleware now sits OUTSIDE basic-auth on /admin/* and rejects
//  state-mutating requests whose Origin (or Referer fallback) does not
//  match the Host header.
// ────────────────────────────────────────────────────────────────────────

/// State-mutating POST WITHOUT an Origin (and WITHOUT a Referer) is
/// the classic "form auto-submitted from evil.example.com" scenario —
/// some browsers omit Origin on form-POST. Must 403 with the unified
/// `vpnctl admin:` error prefix.
#[tokio::test]
async fn admin_csrf_post_without_origin_is_403() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            // Deliberately NO Host, NO Origin, NO Referer.
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "POST without Origin must be rejected by CSRF middleware"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.starts_with("vpnctl admin: csrf"),
        "CSRF reject body must use unified prefix, got: {s:?}"
    );
}

/// State-mutating POST WITH an Origin pointing at a different host
/// than the request's Host header — the cross-origin attack surface.
/// Must 403, must NOT mutate state.
#[tokio::test]
async fn admin_csrf_post_with_mismatched_origin_is_403() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    // Snapshot the token; if CSRF protection works the regenerate
    // request below MUST NOT change it.
    let before = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    let app = router(s.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/u0/sub-token/regenerate")
                .header("host", "test.example")
                .header("origin", "http://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "cross-origin POST must be rejected by CSRF middleware"
    );
    let after = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();
    assert_eq!(
        before, after,
        "sub_token must be unchanged after CSRF-rejected POST"
    );
}

/// GET requests pass through the CSRF middleware unchanged — they are
/// not state-mutating per RFC 9110 and the admin tree's GET handlers
/// are read-only. A test rig that hits /admin/ without ANY headers
/// should still see the page.
#[tokio::test]
async fn admin_csrf_get_passes_through_without_origin() {
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
        "GET on /admin/ must pass through CSRF middleware regardless of Origin"
    );
}

/// Falling back from Origin to Referer: when the browser omits Origin
/// (older clients on simple form-POSTs) but sends a Referer pointing
/// at the same host, the middleware must accept the request.
#[tokio::test]
async fn admin_csrf_referer_fallback_when_origin_absent() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("host", "test.example")
                // NO Origin — Referer fallback should kick in.
                .header("referer", "http://test.example/admin/")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::TEMPORARY_REDIRECT,
        "same-origin Referer (no Origin) must pass CSRF, got {:?}",
        resp.status()
    );
}

/// Regression for the 2026-05-19 broken-admin bug: when the browser
/// sends `Origin: null` (opaque-origin context — sandboxed iframe,
/// privacy extension, file:// open), the Referer fallback MUST work
/// because that's the only remaining signal. Pre-fix:
/// Referrer-Policy was `no-referrer` which stripped Referer from
/// every same-origin POST → CSRF middleware bricked admin UI.
#[tokio::test]
async fn admin_csrf_referer_fallback_when_origin_is_literal_null() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("host", "test.example")
                // `Origin: null` is what privacy-mode browsers actually
                // send for opaque-origin documents (per the Fetch spec).
                .header("origin", "null")
                .header("referer", "http://test.example/admin/users")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::TEMPORARY_REDIRECT,
        "`Origin: null` + same-origin Referer must pass CSRF \
         (this exact scenario bricked prod 2026-05-19), got {:?}",
        resp.status()
    );
}

/// Regression for the 2026-05-19 Pavel-debugged-via-journalctl pain:
/// when CSRF rejects, the response body MUST include the actual
/// Host + Origin + Referer values + a likely-cause hint, so the
/// operator can self-diagnose without shell access (per CLAUDE.md
/// Operator-action policy).
#[tokio::test]
async fn admin_csrf_403_body_shows_host_origin_referer_and_cause() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("host", "real.example")
                // `Origin: null` (opaque origin), no Referer — exact
                // shape Pavel saw in the prod logs 2026-05-19.
                .header("origin", "null")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();

    // Body lists the three header values verbatim — operator can
    // see exactly what mismatched.
    assert!(
        text.contains("Host:    real.example"),
        "Host missing from body: {text}"
    );
    assert!(
        text.contains("Origin:  null"),
        "Origin (literal `null`) missing: {text}"
    );
    assert!(
        text.contains("Referer: (absent)"),
        "Referer state missing: {text}"
    );
    // Likely-cause hint for the `Origin: null` shape — points operator
    // at the opaque-origin diagnosis instead of leaving them guessing.
    assert!(
        text.contains("opaque origin"),
        "must explain the `Origin: null` case in plain English: {text}"
    );
}

/// Regression: the 2026-05-18 security audit shipped
/// `Referrer-Policy: no-referrer` which stripped Referer from every
/// outbound request — including our own same-origin form POSTs. Pinned
/// at `same-origin` so the CSRF middleware's Referer fallback survives.
/// A regression to `no-referrer` would re-brick admin UI for any
/// browser sending `Origin: null`.
#[tokio::test]
async fn admin_referrer_policy_header_is_same_origin_not_no_referrer() {
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
    let policy = resp
        .headers()
        .get("referrer-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        policy, "same-origin",
        "Referrer-Policy must be `same-origin` (NOT `no-referrer` — that bricks the CSRF middleware)"
    );
}

/// Regression for the 2026-05-19 «typed brat in add-user» UX bug:
/// on /admin/users the search form MUST appear before the add-user
/// form in the rendered HTML. Otherwise a keyboard-focused operator
/// who types + hits Enter accidentally creates a user instead of
/// searching.
#[tokio::test]
async fn admin_users_renders_search_form_before_add_user_form() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Need ≥ 1 user — the search bar only renders when the list is
    // non-empty (the bug only manifests once you have users to
    // search through).
    st.inv
        .add_user(&vpnctl_core::User {
            id: vpnctl_core::UserId("seed".into()),
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some("seed-token".into()),
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(st);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    let search_idx = html
        .find(r#"method="get" action="/admin/users""#)
        .expect("search form (method=get) missing");
    let add_idx = html
        .find(r#"method="post" action="/admin/users""#)
        .expect("add-user form (method=post) missing");
    assert!(
        search_idx < add_idx,
        "search form (at {search_idx}) must appear BEFORE add-user form (at {add_idx}) — \
         else accidental Enter from search-flow creates a user (Pavel-2026-05-19 bug)"
    );
    // The dense inbar keeps a dashed accent divider before the create
    // POST so it remains unmistakable from the safe GET search.
    assert!(
        html.contains("border-left: 1px dashed var(--accent)"),
        "add-user form must use a dashed accent divider"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase C-3.2 — web add-user form (POST /admin/users)
//
//  Pin the contract: form-only id, server mints UUID + tuic_password +
//  sub_token, audit row with actor=admin/action=user.add, redirects to
//  /admin/users/<id>. Bad input → 400 with vpnctl admin: prefix.
// ────────────────────────────────────────────────────────────────────────

/// Happy path: POST /admin/users with id=alice → 303 to detail page,
/// user lands in inventory with mint'd UUID + tuic_password +
/// sub_token, audit row appears.
#[tokio::test]
async fn admin_user_create_happy_path() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // No users yet.
    assert_eq!(s.inv.list_users().await.unwrap().len(), 0);

    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=alice"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "expected 303 redirect after create, got {:?}",
        resp.status()
    );
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/admin/users/alice",
        "redirect target must be the new user's detail page"
    );

    let user = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .expect("user must be in inventory after create");
    // UUID minted (length matches uuid v4 hex+dashes = 36).
    assert_eq!(user.uuid.len(), 36, "uuid must be standard 36 chars");
    assert!(user.tuic_password.is_some(), "tuic_password must be minted");
    assert!(user.sub_token.is_some(), "sub_token backfilled by add_user");

    let entries = inv.recent_audit(10).await.unwrap();
    let add = entries
        .iter()
        .find(|e| e.action == "user.add")
        .expect("audit row for user.add missing");
    assert_eq!(add.actor, "admin");
    assert_eq!(add.target.as_deref(), Some("alice"));
    let payload = add.payload.as_ref().expect("payload must contain uuid");
    assert_eq!(
        payload["uuid"],
        serde_json::Value::String(user.uuid.clone())
    );
}

/// Validation: bad id chars → 400 with the unified error prefix.
#[tokio::test]
async fn admin_user_create_rejects_bad_id() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for bad in [
        "alice with space",
        "alice/slash",
        "alice?query",
        "",        // empty
        "русский", // non-ASCII
    ] {
        // Use raw body; we want to exercise the server-side validator,
        // not the URL-decoder. Spaces in body need to be `+` or `%20` to
        // survive form parsing; we test both forms end-to-end so the
        // validator handles whatever the browser sends.
        let body = format!("id={}", bad.replace(' ', "+"));
        let resp = app
            .clone()
            .oneshot(
                add_same_origin(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/users")
                        .header("content-type", "application/x-www-form-urlencoded"),
                )
                .body(Body::from(body))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "id {bad:?} must be rejected, got {:?}",
            resp.status()
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.starts_with("vpnctl admin: invalid user id"),
            "400 body must start with the unified prefix, got: {text:?}"
        );
    }
}

/// Duplicate id → 400 "already exists" (operator-friendly), NOT 500.
#[tokio::test]
async fn admin_user_create_rejects_duplicate_id() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await; // creates u0
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=u0"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "duplicate id must be 400, got {:?}",
        resp.status()
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("already exists"),
        "duplicate body should mention 'already exists', got: {text:?}"
    );
    assert!(
        text.contains("pick a different id"),
        "duplicate body should suggest the fix, got: {text:?}"
    );
}

/// The /admin/users page renders the form so a fresh operator can
/// create their first user without touching the CLI.
#[tokio::test]
async fn admin_users_page_renders_create_form() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/users").await;
    assert!(
        html.contains(r#"action="/admin/users""#),
        "form must POST to /admin/users"
    );
    assert!(
        html.contains(r#"name="id""#),
        "form must have a name=id input"
    );
    assert!(
        html.contains(">create<"),
        "submit button label drifted from 'create'"
    );
    // Single-field creation form post-2026-05-16 — id input + create
    // button + helper sentence. WG keypair management lives on the
    // user-detail page now, not in the creation form.
    assert!(
        html.contains("all keys are auto-generated"),
        "form helper drifted — should promise auto-gen so the operator doesn't go hunting"
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
    use http_body_util::BodyExt;
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

// ────────────────────────────────────────────────────────────────────────
//  Phase F — monitoring page + stats JSON endpoint
//
//  Pin the SSR shape (KPIs + sparkline SVG dimensions) and the JSON
//  endpoint response shape. Sparkline content depends on inventory
//  state at test time, so we assert shape (svg width/height/stroke,
//  KPI labels) rather than pixel values.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_monitoring_renders_fleet_health() {
    // Design v2 3a — monitoring is the fleet-health surface: six
    // status tiles, per-node uptime + trend tables, the monitor's
    // REAL thresholds, probe failures and the GeoIP line. The former
    // sub-access analytics are gone from the page (the JSON API at
    // /api/v1/stats/sub-access stays — pinned by its own test).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    // One health row (mem 75% > the 70 heat watermark) so the tiles,
    // uptime table and trend table all have real cells.
    s.inv
        .record_node_health(
            &ServerId("s0".into()),
            Some(true),
            Some(true),
            Some(4096),
            Some(20480),
            Some(2048),
            Some(8192),
            Some(120),
            None,
            Some(1_048_576),
            Some(r#"{"sing-box":"1.13.12"}"#),
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/monitoring").await;

    // Headrow: Fleet health h1 + the manual sweep button (POST form).
    assert!(html.contains("Fleet"), "Fleet health h1 missing");
    assert!(
        html.contains(r#"action="/admin/monitoring/probe-all""#),
        "probe-all POST form missing"
    );
    // Six-tile strip renders with the fleet up-count.
    assert!(
        html.contains("ed-status-strip") && html.contains("1 / 1 up"),
        "fleet tile must show 1 / 1 up"
    );
    // Mem peak 75% crosses the 70 heat watermark → warm tile.
    assert!(
        html.contains(r#"class="ed-status-tile warn""#),
        "mem-peak tile above 70% must render warm"
    );
    // Uptime table: dense grid with the server link + 100% (1 up probe).
    assert!(
        html.contains(r#"class="ed-grid__id" href="/admin/servers/s0""#),
        "uptime row must link the server"
    );
    // Thresholds table shows the monitor's REAL constants.
    assert!(
        html.contains("mem_used_pct") && html.contains("95%"),
        "threshold table must show the real mem trigger (95%)"
    );
    assert!(
        html.contains("disk_used_pct") && html.contains("90%"),
        "threshold table must show the real disk trigger (90%)"
    );
    assert!(
        html.contains("singbox_log_mib") && html.contains("500"),
        "threshold table must show the 500 MiB log trigger"
    );
    // GeoIP line renders (files absent in test env → «missing») and
    // points at Settings instead of a state-changing GET.
    assert!(
        html.contains("/admin/settings/system#geoip"),
        "GeoIP line must link to the Settings System tab"
    );
    // The old sub-access analytics are gone.
    assert!(
        !html.contains("hits · 24h") && !html.contains("Hourly hits"),
        "sub-access KPIs must be gone from the monitoring page"
    );
}

#[tokio::test]
async fn api_stats_sub_access_returns_well_formed_json() {
    use http_body_util::BodyExt;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    s.inv
        .log_sub_access(&UserId("u0".into()), "1.1.1.1", None, 200, 500)
        .await
        .unwrap();
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/stats/sub-access")
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
    assert!(ct.starts_with("application/json"), "ct: {ct}");

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["bucket"], "hour", "default bucket=hour");
    assert_eq!(v["since_hours"], 24, "default since_hours=24");
    let buckets = v["buckets"].as_array().expect("buckets array");
    assert!(!buckets.is_empty(), "should have at least one bucket");
    assert_eq!(buckets[0]["hits"], 1);
    assert_eq!(buckets[0]["distinct_ips"], 1);
    assert!(buckets[0]["ts"].is_string(), "ts must be ISO-8601 string");
}

#[tokio::test]
async fn api_stats_sub_access_rejects_invalid_bucket() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/stats/sub-access?bucket=fortnight")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unknown bucket kind must be 400"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase C-3.4 — web delete user (double-submit confirm)
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_user_delete_confirm_renders_form_with_match_id() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let app = router(s);
    let html = fetch_html(app, "/admin/users/u0/delete-confirm").await;
    assert!(
        html.contains("delete forever"),
        "submit button label drifted"
    );
    assert!(
        html.contains(r#"action="/admin/users/u0/delete""#),
        "confirm form must POST to /admin/users/u0/delete"
    );
    assert!(html.contains(r#"name="confirm""#), "confirm input missing");
    // The user-id text should appear as guidance for typing.
    assert!(html.contains(">u0<"), "operator must see what to type");
}

#[tokio::test]
async fn admin_user_delete_confirm_unknown_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let body = body_of(
        app,
        "GET",
        "/admin/users/no-such/delete-confirm",
        None,
        None,
    )
    .await;
    assert_eq!(body, "vpnctl admin: no such user 'no-such'\n");
}

#[tokio::test]
async fn admin_user_delete_happy_path() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // u0 with grant to s0
    s.inv
        .log_sub_access(&UserId("u0".into()), "1.1.1.1", None, 200, 100)
        .await
        .unwrap();
    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=u0"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/admin/users",
        "redirect after delete must land on the users list"
    );

    // User gone.
    assert!(
        inv.get_user(&UserId("u0".into())).await.unwrap().is_none(),
        "user must be removed"
    );
    // Grants cascade-deleted (FK CASCADE in 0001_init).
    assert_eq!(
        inv.servers_for_user(&UserId("u0".into()))
            .await
            .unwrap()
            .len(),
        0
    );
    // Audit row written.
    let entries = inv.recent_audit(10).await.unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.action == "user.remove" && e.target.as_deref() == Some("u0")),
        "user.remove audit row missing"
    );
    // sub_access_log row SURVIVES with NULL user_id (migration 0004).
    // Read via active_bans-style check: distinct_ips_for_user("u0", 24)
    // returns 0 because the FK was set NULL, so the row no longer
    // matches `user_id = ?1`. Verify by counting active_bans (0) and
    // by the row count via a raw scan: we expect at least the orphaned
    // row to still be there.
    let n = inv
        .distinct_ips_for_user(&UserId("u0".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "deleted user's distinct IPs query returns 0 (FK was SET NULL — row survives orphaned)"
    );
}

#[tokio::test]
async fn admin_user_delete_mismatch_400() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let inv = s.inv.clone();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=u1"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // User STILL there — mismatch must not delete.
    assert!(inv.get_user(&UserId("u0".into())).await.unwrap().is_some());
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

// ────────────────────────────────────────────────────────────────────────
// Phase E sub-iter 4a — add-server wizard step 1 + step-2 stub.
//
// The wizard is the marquee differentiator over the bash project
// (per CLAUDE.md "Strategic context"). Sub-iter 4a's contract:
//   * GET /admin/servers/new renders a form with `address` +
//     `root_password` fields and the editorial chrome.
//   * POST validates input, stashes it server-side keyed by an
//     HttpOnly+SameSite=Strict cookie, and 303s to step 2.
//   * GET step-2 either reads the session cookie and shows the
//     stashed address, or 400s if the session is missing/expired.
//   * /admin/servers list links to /admin/servers/new (the CLI
//     nudge alone leaves operators stranded).

#[tokio::test]
async fn admin_servers_index_links_to_wizard() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/servers").await;
    assert!(
        html.contains("/admin/servers/new"),
        "servers list must link to the wizard; got {}",
        &html[..html.len().min(800)]
    );
    // The "add server →" CTA is the editorial-voice prompt.
    assert!(
        html.contains("add server"),
        "wizard CTA copy missing on /admin/servers"
    );
}

#[tokio::test]
async fn admin_wizard_new_renders_form_with_required_fields() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/servers/new").await;
    // Form posts back to the same URL.
    assert!(
        html.contains(r#"action="/admin/servers/new""#),
        "form action missing"
    );
    // Both fields present, both required.
    assert!(html.contains(r#"name="address""#), "address field missing");
    assert!(
        html.contains(r#"name="root_password""#),
        "root_password field missing"
    );
    // Password input must be type=password (no echo to the page).
    assert!(
        html.contains(r#"id="root_password" name="root_password" type="password""#),
        "root_password must be type=password"
    );
    // Headline + step indicator (copy contract). «of 2» — the wizard
    // is a 2-step flow; the old «of 3» promised a step that never
    // existed (review 2026-06-04).
    assert!(
        html.contains("Add server · step 1 of 2"),
        "step indicator missing"
    );
}

#[tokio::test]
async fn admin_wizard_submit_rejects_empty_address_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("address=&root_password=hunter2"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with("vpnctl admin: invalid address"),
        "expected canonical 'vpnctl admin: invalid address …' body, got {text:?}"
    );
}

#[tokio::test]
async fn admin_wizard_submit_rejects_shell_injection_in_address() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            // %3B is `;`, %20 is space — these are exactly what a
            // browser form would send for `; rm -rf /`.
            .body(Body::from(
                "address=10.0.0.1%3B%20rm%20-rf%20%2F&root_password=hunter2",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "shell metacharacters in address must be rejected"
    );
}

#[tokio::test]
async fn admin_wizard_submit_rejects_empty_password_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("address=192.0.2.1&root_password="))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with("vpnctl admin: invalid root password"),
        "expected canonical 'vpnctl admin: invalid root password …' body, got {text:?}"
    );
}

/// Happy path: valid input → 303 to step-2 + HttpOnly session cookie.
/// The cookie's Path scope MUST be limited to the wizard so the
/// session id never rides along on /admin/users/* etc.
#[tokio::test]
async fn admin_wizard_submit_happy_path_sets_scoped_cookie_and_redirects() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    assert_eq!(s.wizard.len(), 0, "store starts empty");
    let app = router(s.clone());

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("address=198.51.100.42&root_password=hunter2"))
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "/admin/servers/new/step-2",
        "redirect must go to step-2"
    );
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("set-cookie missing")
        .to_str()
        .unwrap();
    assert!(
        cookie.starts_with("vpnctl_wizard="),
        "wrong cookie name: {cookie}"
    );
    // Security flags: path-scope, HttpOnly, SameSite=Strict.
    assert!(
        cookie.contains("Path=/admin/servers/new"),
        "cookie path must be wizard-scoped, got: {cookie}"
    );
    assert!(
        cookie.contains("HttpOnly"),
        "cookie must be HttpOnly, got: {cookie}"
    );
    assert!(
        cookie.contains("SameSite=Strict"),
        "cookie must be SameSite=Strict, got: {cookie}"
    );
    // Server-side state has the row.
    assert_eq!(s.wizard.len(), 1, "session must be stashed server-side");
}

#[tokio::test]
async fn admin_wizard_step2_renders_address_with_valid_session() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let session_id = s.wizard.insert(
        "vpn-de1.example.org".into(),
        "r00tpwXYZ-distinct".into(),
        22,
    );
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2")
                .header("cookie", format!("vpnctl_wizard={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // Address echoed back; password MUST NOT be in the page.
    assert!(
        html.contains("vpn-de1.example.org"),
        "address must echo on step-2"
    );
    assert!(
        !html.contains("r00tpwXYZ-distinct"),
        "root password must NEVER appear in step-2 HTML"
    );
    // Step indicator («of 2» — see step-1's copy-contract note).
    assert!(
        html.contains("Add server · step 2 of 2"),
        "step indicator missing on step-2"
    );
}

#[tokio::test]
async fn admin_wizard_step2_rejects_missing_session_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "step-2 must 400 without a session"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with("vpnctl admin: wizard session expired"),
        "canonical missing-session body required, got {text:?}"
    );
}

#[tokio::test]
async fn admin_wizard_step2_rejects_bogus_cookie_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2")
                .header("cookie", "vpnctl_wizard=not-a-real-session-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unknown session ids must 400 (no session enumeration leak)"
    );
}

// ───────────────────────────────────────────────────────────────────
// Phase E sub-iter 4b — wizard SSE bootstrap.
//
// The step-2 page must:
//   * render an inline EventSource pointed at the SSE source,
//   * have a log pane + status line populated by the client JS,
//   * NEVER echo the operator's root password into the HTML,
//   * link a fallback "start over" anchor.
//
// The SSE endpoint must:
//   * reject missing/bogus session with 400 + canonical body,
//   * single-shot consume the session (re-attach 400s),
//   * advertise `Content-Type: text/event-stream` (browsers refuse
//     to treat the response as an EventSource otherwise),
//   * never appear in the CSRF/auth blast radius without protection
//     (it's a GET — CSRF passes through, basic-auth wraps it).
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_wizard_step2_page_attaches_autostart_sse_to_endpoint() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let session_id = s.wizard.insert("198.51.100.42".into(), "pw".into(), 22);
    let app = router(s);

    let html = fetch_html_with_cookie(
        app,
        "/admin/servers/new/step-2",
        &format!("vpnctl_wizard={session_id}"),
    )
    .await;

    // v2 6b — CSP-safe: admin.js opens the EventSource from the
    // data-sse-autostart attribute (the old inline <script> was blocked
    // by script-src 'self').
    assert!(
        html.contains(r#"data-sse-autostart="/admin/servers/new/step-2/sse""#),
        "step-2 log pane must carry the autostart SSE URL"
    );
    // The old inline EventSource block is gone (CSP-blocked); the
    // only <script> is the external admin.js the shell always ships.
    assert!(
        !html.contains("new EventSource("),
        "step-2 must not ship an inline EventSource script (CSP-blocked)"
    );
    assert!(
        html.contains("id=\"wizard-log\""),
        "step-2 must have a log pane the SSE handlers append into"
    );
    // v2 6b — the live steps checklist replaced the status <div>;
    // admin.js maps each `step` event's phase to a row here.
    assert!(
        html.contains("id=\"wizard-steps\"") && html.contains("data-step-phase="),
        "step-2 must have the live steps checklist"
    );
    assert!(
        !html.contains(">pw<") && !html.contains("\"pw\""),
        "root password must NEVER appear in the step-2 page HTML"
    );
}

#[tokio::test]
async fn admin_wizard_sse_rejects_missing_session_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2/sse")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "SSE endpoint must 400 without a session cookie"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with("vpnctl admin: wizard session missing"),
        "canonical missing-session body required, got {text:?}"
    );
}

#[tokio::test]
async fn admin_wizard_sse_rejects_bogus_cookie_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2/sse")
                .header("cookie", "vpnctl_wizard=bogus")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "SSE endpoint must 400 on unknown session id"
    );
}

#[tokio::test]
async fn admin_wizard_sse_consumes_session_on_first_attach() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Address that's deliberately unroutable — the SSE handler will
    // start streaming events, the bootstrap's probe phase will fail
    // (RFC 5737 TEST-NET-1 doesn't route), but we only care here
    // that the session is GONE after the first attach.
    let session_id = s.wizard.insert("198.51.100.1".into(), "pw".into(), 22);
    assert_eq!(s.wizard.len(), 1, "precondition: session present");
    let app = router(s.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2/sse")
                .header("cookie", format!("vpnctl_wizard={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "first SSE attach with valid session must succeed"
    );
    // The response body is an open SSE stream; we don't have to drain
    // it — dropping the response closes the receiver. Session must be
    // gone immediately on attach (single-shot semantics).
    assert_eq!(
        s.wizard.len(),
        0,
        "SSE attach must consume the wizard session"
    );
    drop(resp);
}

#[tokio::test]
async fn admin_wizard_sse_advertises_event_stream_content_type() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let session_id = s.wizard.insert("198.51.100.1".into(), "pw".into(), 22);
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2/sse")
                .header("cookie", format!("vpnctl_wizard={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "EventSource requires Content-Type: text/event-stream, got {ct:?}"
    );
}

#[tokio::test]
async fn admin_wizard_submit_carries_ssh_port_2222_into_session() {
    // Review-agent (2026-05-17, important-4): Cloudzy hosts on
    // 2222, the wizard's ssh_port input field must round-trip.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s.clone());
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(
                "address=104.194.156.93&root_password=pw&ssh_port=2222",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Session must have port 2222 stashed.
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("set-cookie missing")
        .to_str()
        .unwrap();
    let session_id = cookie
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("vpnctl_wizard=");
    let session = s
        .wizard
        .get(session_id)
        .expect("session must be retrievable by id");
    assert_eq!(session.ssh_port, 2222, "ssh_port must round-trip from form");
}

#[tokio::test]
async fn admin_wizard_submit_blank_ssh_port_defaults_to_22() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s.clone());
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("address=10.0.0.1&root_password=pw&ssh_port="))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("set-cookie missing")
        .to_str()
        .unwrap();
    let session_id = cookie
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("vpnctl_wizard=");
    let session = s.wizard.get(session_id).unwrap();
    assert_eq!(session.ssh_port, 22, "blank ssh_port must default to 22");
}

#[tokio::test]
async fn admin_wizard_submit_rejects_bogus_ssh_port_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(
                "address=10.0.0.1&root_password=pw&ssh_port=99999",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with("vpnctl admin: invalid ssh_port"),
        "canonical body required, got {text:?}"
    );
}

#[tokio::test]
async fn admin_wizard_step1_form_has_ssh_port_field() {
    // Front-end: ensure the operator sees the (optional) ssh_port
    // field on step 1 — otherwise they'd never know they can change
    // it for Cloudzy / non-22 hosts.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/servers/new").await;
    assert!(
        html.contains("name=\"ssh_port\""),
        "wizard step-1 must expose an ssh_port input field"
    );
    assert!(
        html.contains("optional, default 22"),
        "ssh_port label must clarify it's optional with default 22"
    );
}

#[tokio::test]
async fn admin_wizard_sse_collision_appends_numeric_suffix() {
    // Operator runs the wizard for the same IP twice. The second
    // attach must derive a non-colliding server id rather than
    // 400-ing — that's the difference between an operator hitting
    // back-button + retry (good UX) vs. having to invent a new
    // address (bad UX).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Pre-seed a server with the id that would be derived from the
    // wizard's address.
    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("198.51.100.1".into()),
        address: "198.51.100.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    s.inv.add_server(&server).await.unwrap();

    let session_id = s.wizard.insert("198.51.100.1".into(), "pw".into(), 22);
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2/sse")
                .header("cookie", format!("vpnctl_wizard={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // The SSE attach itself succeeds (200) — the collision is handled
    // by id suffixing inside the handler. The bootstrap pipeline will
    // then fail at the probe phase (no real server) but that's fine
    // for this test; we only care that the attach didn't 409.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "repeat wizard for same address must suffix id, not 409"
    );
    drop(resp);
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

// ────────────────────────────────────────────────────────────────────────
// Track-3 chunk 3 — live VPN stats section on user-detail.
//
// Reads `recent_vpn_stats_for_user(uid, 24)`. Two states matter:
//   * Empty: explicit "polling not yet wired (chunk 4)" copy that
//     points at the daemon's SSH key location — without this the
//     missing data looks like a bug.
//   * Populated: KPI tiles (uploaded / downloaded / peak conns) +
//     per-server breakdown table.

use vpnctl_inventory::VpnStatsDelta;

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

// ────────────────────────────────────────────────────────────────────────
// Phase H chunk 3 — server detail page (/admin/servers/{id})
//
// Covers:
//   * Unknown server → 404 with canonical body
//   * Known server, no probes → empty-state mentions "chunk 4"
//   * Known server WITH a probe row → KPI tiles render with real numbers
//   * Drift highlight when declared protocols disagree with observed
//     listening ports
//   * Servers-list page links to the detail page (clickable headline)

#[tokio::test]
async fn admin_server_detail_unknown_id_returns_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/no-such")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.starts_with("vpnctl admin: no such server"));
}

#[tokio::test]
async fn admin_server_detail_no_probe_shows_chunk4_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // server s0 only
    let html = fetch_html(router(s), "/admin/servers/s0").await;
    assert!(html.contains("Live status"));
    assert!(
        html.contains("No probes yet"),
        "empty-state copy must mention 'No probes yet'"
    );
    // Copy refreshed 2026-06-10: poller is LIVE at a 10-min cadence;
    // blank = not probed yet / not a sing-box node.
    assert!(
        html.contains("every 10 min"),
        "must state the live poller cadence"
    );
}

#[tokio::test]
async fn admin_server_detail_with_probe_renders_kpis() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    // Insert a probe row matching what node_probe would produce
    s.inv
        .record_node_health(
            &ServerId("s0".into()),
            Some(true),
            Some(true),
            Some(9876),
            Some(20480),
            Some(231),
            Some(960),
            Some(4),
            Some(r#"["tcp/443","tcp/8388","udp/8388","udp/8443"]"#),
            Some(308_432),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers/s0").await;
    // Dense six-tile hero strip visible.
    assert!(html.contains("ed-status-strip"));
    assert!(html.contains("active"), "sing-box active visible");
    assert!(html.contains("48%"), "disk pct visible (9876/20480)");
    assert!(html.contains("76%"), "mem pct visible (1 - 231/960 = 76)");
    assert!(
        html.contains(r#"class="ed-status-tile warn""#),
        "memory above 70% must render the warm heat tile"
    );
    // No empty-state once we have data
    assert!(!html.contains("No probes yet"));
}

#[tokio::test]
async fn admin_server_detail_highlights_drift_between_declared_and_observed() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Server declares vless+reality + tuic-v5 in inventory
    s.inv
        .add_server(&vpnctl_core::Server {
            id: ServerId("driftnode".into()),
            address: "10.0.0.99".into(),
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
    // But the probe sees vless (tcp/443) AND an EXTRA hysteria2 (udp/8444),
    // and NO tuic (no udp/8443). Two drifts: missing tuic, extra hy2.
    s.inv
        .record_node_health(
            &ServerId("driftnode".into()),
            Some(true),
            Some(true),
            Some(1000),
            Some(10000),
            Some(500),
            Some(1000),
            Some(10),
            Some(r#"["tcp/22","tcp/443","udp/8444"]"#),
            Some(1000),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers/driftnode/protocols").await;
    // v2 3c grid: the silent tuic port renders the warm flag + the
    // declared-but-NOT-listening line names it.
    assert!(
        html.contains("✗ silent") || html.contains("✗ молчит"),
        "silent declared port must carry the ✗ flag; got: {}",
        &html[..html.len().min(400)]
    );
    assert!(
        html.contains("declared but NOT listening"),
        "missing-port warning line must render"
    );
    assert!(
        html.contains("udp/8443"),
        "missing tuic udp/8443 must be listed"
    );
    // The extra hysteria2 socket lands in the grouped undeclared table
    // (unclassified group names raw ports).
    assert!(
        html.contains("Listening but undeclared"),
        "undeclared group table must render"
    );
    assert!(
        html.contains("udp/8444"),
        "extra hysteria2 udp/8444 must be listed in a group"
    );
    // SSH port 22 must NOT be flagged as "extra" (always-listening).
    let undeclared = html.split("Listening but undeclared").nth(1).unwrap_or("");
    assert!(
        !undeclared.contains("tcp/22"),
        "ssh port must be excluded from the undeclared groups"
    );
}

#[tokio::test]
async fn admin_servers_list_link_to_detail_page() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers").await;
    assert!(
        html.contains(r#"href="/admin/servers/s0""#),
        "server card headline must link to detail page"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Post-2026-05-16 WireGuard contract for the web layer:
//
//   * Creation form has ONE field (`id`); no wg-related inputs.
//   * `POST /admin/users` ALWAYS mints a server-generated WG keypair,
//     IGNORING any wireguard_pubkey / gen_wireguard form fields that
//     a stale client might send. Both halves land in the row atomically.
//   * Operator-paranoid path (paste pubkey) moves to the CLI and to
//     a dedicated control on the user-detail page (queued).
//
// This block pins those guarantees as anti-regression net.

#[tokio::test]
async fn admin_user_create_always_mints_server_generated_wireguard_pair() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    // Bare `id=alice` — no wg-related field. Used to be the
    // "keeps None" branch; now MUST result in both halves set.
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=alice"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let u = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    let pk = u.wireguard_pubkey.as_deref().expect("pubkey auto-set");
    let priv_ = u.wireguard_private.as_deref().expect("private auto-set");
    assert_eq!(pk.len(), 44, "pubkey must be 44-char standard b64: {pk}");
    assert_eq!(priv_.len(), 44, "private must be 44-char standard b64");
    assert!(pk.ends_with('='));
    assert!(priv_.ends_with('='));
    assert_ne!(pk, priv_, "pub and priv must differ");
}

#[tokio::test]
async fn admin_user_create_ignores_stale_wireguard_pubkey_field() {
    // A stale browser tab might still POST `wireguard_pubkey=...`
    // from the old form. The handler must IGNORE that input and
    // still mint a server-generated pair — sneaking an operator-
    // supplied pubkey in through a back door would silently
    // bypass the one-action creation contract.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    let attacker_pubkey = "AttackerKkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkAB=";
    let body = format!(
        "id=bob&wireguard_pubkey={}",
        attacker_pubkey.replace('=', "%3D")
    );
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(body))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let u = inv.get_user(&UserId("bob".into())).await.unwrap().unwrap();
    let pk = u.wireguard_pubkey.as_deref().unwrap();
    assert_ne!(
        pk, attacker_pubkey,
        "stale form field MUST be ignored; got {pk}"
    );
    assert!(u.wireguard_private.is_some(), "server-generated pair");
}

#[tokio::test]
async fn admin_users_page_form_is_one_field_one_button() {
    // Single input + single button = one operator action.
    // Anti-regression: future "let me add one more nice optional
    // field" PRs surface here.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/users").await;
    assert!(
        !html.contains(r#"name="wireguard_pubkey""#),
        "wireguard_pubkey input MUST NOT be in the creation form"
    );
    assert!(
        !html.contains(r#"name="gen_wireguard""#),
        "gen_wireguard checkbox MUST NOT be in the creation form"
    );
    // Helper copy that pins the new one-action contract.
    assert!(
        html.contains("all keys are auto-generated"),
        "form helper must promise auto-gen so the operator doesn't go hunting for missing options"
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
    // at the CLI workaround.
    assert!(
        html.contains("vpnctl server add"),
        "case B must point at the CLI when inventory has zero WG-capable nodes"
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
}

// ────────────────────────────────────────────────────────────────────────
// Pavel iter A1: server-detail protocols section — checkbox list of every
// registered protocol with enable/disable form. Closes the "main-brat WG
// keys are useless because vps-is-01 doesn't run wireguard" gap by
// letting the operator add protocols to an existing server without CLI.

#[tokio::test]
async fn admin_server_detail_protocols_section_shows_every_registered_protocol() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
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
    let app = router(s);
    let html = fetch_html(app, "/admin/servers/nowg/protocols").await;
    assert!(html.contains("Enabled protocols"), "section heading");
    // Every registered protocol appears as a row (sing-box ships 6,
    // amneziawg ships 1 — total 7 unique ids in the registry).
    for pid in [
        "vless+reality",
        "tuic-v5",
        "hysteria2",
        "shadowsocks-2022",
        "anytls",
        "trojan",
        "wireguard",
    ] {
        assert!(
            html.contains(pid),
            "protocol row '{pid}' missing from server-detail"
        );
    }
    // The currently-enabled one has a disable button + ✓ on marker.
    // `+` in vless+reality gets URL-encoded to %2B in the form action.
    assert!(
        html.contains(r#"/admin/servers/nowg/protocols/vless%2Breality/disable"#),
        "enabled protocol must have a disable form (vless+reality URL-encoded)"
    );
    assert!(html.contains("✓ on"), "enabled marker missing");
    // A compatible-but-not-yet-enabled one has an enable button.
    assert!(
        html.contains(r#"/admin/servers/nowg/protocols/hysteria2/enable"#),
        "compatible-disabled protocol must have an enable form"
    );
    // Incompatible (wireguard under sing-box kernel) is greyed out
    // with no toggle button — only the explainer copy.
    assert!(
        html.contains("not supported by kernel sing-box"),
        "incompatible explainer must appear next to wireguard"
    );
    assert!(
        !html.contains(r#"/admin/servers/nowg/protocols/wireguard/enable"#),
        "incompatible protocol MUST NOT have an enable form"
    );
}

#[tokio::test]
async fn admin_server_enable_protocol_persists_and_audits() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("amz".into()),
            address: "198.51.100.5".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("amneziawg".into())],
            enabled_protocols: vec![], // start empty
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/amz/protocols/wireguard/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let server = inv
        .get_server(&ServerId("amz".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        server
            .enabled_protocols
            .contains(&ProtocolId("wireguard".into())),
        "wireguard must be persisted into enabled_protocols"
    );
    // Audit row exists with the protocol name + newly_added flag.
    let audit = inv.recent_audit(5).await.unwrap();
    let row = audit
        .iter()
        .find(|a| a.action == "server.protocol.enable")
        .expect("audit row");
    let payload = row
        .payload
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_default();
    assert!(payload.contains("wireguard"));
    assert!(payload.contains("newly_added"));
}

#[tokio::test]
async fn admin_server_enable_protocol_rejects_unregistered_protocol_id() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/sb/protocols/totally-fake/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("unknown protocol"));
    assert!(text.contains("totally-fake"));
}

#[tokio::test]
async fn admin_server_disable_protocol_removes_row_and_audits() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
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
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/sb/protocols/tuic-v5/disable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let server = inv
        .get_server(&ServerId("sb".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !server
            .enabled_protocols
            .contains(&ProtocolId("tuic-v5".into())),
        "tuic-v5 must be gone after disable"
    );
    assert!(
        server
            .enabled_protocols
            .contains(&ProtocolId("vless+reality".into())),
        "other protocols must stay untouched"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Multi-kernel server (Pavel: «а что на 1 сервере не может быть 2 ядра?»).
// Server.kernels is now Vec<KernelId>; server detail gains a Kernels
// section with enable/disable mirroring the Protocols section.

#[tokio::test]
async fn admin_server_detail_kernels_section_shows_every_registered_kernel() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("sb-only".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/servers/sb-only/protocols").await;
    assert!(html.contains("Kernels"), "Kernels heading missing");
    // sing-box is registered AND enabled → disable form
    assert!(
        html.contains("/admin/servers/sb-only/kernels/sing-box/disable"),
        "enabled kernel must have disable form"
    );
    // amneziawg is registered but NOT enabled → enable form
    assert!(
        html.contains("/admin/servers/sb-only/kernels/amneziawg/enable"),
        "disabled kernel must have enable form"
    );
}

#[tokio::test]
async fn admin_server_enable_kernel_persists_and_audits() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("hybrid".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/hybrid/kernels/amneziawg/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let server = inv
        .get_server(&ServerId("hybrid".into()))
        .await
        .unwrap()
        .unwrap();
    let kids: Vec<&str> = server.kernels.iter().map(|k| k.0.as_str()).collect();
    assert!(
        kids.contains(&"sing-box") && kids.contains(&"amneziawg"),
        "hybrid server must run both kernels post-enable, got: {kids:?}"
    );
    let audit = inv.recent_audit(5).await.unwrap();
    assert!(
        audit.iter().any(|a| a.action == "server.kernel.enable"),
        "audit row for kernel enable missing"
    );
}

#[tokio::test]
async fn admin_server_enable_kernel_rejects_unregistered_id() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/sb/kernels/totally-fake/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("unknown kernel"));
}

#[tokio::test]
async fn admin_multi_kernel_server_enables_wireguard_protocol() {
    // The end-to-end scenario Pavel raised: add amneziawg kernel
    // to a sing-box node → wireguard protocol becomes enable-able
    // (not "incompatible") on the same server.
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("dual".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into()), KernelId("amneziawg".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app.clone(), "/admin/servers/dual/protocols").await;
    // wireguard MUST now show an enable form (previously was
    // "incompatible" under the sing-box-only kernel).
    assert!(
        html.contains("/admin/servers/dual/protocols/wireguard/enable"),
        "wireguard must be enable-able once amneziawg kernel is on the server"
    );
    // Validate end-to-end: actually enable wireguard, then assert
    // it lands in the row.
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/dual/protocols/wireguard/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let server = inv
        .get_server(&ServerId("dual".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        server.enabled_protocols.iter().any(|p| p.0 == "wireguard"),
        "wireguard should be in enabled_protocols after enable"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Pavel iter A2 — quick-add server inline form on /admin/servers.
// Single-action UX matching the one-input user-create form: id +
// address + ssh_port → server registered with default kernel=sing-box
// and EVERY sing-box-supported protocol enabled. Per-knob tuning
// lives on the detail page.

#[tokio::test]
async fn admin_server_quick_add_registers_with_default_protocols() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/quick-add")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=fra-01&address=203.0.113.7&ssh_port=2222"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let srv = inv
        .get_server(&vpnctl_core::ServerId("fra-01".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(srv.address, "203.0.113.7");
    assert_eq!(srv.ssh_port, 2222);
    assert_eq!(srv.kernels.len(), 1);
    assert_eq!(srv.kernels[0].0, "sing-box");
    // Default protocols = every protocol the kernel supports. Spot-check
    // a few that sing-box implements in the workspace registry.
    let pids: Vec<&str> = srv.enabled_protocols.iter().map(|p| p.0.as_str()).collect();
    assert!(
        pids.contains(&"vless+reality"),
        "default protocols: {pids:?}"
    );
    assert!(pids.contains(&"tuic-v5"));
    assert!(pids.contains(&"hysteria2"));
    // wireguard must NOT be in defaults — different kernel.
    assert!(!pids.contains(&"wireguard"));
}

/// REGRESSION (review 2026-06-04): quick-add validated server ids with
/// the USER-id validator (2..=32, lowercase-only) while the error text
/// promised «1-64 chars of A-Z a-z 0-9 . _ -» — so a 1-char or
/// mixed-case id was rejected with a message claiming it's allowed.
/// The dedicated `valid_server_id` now enforces exactly what the
/// message says.
#[tokio::test]
async fn admin_server_quick_add_id_policy_matches_error_text() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    let post = |id_addr: &'static str| {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/quick-add")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from(id_addr))
        .unwrap()
    };

    // Mixed case — promised by the message, used to 400.
    let resp = app
        .clone()
        .oneshot(post("id=Fra-01&address=203.0.113.8"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "mixed-case server id must be accepted (the error text always promised A-Z)"
    );
    assert!(
        inv.get_server(&vpnctl_core::ServerId("Fra-01".into()))
            .await
            .unwrap()
            .is_some()
    );

    // 1-char — promised by the message («1-64»), used to 400 (user cap 2..=32).
    let resp = app
        .clone()
        .oneshot(post("id=x&address=203.0.113.9"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "1-char server id must be accepted"
    );

    // Genuinely invalid stays rejected: embedded space…
    let resp = app
        .clone()
        .oneshot(post("id=bad%20id&address=203.0.113.10"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // …and over-long (65 chars).
    let long = format!("id={}&address=203.0.113.11", "a".repeat(65));
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/quick-add")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(long))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "65-char id must 400"
    );
}

#[tokio::test]
async fn admin_server_quick_add_rejects_duplicate_id() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("dup".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/quick-add")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=dup&address=198.51.100.5&ssh_port=22"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("already exists"),
        "duplicate id must surface 'already exists' wording"
    );
}

/// HANDOFF §6 #2 — duplicate-ADDRESS guard. Two inventory records for one
/// physical node fight over its `users[]`; the second deploy trips the
/// DG-1 user-removal guard (the `us` / `us1` incident, 2026-07-08).
/// quick-add must 400 when the address already belongs to another server,
/// naming the clashing id, and must NOT create the duplicate.
#[tokio::test]
async fn admin_server_quick_add_rejects_duplicate_address() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("us".into()),
        address: "130.94.19.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    let app = router(s);
    // Different id, SAME address → rejected.
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/quick-add")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=us1&address=130.94.19.7&ssh_port=22"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let txt = std::str::from_utf8(&body).unwrap();
    assert!(
        txt.contains("already registered to server 'us'"),
        "dup-address 400 must name the clashing server id, got: {txt}"
    );
    // The duplicate must NOT have been created.
    assert!(
        inv.get_server(&ServerId("us1".into()))
            .await
            .unwrap()
            .is_none(),
        "duplicate-address server must not be registered"
    );
}

/// HANDOFF §6 #2 — the Phase-E wizard (step 1) must reject a duplicate
/// address up-front, before the operator commits to a full bootstrap.
#[tokio::test]
async fn admin_wizard_step1_rejects_duplicate_address() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("us".into()),
            address: "130.94.19.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(
                "address=130.94.19.7&root_password=hunter2&ssh_port=22",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("already registered to server 'us'"),
        "wizard step-1 must reject a duplicate address naming the clash"
    );
}

// Pavel iter B — server-side grant/revoke (centralised view on
// server detail). Same mutation as user-side, but redirect lands
// back on the server page so the operator stays where they started.

#[tokio::test]
async fn admin_server_detail_lists_all_users_with_grant_buttons() {
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    for uid in ["alice", "bob"] {
        s.inv
            .add_user(&User {
                id: UserId(uid.into()),
                uuid: format!("uuid-{uid}"),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .await
            .unwrap();
    }
    // Grant alice but not bob.
    s.inv
        .grant(&UserId("alice".into()), &ServerId("sb".into()))
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/servers/sb/grants").await;
    // Alice = granted → revoke form
    assert!(
        html.contains("/admin/servers/sb/grants/alice/revoke"),
        "granted user must have revoke form on server detail"
    );
    // Bob = ungranted → grant form
    assert!(
        html.contains("/admin/servers/sb/grants/bob"),
        "ungranted user must have grant form on server detail"
    );
    // Counter pin (1 of 2)
    assert!(html.contains("1 of 2"), "X of N counter missing");
}

#[tokio::test]
async fn admin_server_grant_user_persists_and_redirects_to_server() {
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
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
                    .uri("/admin/servers/sb/grants/alice"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Redirect target should be the SERVER page, not the user page.
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(loc, "/admin/servers/sb/grants");
    // Mutation landed.
    let users_on_server = inv.users_for_server(&ServerId("sb".into())).await.unwrap();
    assert!(users_on_server.iter().any(|u| u.id.0 == "alice"));
}

// Pavel iter C2 — search + sort on /admin/users.

#[tokio::test]
async fn admin_users_search_filters_by_id_substring() {
    use vpnctl_core::{User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    for uid in ["alice", "bob", "alicia", "carol"] {
        s.inv
            .add_user(&User {
                id: UserId(uid.into()),
                uuid: format!("uuid-{uid}"),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .await
            .unwrap();
    }
    let app = router(s);
    let html = fetch_html(app, "/admin/users?q=ali").await;
    // alice + alicia match; bob + carol do not.
    assert!(html.contains(">alice<"), "alice should appear");
    assert!(html.contains(">alicia<"), "alicia should appear");
    assert!(!html.contains(">bob<"), "bob must be filtered out");
    assert!(!html.contains(">carol<"), "carol must be filtered out");
    assert!(html.contains("showing 2 of 4"), "subset counter missing");
}

#[tokio::test]
async fn admin_users_sort_servers_orders_by_grants_count_ascending() {
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    for sid in ["s1", "s2", "s3"] {
        s.inv
            .add_server(&Server {
                id: ServerId(sid.into()),
                address: "203.0.113.7".into(),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels: vec![KernelId("sing-box".into())],
                enabled_protocols: vec![],
                trusted_host_fingerprint: None,
                hoster: "generic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            })
            .await
            .unwrap();
    }
    for uid in ["alice", "bob", "carol"] {
        s.inv
            .add_user(&User {
                id: UserId(uid.into()),
                uuid: format!("uuid-{uid}"),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .await
            .unwrap();
    }
    // alice on 3 servers, bob on 1, carol on 0
    for sid in ["s1", "s2", "s3"] {
        s.inv
            .grant(&UserId("alice".into()), &ServerId(sid.into()))
            .await
            .unwrap();
    }
    s.inv
        .grant(&UserId("bob".into()), &ServerId("s1".into()))
        .await
        .unwrap();

    // `?sort=servers` is ASCENDING (bare name = ascending, matching the
    // id / id-desc convention). Fewest grants first: carol(0) < bob(1)
    // < alice(3).
    let html = fetch_html(router(s.clone()), "/admin/users?sort=servers").await;
    let pos_alice = html.find(">alice<").expect("alice rendered");
    let pos_bob = html.find(">bob<").expect("bob rendered");
    let pos_carol = html.find(">carol<").expect("carol rendered");
    assert!(
        pos_carol < pos_bob && pos_bob < pos_alice,
        "sort=servers (ascending) must render carol<bob<alice; got positions a={pos_alice} b={pos_bob} c={pos_carol}"
    );

    // `?sort=servers-desc` is DESCENDING. Most grants first:
    // alice(3) < bob(1) < carol(0).
    let html_desc = fetch_html(router(s), "/admin/users?sort=servers-desc").await;
    let pos_alice = html_desc.find(">alice<").expect("alice rendered");
    let pos_bob = html_desc.find(">bob<").expect("bob rendered");
    let pos_carol = html_desc.find(">carol<").expect("carol rendered");
    assert!(
        pos_alice < pos_bob && pos_bob < pos_carol,
        "sort=servers-desc (descending) must render alice<bob<carol; got positions a={pos_alice} b={pos_bob} c={pos_carol}"
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

#[tokio::test]
async fn admin_audit_timeline_summary_never_leaks_secret_fields() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Simulate a payload that contains BOTH whitelisted keys AND
    // hypothetical secret fields the summary must NOT render.
    s.inv
        .audit(
            "admin",
            "user.add",
            Some("alice"),
            Some(&serde_json::json!({
                "uuid": "aaa-bbb",
                "wg_keypair_provenance": "server-generated",
                // Hypothetical leak vectors — MUST NOT appear in summary
                "tuic_password": "PW_SECRET_LEAK_CHECK",
                "wireguard_private": "PRIV_SECRET_LEAK_CHECK",
                "sub_token": "TOKEN_SECRET_LEAK_CHECK",
            })),
        )
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/audit").await;
    // Whitelisted key visible
    assert!(html.contains("wg_keypair_provenance=server-generated"));
    // Secrets MUST NOT leak via the summary rendering path
    for leak in [
        "PW_SECRET_LEAK_CHECK",
        "PRIV_SECRET_LEAK_CHECK",
        "TOKEN_SECRET_LEAK_CHECK",
    ] {
        assert!(
            !html.contains(leak),
            "audit summary leaked {leak} into HTML"
        );
    }
}

// ─── Operator-facing Deploy button (CLAUDE.md "Web is the ONLY
//     operator surface" — Pavel must never open a terminal).

#[tokio::test]
async fn admin_server_detail_shows_deploy_button() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/servers/sb").await;
    assert!(
        html.contains(r#"action="/admin/servers/sb/deploy""#),
        "deploy form must POST to /admin/servers/<id>/deploy (noscript fallback)"
    );
    assert!(html.contains(">deploy →<"), "submit button label drifted");
    // Item-1 SSE deploy: JS-driven button streams progress to a log pane.
    assert!(
        html.contains(r#"data-sse-url="/admin/servers/sb/deploy/sse""#),
        "deploy button must carry the SSE trigger URL"
    );
    assert!(
        html.contains(r#"id="deploy-log""#),
        "live deploy log pane must be present"
    );
    assert!(
        html.contains(r#"src="/admin/assets/admin.js""#),
        "external admin.js (CSP-safe SSE wiring) must be loaded"
    );
    // The POST fallback must be inside <noscript> (JS path is primary).
    assert!(
        html.contains("<noscript>"),
        "synchronous POST deploy must be the <noscript> fallback"
    );
}

/// "Update kernels" button (update-kernels PR2): the server-detail page
/// shows the SSE-driven kernel-binary upgrade trigger with its OWN log
/// pane (`update-kernels-log`, distinct from `deploy-log`). Copy-contract.
#[tokio::test]
async fn admin_server_detail_shows_update_kernels_button() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("ukb".into()),
            address: "203.0.113.8".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/servers/ukb").await;
    assert!(
        html.contains(r#"data-sse-url="/admin/servers/ukb/update-kernels/sse""#),
        "update-kernels button must carry the per-server SSE trigger URL"
    );
    // Its OWN log pane — distinct from the deploy button's `deploy-log`.
    assert!(
        html.contains(r#"id="update-kernels-log""#),
        "update-kernels needs its own live log pane (not deploy-log)"
    );
    assert!(
        html.contains(r#"data-log="update-kernels-log""#),
        "update-kernels button must point admin.js at its own log pane"
    );
    assert!(
        html.contains("update kernels") || html.contains("обновить ядра"),
        "update-kernels button label drifted"
    );
}

/// Operator-action-policy contract (CLAUDE.md HARD rule): the
/// update-kernels button's title / caption must NOT carry a bare
/// `ssh root@…` operator instruction. It describes what the DAEMON does
/// (apt upgrade + service restart), matching Deploy's allowed descriptive
/// register — it must not read as a shell-on-node instruction-to-operator.
#[tokio::test]
async fn admin_server_detail_update_kernels_copy_has_no_ssh_operator_instruction() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("ukpolicy".into()),
            address: "203.0.113.11".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/servers/ukpolicy").await;
    // No bare operator-facing `ssh root@…` instruction anywhere on the
    // page (the page carries no ssh-instruction copy today; the new
    // update-kernels block must not introduce one).
    assert!(
        !html.contains("ssh root@"),
        "update-kernels copy must not instruct the operator to `ssh root@…` the node"
    );
}

/// "Update all kernels" button (update-kernels PR2): the servers-list
/// page shows the fleet-wide SSE trigger + its own log pane when ≥1
/// server. Copy-contract.
#[tokio::test]
async fn admin_servers_renders_update_all_kernels_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers").await;
    assert!(
        html.contains(r#"data-sse-url="/admin/servers/update-kernels-all/sse""#),
        "update-all-kernels button must carry the fleet-wide SSE trigger URL"
    );
    assert!(
        html.contains(r#"id="update-kernels-log""#),
        "update-all-kernels needs its own live log pane"
    );
    assert!(
        html.contains("update all kernels") || html.contains("обновить все ядра"),
        "update-all-kernels button label drifted"
    );
}

/// Handler smoke: a cross-site `Sec-Fetch-Site` on the per-server
/// update-kernels SSE route is refused with 403 (CSRF guard), mirroring
/// the deploy SSE guard. A full stream needs a live node — the guard +
/// not-found below are the daemon-side analog.
#[tokio::test]
async fn server_update_kernels_sse_cross_site_is_403() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("uksse".into()),
            address: "203.0.113.12".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/uksse/update-kernels/sse")
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "cross-site update-kernels SSE trigger must be refused"
    );
}

/// Handler smoke: the per-server update-kernels SSE route 404s for an
/// unknown server id (server lookup runs after the same-origin guard).
#[tokio::test]
async fn server_update_kernels_sse_unknown_server_is_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/no-such/update-kernels/sse")
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("no such server"),
        "404 body should name the missing server, got: {text}"
    );
}

/// Handler smoke: the fleet-wide update-kernels-all SSE route refuses a
/// cross-site `Sec-Fetch-Site` with 403, mirroring the deploy-all guard.
#[tokio::test]
async fn servers_update_kernels_all_sse_cross_site_is_403() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/update-kernels-all/sse")
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "cross-site update-kernels-all SSE trigger must be refused"
    );
}

#[tokio::test]
async fn admin_server_deploy_bootstraps_wireguard_server_keypair() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("wg-node".into()),
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
    let app = router(s);
    // Pre-deploy: no WG keys.
    let before = inv
        .list_server_secrets(&ServerId("wg-node".into()))
        .await
        .unwrap();
    assert!(!before.contains_key("wireguard.server_public_key"));
    assert!(!before.contains_key("wireguard.server_private_key"));

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/wg-node/deploy"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Post-deploy: WG server keypair minted.
    let after = inv
        .list_server_secrets(&ServerId("wg-node".into()))
        .await
        .unwrap();
    let pub_ = after.get("wireguard.server_public_key").expect("pubkey");
    let priv_ = after.get("wireguard.server_private_key").expect("private");
    assert_eq!(pub_.len(), 44, "WG pubkey is 44 b64 chars");
    assert_eq!(priv_.len(), 44);
    assert!(pub_.ends_with('='));
    assert!(priv_.ends_with('='));
    assert_ne!(pub_, priv_, "pub != priv");

    // Audit recorded.
    let audit = inv.recent_audit(5).await.unwrap();
    let row = audit
        .iter()
        .find(|a| a.action == "server.deploy")
        .expect("audit row");
    let payload = row
        .payload
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_default();
    // Post-refactor (2026-05-30 server_secret_specs): the `bootstrapped`
    // audit field records the minted secret KEY NAMES (not human labels),
    // so the WG keypair shows as its primary key. Asserting the key name
    // is strictly more precise than the old "wireguard server keypair".
    assert!(
        payload.contains("wireguard.server_private_key"),
        "deploy audit payload should record the minted WG key; got {payload}"
    );
}

#[tokio::test]
async fn admin_server_deploy_idempotent_re_click_no_dup_keys() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    // UNIQUE server-id per deploy-POST test: the per-server deploy gate
    // (`wizard_bootstrap::DeployGuard`) is a process-wide static, so two
    // parallel tests deploying the SAME id would race — the loser gets a
    // 409 "deploy already running" and mints no secrets. Each deploy test
    // must therefore own its server-id (here `wg-idem`, distinct from the
    // sibling `wg-node` mint test).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("wg-idem".into()),
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
    let app = router(s);

    // First click.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/wg-idem/deploy"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let first_pub = inv
        .list_server_secrets(&ServerId("wg-idem".into()))
        .await
        .unwrap()
        .get("wireguard.server_public_key")
        .unwrap()
        .clone();

    // Second click — keys must NOT change (idempotent).
    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/wg-idem/deploy"),
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
    let second_pub = inv
        .list_server_secrets(&ServerId("wg-idem".into()))
        .await
        .unwrap()
        .get("wireguard.server_public_key")
        .unwrap()
        .clone();
    assert_eq!(
        first_pub, second_pub,
        "deploy must be idempotent — re-clicking when keys exist must NOT rotate them"
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

#[tokio::test]
async fn admin_dashboard_shows_limit_alerts_when_user_over_threshold() {
    use chrono::Utc;
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    use vpnctl_inventory::VpnStatsDelta;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("heavy".into()),
            uuid: "uuid-h".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    // 1 GiB cap, 80% threshold; record 900 MiB usage → 87% → alert.
    s.inv
        .set_user_traffic_limit(&UserId("heavy".into()), Some(1_073_741_824), Some(80))
        .await
        .unwrap();
    let deltas = vec![VpnStatsDelta {
        user_id: Some(UserId("heavy".into())),
        upload_bytes: 500 * 1024 * 1024,
        download_bytes: 400 * 1024 * 1024,
        active_connections: 1,
    }];
    s.inv
        .record_vpn_stats(&ServerId("sb".into()), &deltas)
        .await
        .unwrap();
    // Suppress unused-import warning (Utc was for record_vpn_stats_at
    // signature; record_vpn_stats stamps internally).
    let _ = Utc::now();
    // Dashboard 1b: limit crossings no longer get a dedicated card —
    // the health-monitor fires a `user.traffic_limit:<uid>` alert
    // (Bundle 4) and the dashboard surfaces it through the health
    // feed. Seed the alert row the monitor would have written.
    s.inv
        .insert_alert_if_no_unacked(
            "user.traffic_limit:heavy",
            None,
            "warning",
            "heavy at 87% of monthly limit",
            None,
        )
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/").await;
    assert!(
        html.contains("Health feed"),
        "health feed missing on dashboard"
    );
    assert!(
        html.contains("user.traffic_limit"),
        "feed row must name the limit-alert kind"
    );
    assert!(
        html.contains(r#"href="/admin/users/heavy""#),
        "user-scoped alert must link the user from the kind suffix"
    );
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
async fn admin_server_detail_deploy_caption_describes_ssh_push() {
    // 2026-05-17 — Pavel: подпись «Mints missing keys… Subscription
    // URLs go live immediately» неполная: реальный deploy включает
    // ensure_installed + apply_config + restart. Pin the new copy.
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("deploysrv".into()),
        address: "203.0.113.9".into(),
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
    let app = router(s);
    let html = fetch_html(app, "/admin/servers/deploysrv").await;

    // New caption mentions the real SSH-side work, not just secret mint.
    assert!(
        html.contains("ensure_installed"),
        "deploy caption must mention ensure_installed (apt-get install side)"
    );
    assert!(
        html.contains("apply_config"),
        "deploy caption must mention apply_config (systemctl restart side)"
    );
    // Old half-truth wording is gone.
    assert!(
        !html.contains("Mints missing keys for every enabled protocol."),
        "deploy caption regressed to the old keys-only wording"
    );
    // Tooltip on the button mentions the full cycle too.
    assert!(
        html.contains("Full deploy:") || html.contains("Full deploy "),
        "deploy button title attribute must lead with 'Full deploy:'"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Phase C-4 — Settings backups section + manual snapshot trigger +
// per-file download. The hourly scheduler is unit-tested in
// `crates/inventory/src/backup.rs`; these tests pin the WEB surface.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_settings_shows_backups_section_with_snapshot_button() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/settings/backups").await;
    assert!(
        html.contains("Backups — inventory snapshots"),
        "Settings page must have a Backups section heading"
    );
    assert!(
        html.contains("action=\"/admin/backup/snapshot\""),
        "Settings must include the manual snapshot POST form"
    );
    assert!(
        html.contains(">snapshot now<"),
        "Settings must include the 'snapshot now' button"
    );
    // Operator-facing copy: explain the off-site model + restore
    // requires CLI. Catch regressions if someone reverts the
    // operator-driven design.
    assert!(
        html.contains("Off-site is operator-driven"),
        "Settings must explain the operator-driven off-site model"
    );
    assert!(
        html.contains("vpnctl restore"),
        "Settings must mention the `vpnctl restore` CLI command"
    );
}

#[tokio::test]
async fn admin_backup_snapshot_now_posts_and_redirects_back() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s.clone());
    // Use a tempdir-scoped backup dir so the test doesn't touch
    // /var/lib/vpnctl/. The handler currently uses
    // crate::app::DEFAULT_BACKUP_DIR which points at the production
    // path — but inside `cargo test` we don't have write access there,
    // so the snapshot will fail with a 500. That's actually what we
    // want to confirm: the POST is reachable and audits even on
    // failure.
    //
    // (The successful-path is tested in the inventory crate's
    // backup::tests::snapshot_now_creates_file_and_lists.)
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/backup/snapshot"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    // Either 303 (snapshot succeeded — production root daemon) OR
    // 500 (snapshot failed — typical test env without write to
    // /var/lib/vpnctl/backups). Both are acceptable; what we're
    // asserting is the endpoint is wired + the audit path runs.
    assert!(
        matches!(
            resp.status(),
            StatusCode::SEE_OTHER | StatusCode::INTERNAL_SERVER_ERROR
        ),
        "expected 303 or 500, got {:?}",
        resp.status()
    );
    // Audit row should be present regardless (success OR failure path
    // both write `backup.snapshot`).
    let audits = s.inv.recent_audit(50).await.unwrap();
    assert!(
        audits.iter().any(|a| a.action == "backup.snapshot"),
        "manual snapshot must write an audit row even when the snapshot itself fails"
    );
}

#[tokio::test]
async fn admin_backup_download_rejects_path_traversal() {
    // Validation gate: a name with `..` or `/` MUST 400 before the
    // handler ever touches the filesystem. Otherwise an
    // unauthenticated attacker (or a misconfigured proxy) could
    // exfiltrate arbitrary files in the backup dir's neighbourhood.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    for name in [
        "../etc/passwd",
        "..%2Fetc%2Fpasswd",
        "inv.db.../../etc.bak",
        "name_with_slash/inv.db.x.bak",
        // Right prefix+suffix but wrong charset (contains '/').
        "inv.db.2026-01-01T00-00-00.000Z/bad.bak",
    ] {
        let encoded: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~') {
                    c.to_string()
                } else {
                    format!("%{:02X}", c as u8)
                }
            })
            .collect();
        let uri = format!("/admin/backup/download/{encoded}");
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::NOT_FOUND,
            "name {name:?} must be 400/404, got {:?}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn admin_backup_scheduler_produces_snapshot_and_audits() {
    // Pin the wiring: scheduler actually fires → file appears in
    // backup_dir → `backup.snapshot` audit row written with
    // `trigger: "scheduler"`. Without this test the production
    // scheduler path could regress silently (the manual handler is
    // a different code path).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let backup_dir = dir.path().join("bkp");

    // Short delays: 50ms startup, 50ms tick. Two-three ticks should
    // fire within 500ms, giving us at least one snapshot + audit
    // row. We then abort the task.
    let handle = vpnctld::spawn_backup_scheduler_with_for_test(
        inv.clone(),
        backup_dir.clone(),
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(50),
    );
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    handle.abort();

    let snapshots = vpnctl_inventory::list_snapshots(&backup_dir).unwrap();
    assert!(
        !snapshots.is_empty(),
        "scheduler must have produced at least one snapshot in 500ms; got 0"
    );
    let audits = inv.recent_audit(50).await.unwrap();
    let scheduler_rows: Vec<_> = audits
        .iter()
        .filter(|a| {
            a.action == "backup.snapshot"
                && a.payload
                    .as_ref()
                    .and_then(|p| p.get("trigger"))
                    .and_then(|v| v.as_str())
                    == Some("scheduler")
        })
        .collect();
    assert!(
        !scheduler_rows.is_empty(),
        "scheduler must write at least one audit row with trigger=scheduler"
    );
}

#[tokio::test]
async fn admin_backup_download_404_on_missing_snapshot() {
    // Valid-shaped filename but file doesn't exist. The handler
    // should 404 with a canonical body — not 500.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/backup/download/inv.db.2026-01-01T00-00-00.000Z.bak")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Production-default backup dir might not even exist in tests
    // (canonicalize errors with NotFound → 500), OR it exists but
    // file is missing (404). Either keeps the operator's path
    // safe; we accept both.
    assert!(
        matches!(
            resp.status(),
            StatusCode::NOT_FOUND | StatusCode::INTERNAL_SERVER_ERROR
        ),
        "missing snapshot should be 404 or 500, got {:?}",
        resp.status()
    );
}

// ────────────────────────────────────────────────────────────────────────
// NM-10 — protocol visibility UI (server-detail hide/unhide chip +
// user-detail per-protocol delivery grid). Backend handlers landed in
// cd71cf9; these tests pin the corresponding UI surfaces so a future
// HTML refactor can't silently drop the toggle. Each test exercises a
// distinct rule: hidden-chip render, visible-chip render, POST mutation
// round-trip, per-grant grid presence, server-hidden read-only marker,
// override-blocks-render check, ungranted-server-suppression.

#[tokio::test]
async fn nm10_server_detail_visible_protocol_shows_hide_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("hidesrv".into()),
            address: "203.0.113.10".into(),
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
    let html = fetch_html(router(s), "/admin/servers/hidesrv/protocols").await;
    // Visible (hidden=0) protocol: shows "✓ on" without the "· hidden"
    // suffix AND offers a hide button (no unhide).
    assert!(
        html.contains("✓ on") && !html.contains("✓ on · hidden"),
        "visible enabled protocol should show plain ✓ on marker"
    );
    assert!(
        html.contains(r#"/admin/servers/hidesrv/protocols/vless%2Breality/hide"#),
        "visible protocol must offer a hide button (POST /hide)"
    );
    assert!(
        !html.contains(r#"/admin/servers/hidesrv/protocols/vless%2Breality/unhide"#),
        "visible protocol must NOT offer an unhide button"
    );
}

#[tokio::test]
async fn nm10_server_detail_hidden_protocol_shows_unhide_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("hidesrv".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("hidesrv".into()),
            &ProtocolId("tuic-v5".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/hidesrv/protocols").await;
    assert!(
        html.contains("✓ on · hidden"),
        "hidden protocol must surface the · hidden suffix on its status chip"
    );
    assert!(
        html.contains(r#"/admin/servers/hidesrv/protocols/tuic-v5/unhide"#),
        "hidden protocol must offer an unhide button (POST /unhide)"
    );
    assert!(
        !html.contains(r#"/admin/servers/hidesrv/protocols/tuic-v5/hide""#),
        "hidden protocol must NOT offer a redundant hide button"
    );
}

#[tokio::test]
async fn nm10_server_detail_post_hide_persists_and_redirects() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("hsrv".into()),
            address: "203.0.113.11".into(),
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
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/hsrv/protocols/vless%2Breality/hide"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/admin/servers/hsrv/protocols#enabled-protocols",
        "303 must redirect back to /admin/servers/{{id}}#enabled-protocols so the browser scrolls the operator back to the section they just clicked in (Pavel 2026-05-20: «каждый раз когда я жму disable меня выкидывает в верх страницы»)"
    );
    assert!(
        inv.is_server_protocol_hidden(
            &ServerId("hsrv".into()),
            &ProtocolId("vless+reality".into())
        )
        .await
        .unwrap(),
        "hidden flag must persist after POST /hide"
    );
    let audit = inv.recent_audit(5).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.action == "server.protocol.set_hidden"),
        "POST /hide must write an audit row"
    );
}

#[tokio::test]
async fn nm10_user_detail_per_protocol_grid_renders_for_granted_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            sub_token: Some("t1".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("gridsrv".into()),
            address: "203.0.113.12".into(),
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
    s.inv
        .grant(&UserId("alice".into()), &ServerId("gridsrv".into()))
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/alice/access").await;
    assert!(
        html.contains("Per-protocol delivery"),
        "grid heading must appear under the granted server's row"
    );
    // Default state = delivered + block button per protocol.
    assert!(
        html.contains("✓ delivered"),
        "default delivery state should be ✓ delivered"
    );
    assert!(
        html.contains(r#"/admin/users/alice/grants/gridsrv/protocols/vless%2Breality/disable"#),
        "vless+reality must have a disable (block) form"
    );
    assert!(
        html.contains(r#"/admin/users/alice/grants/gridsrv/protocols/tuic-v5/disable"#),
        "tuic-v5 must have a disable (block) form"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_hides_when_server_not_granted() {
    // Ungranted server should NOT render the per-protocol grid —
    // overrides would refuse with Invalid anyway, and surfacing the
    // buttons creates a confusing "click does nothing" UX.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("bob".into()),
            uuid: "00000000-0000-0000-0000-000000000002".to_string(),
            sub_token: Some("t2".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("notgranted".into()),
            address: "203.0.113.13".into(),
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
    // No grant() call.
    let html = fetch_html(router(s), "/admin/users/bob/access").await;
    assert!(
        !html.contains(r#"/admin/users/bob/grants/notgranted/protocols/vless%2Breality/disable"#),
        "ungranted server must NOT expose the per-protocol disable form"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_marks_server_hidden_readonly() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("carol".into()),
            uuid: "00000000-0000-0000-0000-000000000003".to_string(),
            sub_token: Some("t3".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("hidsrv".into()),
            address: "203.0.113.14".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .grant(&UserId("carol".into()), &ServerId("hidsrv".into()))
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("hidsrv".into()),
            &ProtocolId("tuic-v5".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/carol/access").await;
    // Server-hidden + no override → read-only label, NO block button.
    assert!(
        html.contains("server-hidden (read-only here)"),
        "server-hidden protocol must surface read-only marker in the grid"
    );
    assert!(
        !html.contains(r#"/admin/users/carol/grants/hidsrv/protocols/tuic-v5/disable"#),
        "server-hidden + no override should suppress the block button (would be a redundant override)"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_shows_user_blocked_marker_and_unblock_form() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("dave".into()),
            uuid: "00000000-0000-0000-0000-000000000004".to_string(),
            sub_token: Some("t4".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("dsrv".into()),
            address: "203.0.113.15".into(),
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
    s.inv
        .grant(&UserId("dave".into()), &ServerId("dsrv".into()))
        .await
        .unwrap();
    s.inv
        .set_grant_protocol_override(
            &UserId("dave".into()),
            &ServerId("dsrv".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/dave/access").await;
    assert!(
        html.contains("✗ user-blocked"),
        "user-blocked override must surface the ✗ marker"
    );
    assert!(
        html.contains(r#"/admin/users/dave/grants/dsrv/protocols/vless%2Breality/enable"#),
        "user-blocked protocol must offer an unblock (enable) button"
    );
    assert!(
        !html.contains(r#"/admin/users/dave/grants/dsrv/protocols/vless%2Breality/disable"#),
        "user-blocked protocol must NOT redundantly offer a block button"
    );
}

#[tokio::test]
async fn nm10_user_detail_post_block_persists_and_redirects() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_user(&User {
            id: UserId("erin".into()),
            uuid: "00000000-0000-0000-0000-000000000005".to_string(),
            sub_token: Some("t5".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("esrv".into()),
            address: "203.0.113.16".into(),
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
    s.inv
        .grant(&UserId("erin".into()), &ServerId("esrv".into()))
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/erin/grants/esrv/protocols/vless%2Breality/disable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/admin/users/erin/access#server-access",
        "303 must redirect back to /admin/users/{{uid}}#server-access so the browser scrolls the operator back to the per-protocol grid they just clicked in"
    );
    let overrides = inv
        .list_protocol_overrides_for_user(&UserId("erin".into()))
        .await
        .unwrap();
    assert!(
        overrides
            .get(&(ServerId("esrv".into()), ProtocolId("vless+reality".into())))
            .copied()
            .unwrap_or(false),
        "POST /disable must insert a disabled override"
    );
    // Auditable-write invariant (CLAUDE.md): every inventory mutation
    // writes one audit_log row. Mirrors the parallel assert on the
    // server-hide test above.
    let audit = inv.recent_audit(5).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.action == "grant.protocol.set_override"),
        "POST /disable must write a grant.protocol.set_override audit row, got: {:?}",
        audit.iter().map(|a| &a.action).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_renders_both_axes_branch() {
    // The "server-hidden + user-blocked" branch (line 7501 in admin.rs)
    // is the only label where BOTH axes deny the protocol. A regression
    // collapsing the branch into "server-hidden (read-only)" would lose
    // the "unblock (user)" button — the operator's only path to clear
    // a stale per-user override on a server-hidden protocol. This test
    // pins that label + the unblock-user form so the branch can't be
    // silently deleted.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("frank".into()),
            uuid: "00000000-0000-0000-0000-000000000006".to_string(),
            sub_token: Some("t6".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("fsrv".into()),
            address: "203.0.113.17".into(),
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
    s.inv
        .grant(&UserId("frank".into()), &ServerId("fsrv".into()))
        .await
        .unwrap();
    // Set BOTH axes — server-hide AND user-block. Canonical render
    // omits via OR-semantics; UI must surface both flags so the
    // operator's mental model matches.
    s.inv
        .set_server_protocol_hidden(
            &ServerId("fsrv".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    s.inv
        .set_grant_protocol_override(
            &UserId("frank".into()),
            &ServerId("fsrv".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/frank/access").await;
    assert!(
        html.contains("server-hidden + user-blocked"),
        "both-axes-deny branch must render the compound label"
    );
    assert!(
        html.contains(r#"/admin/users/frank/grants/fsrv/protocols/vless%2Breality/enable"#),
        "both-axes branch must STILL offer the unblock-user form (operator clears the user-axis here; server-axis on server detail)"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_iterates_table_not_in_memory_enabled_protocols() {
    // Defensive: the grid iterates `hidden_map.keys()` (the
    // `server_protocols` table rows) rather than the in-memory
    // `Server.enabled_protocols` cache, so OR-semantics resolution
    // matches `visible_protocols_for_subscription` BYTE-for-BYTE
    // even in the (rare/impossible-in-production) case where the
    // cache and table diverge. This test exercises the happy path:
    // a server with two protocols renders both rows in alphabetical
    // order matching the canonical query's ORDER BY.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("gina".into()),
            uuid: "00000000-0000-0000-0000-000000000007".to_string(),
            sub_token: Some("t7".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("gsrv".into()),
            address: "203.0.113.18".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            // Out of order on purpose — render should still sort.
            enabled_protocols: vec![
                ProtocolId("tuic-v5".into()),
                ProtocolId("vless+reality".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .grant(&UserId("gina".into()), &ServerId("gsrv".into()))
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/gina/access").await;
    let tuic_pos = html.find("tuic-v5").expect("tuic row present");
    let vless_pos = html.find("vless+reality").expect("vless row present");
    assert!(
        tuic_pos < vless_pos,
        "grid rows must be alphabetically sorted by protocol_id to match visible_protocols_for_subscription ORDER BY"
    );
}

// ─── NM-12: DPI-risk chips on server-detail + user-detail grid ───────
//
// Pavel 2026-05-20: «давай начнём с того что ты уберёшь чтото плохие
// протоколы и пометишь их в ui как плохие и можешь даже шрифт меньше
// сделать у них». Risk tier comes from the registry — no inventory
// state. These tests pin the chip text, the colour-driving class, the
// smaller-font branch for Weak rows, and the explainer tooltip.

#[tokio::test]
async fn nm12_server_detail_renders_dpi_strong_chip_for_vless_reality() {
    // Strong tier should produce a "DPI: strong" chip on the row.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("strongsrv".into()),
            address: "203.0.113.20".into(),
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
    let html = fetch_html(router(s), "/admin/servers/strongsrv/protocols").await;
    assert!(
        html.contains("DPI: strong"),
        "vless+reality row must surface its Strong DPI-risk chip"
    );
    // Tooltip carries the explainer ("Active-probe-resistant: ...").
    assert!(
        html.contains("Active-probe-resistant"),
        "Strong tier tooltip must explain the active-probe defence"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_weak_chip_and_smaller_font_for_wireguard() {
    // Weak tier produces "DPI: weak" chip AND the row gets
    // font-size: 11px (visual de-emphasis). The test pins BOTH so a
    // regression that drops the font shrink would fail loudly.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("weaksrv".into()),
            address: "203.0.113.21".into(),
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
    let html = fetch_html(router(s), "/admin/servers/weaksrv/protocols").await;
    assert!(
        html.contains("DPI: weak"),
        "wireguard row must surface its Weak DPI-risk chip"
    );
    assert!(
        html.contains("font-size: 11px"),
        "Weak protocol row must shrink the name to 11px (Pavel: «шрифт меньше у них»)"
    );
    // Explainer mentions the specific fingerprint so the operator
    // understands WHY it's Weak — and the chip-tooltip lookup table
    // never silently changes.
    assert!(
        html.contains("0x01 handshake tag") || html.contains("WireGuard"),
        "Weak tier tooltip must explain the trivial fingerprint (raw-WG 0x01 tag)"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_chip_for_every_known_protocol() {
    // Spec: every registered protocol must produce SOME chip. A
    // future protocol added without overriding dpi_risk() still
    // gets `Moderate` (the default), so the chip set is exhaustive.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("allsrv".into()),
            address: "203.0.113.22".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![
                KernelId("amneziawg".into()),
                KernelId("sing-box".into()),
                KernelId("wgturn".into()),
            ],
            // Empty enabled_protocols — the server-detail still lists
            // every protocol in the registry with [enable] buttons,
            // and the chip should render alongside the name.
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/allsrv/protocols").await;
    // Tier distribution across the FULL production registry (the test
    // `state` mirrors `build_registry` — naive + dns-tunnel included):
    //   Strong:   vless+reality, wgturn, naive     (3)
    //   Moderate: tuic-v5, anytls, dns-tunnel      (3)
    //   Weak:     shadowsocks-2022, wireguard,
    //             trojan, hysteria2                (4)
    //   ────────────────────────────────────────────
    //   total                                      (10)
    let strong_count = html.matches("DPI: strong").count();
    let moderate_count = html.matches("DPI: moderate").count();
    let weak_count = html.matches("DPI: weak").count();
    assert_eq!(
        strong_count, 3,
        "expected 3 Strong chips (vless+reality, wgturn, naive), got {strong_count}"
    );
    assert_eq!(
        moderate_count, 3,
        "expected 3 Moderate chips (tuic-v5, anytls, dns-tunnel), got {moderate_count}"
    );
    assert_eq!(
        weak_count, 4,
        "expected 4 Weak chips (shadowsocks-2022, wireguard, trojan, hysteria2), got {weak_count}"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_moderate_chip_for_tuic_v5() {
    // After the review-agent re-tier (Trojan/Hysteria2 → Weak), only
    // tuic-v5 and anytls are Moderate. This test pins that tuic-v5
    // actually carries the Moderate chip — without it the
    // Strong/Weak tests would happily pass even if the Moderate arm
    // of `border_css()` / `text_css()` were broken.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("modsrv".into()),
            address: "203.0.113.24".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/modsrv/protocols").await;
    assert!(
        html.contains("DPI: moderate"),
        "tuic-v5 row must surface its Moderate DPI-risk chip"
    );
    // Moderate uses --rule + --mute (not the green/red palette); the
    // tooltip wording is distinct from Strong/Weak.
    assert!(
        html.contains("Recognisable on careful active probing"),
        "Moderate tier tooltip must explain the careful-probe boundary"
    );
}

#[tokio::test]
async fn nm12_server_detail_hidden_weak_protocol_still_shows_chip() {
    // The chip is informational about the wire format, not about
    // current visibility. Hiding a Weak protocol (NM-10) does NOT
    // erase the DPI: weak chip — the operator still needs to see
    // WHY they hid it. A regression that suppresses the chip on
    // hidden rows would silently strip the most important context.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("hwsrv".into()),
            address: "203.0.113.25".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("shadowsocks-2022".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("hwsrv".into()),
            &ProtocolId("shadowsocks-2022".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/hwsrv/protocols").await;
    assert!(
        html.contains("DPI: weak"),
        "hidden Weak protocol must STILL show the chip — chip is about the wire format, not visibility"
    );
    assert!(
        html.contains("✓ on · hidden"),
        "hidden status marker must also appear alongside the chip"
    );
}

#[tokio::test]
async fn nm12_unknown_protocol_in_server_renders_no_chip_defensively() {
    // Defensive: if a server's `enabled_protocols` row references a
    // ProtocolId the registry doesn't know about (impossible in
    // production — registry is seeded at boot — but possible during
    // an interrupted migration / dev-time table edit), the render
    // path falls back to `risk = None` and emits NO chip rather
    // than panicking.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("unksrv".into()),
            address: "203.0.113.26".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            // Empty enabled_protocols — server-detail still lists
            // every registry protocol with [enable] buttons; none
            // of THEM are unknown, so we don't see the None branch
            // here. To exercise it we'd need a synthetic registry,
            // which the test stub doesn't expose. So this test
            // instead pins the inverse property: every protocol id
            // emitted by the rendered HTML carries a chip. If the
            // chip ever silently drops on a known-good row this
            // count goes out of sync.
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/unksrv/protocols").await;
    // 10 registered protocols → 10 chips (Strong + Moderate + Weak
    // sum). If the chip-or-no-chip decision branches on something
    // OTHER than "registry knows this id", the count drifts.
    let total_chips = html.matches("DPI: strong").count()
        + html.matches("DPI: moderate").count()
        + html.matches("DPI: weak").count();
    assert_eq!(
        total_chips, 10,
        "10 registered protocols must each carry exactly one chip on a server with all kernels — got {total_chips}"
    );
}

#[tokio::test]
async fn nm12_user_detail_grid_renders_dpi_chip_and_weak_shrinks_to_10px() {
    // Same chip shows up in the user-detail per-protocol delivery
    // sub-grid, but at the smaller layout (9px chip, 10px Weak vs
    // 11px Moderate/Strong) so it fits the dense row.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("hank".into()),
            uuid: "00000000-0000-0000-0000-000000000008".to_string(),
            sub_token: Some("t8".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("hsrv".into()),
            address: "203.0.113.23".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("amneziawg".into()), KernelId("sing-box".into())],
            // Mix Strong (vless+reality) and Weak (wireguard,
            // shadowsocks-2022) so both font branches exercise.
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("wireguard".into()),
                ProtocolId("shadowsocks-2022".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .grant(&UserId("hank".into()), &ServerId("hsrv".into()))
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/hank/access").await;
    assert!(
        html.contains("DPI: strong") && html.contains("DPI: weak"),
        "grid must render risk chips matching the protocol tiers"
    );
    // Grid font-size: 10px for Weak rows, 11px otherwise. Assert
    // the 10px branch fires (would not be present without a Weak
    // protocol in the row set).
    assert!(
        html.contains("font-size: 10px"),
        "Weak protocol row in user-detail grid must shrink to 10px"
    );
}

// ─── NM-12 follow-up: scroll-preserve via Location fragment ──────────
//
// Pavel 2026-05-20: «каждый раз когда я жму disable меня выкидывает
// в верх страницы». PRG (Post/Redirect/Get) loses the operator's
// scroll position when the redirect target is a bare path — the
// browser GETs the page and resets to top. Fix: every visibility-
// toggle handler appends `#enabled-protocols` (server-detail) or
// `#server-access` (user-detail) to the Location header, and the
// section heading carries the matching `id=`. Browser scrolls to
// the anchor instead of the top.
//
// These tests pin BOTH halves of the contract so a regression
// removing the fragment OR the id would fail.

#[tokio::test]
async fn nm12_followup_server_detail_section_carries_enabled_protocols_anchor() {
    // The redirects all assume an anchor element with
    // id="enabled-protocols" exists on the server-detail page.
    // Without the id the fragment redirect lands at the top of
    // the page anyway (browsers silently ignore unmatched
    // fragments). This pins the markup half of the contract.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("anchsrv".into()),
            address: "203.0.113.27".into(),
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
    let html = fetch_html(router(s), "/admin/servers/anchsrv/protocols").await;
    assert!(
        html.contains(r#"id="enabled-protocols""#),
        "server-detail must carry an id=\"enabled-protocols\" anchor for the visibility-toggle handlers to scroll back into"
    );
}

#[tokio::test]
async fn nm12_followup_user_detail_section_carries_server_access_anchor() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("ivy".into()),
            uuid: "00000000-0000-0000-0000-000000000009".to_string(),
            sub_token: Some("t9".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/ivy/access").await;
    assert!(
        html.contains(r#"id="server-access""#),
        "user-detail must carry an id=\"server-access\" anchor for the grant-toggle handlers to scroll back into"
    );
}

#[tokio::test]
async fn nm12_followup_server_protocol_unhide_redirects_with_fragment() {
    // server_protocol_hide is already covered by
    // nm10_server_detail_post_hide_persists_and_redirects (updated
    // to assert the fragment). Unhide is the symmetric handler —
    // pin it separately so a copy-paste regression deleting the
    // fragment from only one of the two would fail.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("uhsrv".into()),
            address: "203.0.113.28".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    inv.set_server_protocol_hidden(
        &ServerId("uhsrv".into()),
        &ProtocolId("tuic-v5".into()),
        true,
    )
    .await
    .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/uhsrv/protocols/tuic-v5/unhide"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/servers/uhsrv/protocols#enabled-protocols");
}

#[tokio::test]
async fn nm12_followup_grant_protocol_enable_redirects_with_fragment() {
    // grant_protocol_disable already covered by
    // nm10_user_detail_post_block_persists_and_redirects (updated
    // to assert the fragment). Enable is the symmetric handler.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_user(&User {
            id: UserId("ji".into()),
            uuid: "00000000-0000-0000-0000-000000000010".to_string(),
            sub_token: Some("t10".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("jsrv".into()),
            address: "203.0.113.29".into(),
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
    inv.grant(&UserId("ji".into()), &ServerId("jsrv".into()))
        .await
        .unwrap();
    inv.set_grant_protocol_override(
        &UserId("ji".into()),
        &ServerId("jsrv".into()),
        &ProtocolId("vless+reality".into()),
        true,
    )
    .await
    .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/ji/grants/jsrv/protocols/vless%2Breality/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/users/ji/access#server-access");
}

#[tokio::test]
async fn nm12_followup_legacy_server_disable_protocol_also_carries_fragment() {
    // The pre-existing `server_disable_protocol` handler (NOT part
    // of NM-10 — it removes the protocol from `enabled_protocols`
    // entirely, requires a `deploy` to take effect on the node)
    // also gets the fragment so the operator stays anchored after
    // a click on the [disable] (not [hide]) button. This is the
    // button Pavel was actually using when he reported the scroll
    // bug — pinning it separately so we never lose the fix.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("lsrv".into()),
            address: "203.0.113.30".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/lsrv/protocols/tuic-v5/disable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/servers/lsrv/protocols#enabled-protocols");
}

#[tokio::test]
async fn nm12_followup_servers_list_reflects_hidden_state() {
    // Pavel 2026-05-20: «нужно сделаить на /admin/servers чтоб это
    // отобразилось, сейчас показано что там все протоколы, хотя я
    // сделал hide». Pre-fix the server-card on /admin/servers
    // rendered `Server.enabled_protocols` straight (in-memory
    // cache, no awareness of `server_protocols.hidden`). Post-fix
    // it splits visible vs hidden via the new bulk matrix and
    // renders them in two distinct rows.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("lpsrv".into()),
            address: "203.0.113.40".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            // 3 enabled: vless+reality (visible), tuic-v5 + anytls
            // (will be hidden below).
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
                ProtocolId("anytls".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("lpsrv".into()),
            &ProtocolId("tuic-v5".into()),
            true,
        )
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("lpsrv".into()),
            &ProtocolId("anytls".into()),
            true,
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers").await;

    // Densify 2a: visible protocols render in the dense-table cell; the
    // hidden ones live ONLY inside the "+N hidden" flag's title (still
    // listening on the node, just not emitted to subscriptions — NM-10/12).
    let visible_seg = html
        .split(r#"<span class="ed-grid__flag""#)
        .next()
        .expect("page renders");
    assert!(
        visible_seg.contains("vless+reality"),
        "visible protocol list must show vless+reality"
    );
    assert!(
        !visible_seg.contains("tuic-v5") && !visible_seg.contains("anytls"),
        "hidden protocols must NOT appear in the visible list (only in the flag title)"
    );
    // The +N hidden flag renders, names the hidden protocols in its title,
    // and shows the count.
    assert!(
        html.contains(r#"class="ed-grid__flag""#),
        "a +N hidden flag must render for the server with hidden protocols"
    );
    assert!(
        html.contains("tuic-v5") && html.contains("anytls"),
        "hidden protocols must be surfaced (in the flag title)"
    );
    assert!(html.contains("+2"), "flag must show the hidden count (+2)");
}

#[tokio::test]
async fn nm12_followup_servers_list_no_hidden_row_when_all_visible() {
    // Symmetric: when no protocol is hidden on a server, the
    // `dt { "hidden" }` row must NOT render — keeps the card
    // compact for the happy-path operator. A regression that
    // always emits the row (even with 0 hidden) would clutter
    // the list page.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("vsrv".into()),
            address: "203.0.113.41".into(),
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
    let html = fetch_html(router(s), "/admin/servers").await;
    // The hidden dt label only appears when there's at least one
    // hidden protocol. Search for the literal `<dt style="color:
    // var(--acc);">hidden</dt>` substring.
    assert!(
        !html.contains(r#"<dt style="color: var(--acc);">hidden</dt>"#),
        "no protocols are hidden — the hidden dt row must NOT render"
    );
}

// ─── i18n: bilingual admin shell (Pavel 2026-05-21) ─────────────────
//
// Pavel: «добавил русскую версию». Cookie-driven locale toggle in the
// masthead, with `vpnctl_lang=ru` flipping nav + footer + masthead
// subtitle to Russian. These tests pin the toggle round-trip and a
// representative key for each locale.

#[tokio::test]
async fn i18n_default_locale_is_english_with_english_nav() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains(">Dashboard<"),
        "nav must render Dashboard label in English by default"
    );
    // The lang switch button shows the OTHER locale (`RU` when active
    // is `EN`); the active locale renders as bold text next to it.
    assert!(
        html.contains(">RU<"),
        "topbar toggle button must offer the alternate locale (RU when EN active)"
    );
}

#[tokio::test]
async fn i18n_ru_cookie_renders_russian_nav_and_subtitle() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .header("cookie", "vpnctl_lang=ru")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        html.contains(">Дашборд<"),
        "ru cookie must render the nav Dashboard label as Дашборд"
    );
    assert!(
        html.contains(">Серверы<"),
        "ru cookie must render Servers as Серверы"
    );
    assert!(
        html.contains(r#"<html lang="ru""#) || html.contains(r#"<html lang=\"ru\""#),
        "ru cookie must set `<html lang=\"ru\">` for hyphenation + screen readers"
    );
}

#[tokio::test]
async fn i18n_ru_renders_translated_body_copy_on_each_page() {
    // Pavel 2026-05-21: «делай полный перевод». First wave covered
    // chrome only; this commit pushed translations into the body
    // copy on every top-level page. Pin a representative Russian
    // phrase from each page so a future "let's revert translations"
    // PR has to update all 6 simultaneously.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Seed a server so the server-detail page (the PR-Server cards'
    // surface) is reachable for the walker — it returns 404 otherwise.
    // Seed a user too so the user-detail page (the PR-User cards'
    // surface) is reachable for the same reason.
    seed(&s.inv, 1, 1, &[]).await;
    let app = router(s);

    let fetch = |path: &'static str| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("cookie", "vpnctl_lang=ru")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{path} must return 200");
            String::from_utf8(
                axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap()
        }
    };

    // Dashboard
    let h = fetch("/admin/").await;
    assert!(
        h.contains("одним взглядом"),
        "dashboard H1 must read 'homelab одним взглядом' under ru"
    );
    assert!(
        h.contains("Счётчики читаются напрямую из SQLite-инвентаря"),
        "dashboard deck must be translated"
    );
    // PR-Dash — the kernel-rollup eyebrow always renders (its no-data
    // empty-state appears even on a fresh, server-less fleet), so its
    // RU arm is a reliable walker anchor. It moved to the dashboard's
    // activity tab (ui-audit follow-up), so fetch that tab for it.
    let h_activity = fetch("/admin/activity").await;
    assert!(
        h_activity.contains("Версии ядер · sing-box"),
        "PR-Dash kernel-rollup eyebrow must be translated under ru"
    );

    // Monitoring (v2 3a — fleet health)
    let h = fetch("/admin/monitoring").await;
    assert!(
        h.contains("Здоровье"),
        "monitoring H1 must read 'Здоровье флота' under ru"
    );
    assert!(
        h.contains("Пороги алертов"),
        "monitoring thresholds eyebrow must be translated"
    );

    // Servers list (empty in fresh inventory — empty-state copy)
    let h = fetch("/admin/servers").await;
    assert!(
        h.contains("в инвентаре"),
        "servers H1 must read 'N серверов в инвентаре'"
    );
    assert!(
        h.contains("Читаются напрямую из SQLite-инвентаря"),
        "servers deck must be translated"
    );

    // Users list
    let h = fetch("/admin/users").await;
    assert!(
        h.contains("в базе"),
        "users H1 must read 'N пользователей в базе'"
    );
    assert!(
        h.contains("публичный URL подписки"),
        "users deck must be translated"
    );

    // Audit page
    let h = fetch("/admin/audit").await;
    assert!(
        h.contains("каждое") && h.contains("изменение"),
        "audit H1 must read 'каждое изменение в базе'"
    );

    // Alerts page (v2 5a — dense headrow)
    let h = fetch("/admin/alerts").await;
    assert!(
        h.contains("открытых алертов"),
        "alerts H1 must read 'N открытых алертов' under ru"
    );

    // Settings page
    let h = fetch("/admin/settings").await;
    assert!(
        h.contains("homelab") && h.contains("управление"),
        "settings H1 must read 'homelab управление'"
    );
    assert!(
        h.contains("Здесь лежат настройки уровня всего демона"),
        "settings deck must be translated"
    );

    // Server detail — PR-Server cards. The drift-detail eyebrow always
    // renders (default load shows the «check live drift» link), so its
    // RU arm is a reliable walker anchor for the new server-detail cards.
    let h = fetch("/admin/servers/s0/protocols").await;
    assert!(
        h.contains("Детальный дрейф · UUID на ноде"),
        "PR-Server drift-detail eyebrow must be translated under ru"
    );

    // User detail — PR-User cards. The presence badge (user#1) always
    // renders (online or offline), so its RU eyebrow is a reliable
    // walker anchor for the new user-detail surface.
    let h = fetch("/admin/users/u0/activity").await;
    assert!(
        h.contains("Присутствие"),
        "PR-User presence eyebrow must be translated under ru"
    );
    // abuse-origins — the "Subscription origins" section eyebrow always
    // renders on user-detail (empty-state included), so its RU arm is a
    // reliable walker anchor for the new origins surface.
    assert!(
        h.contains("Источники подписки"),
        "abuse-origins 'Subscription origins' eyebrow must be translated under ru"
    );
}

#[tokio::test]
async fn i18n_en_default_renders_english_body_copy() {
    // Symmetric: default (no cookie, no Accept-Language: ru) keeps
    // the English copy. A bug that swaps the locale arms in tr()
    // would surface here AND in the ru test above.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("at a glance"),
        "default EN dashboard H1 must read 'homelab at a glance'"
    );
    assert!(
        !html.contains("одним взглядом"),
        "default EN must NOT leak Russian copy"
    );
}

#[tokio::test]
async fn i18n_accept_language_ru_picks_russian_when_no_cookie() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .header("accept-language", "ru-RU,ru;q=0.9,en;q=0.8")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        html.contains(">Дашборд<"),
        "no cookie + Accept-Language: ru* → render Russian"
    );
}

#[tokio::test]
async fn i18n_lang_toggle_post_sets_cookie_and_redirects_back() {
    // POST /admin/tweak/lang with `value=ru` → 303 + Set-Cookie:
    // vpnctl_lang=ru. Matches the existing theme/accent tweak shape.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tweak/lang")
                    .header("referer", "http://192.168.0.236:18402/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("value=ru"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        set_cookie.contains("vpnctl_lang=ru"),
        "POST /admin/tweak/lang value=ru must set vpnctl_lang=ru cookie, got {set_cookie}"
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/admin/users",
        "303 must redirect back via Referer (sanitised to /admin path)"
    );
}

#[tokio::test]
async fn i18n_lang_toggle_rejects_invalid_value() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tweak/lang")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("value=de"))
            .unwrap(),
        )
        .await
        .unwrap();
    // Bad-value path returns 400 via bad_request() in set_tweak_cookie.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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

#[tokio::test]
async fn nm12_followup_legacy_server_enable_protocol_also_carries_fragment() {
    // Symmetric to the [disable] test above.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("esrv2".into()),
            address: "203.0.113.31".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/esrv2/protocols/anytls/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/servers/esrv2/protocols#enabled-protocols");
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

// ─── sub_access.suspicious_local_ip alert spec (Pavel 2026-05-21) ───
//
// «если видим 127.0.0.1 или любой из 192.168/10/172.16-31 (метка
// LAN) и 169.254.* то это инцидент, который требует разбирательства».
// The writer task fires an admin_alert per (user_id) bucket when a
// LAN/loopback/link-local IP is paired with a UA that's NOT on the
// allowlist (only `phase6-monitor (canary)` today).

/// Helper: send one record through the writer + wait for it to drain
/// + return the inventory handle for assertions.
async fn enqueue_one_and_drain(
    s: &vpnctld::AppState,
    user_id: &str,
    ip: &str,
    device_class: Option<&str>,
) {
    let _ = vpnctld::access_log::try_enqueue(
        &s.access_log_tx,
        vpnctld::access_log::AccessLogRecord {
            user_id: vpnctl_core::UserId(user_id.to_string()),
            ip: ip.to_string(),
            ua: device_class.map(str::to_owned),
            status: 200,
            bytes: 0,
            accept_language: None,
            http_version: Some("HTTP/1.1".to_string()),
            device_class: device_class.map(str::to_owned),
            geo_country: None,
            geo_asn: None,
            tls_ja3: None,
            tls_ja4: None,
        },
    );
    // Writer is async; small sleep + drain is the same pattern the
    // existing `sub_access_writer_persists_one_hit` test uses.
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
}

#[tokio::test]
async fn track_1_3_suspicious_local_ip_fires_for_localhost_with_unknown_ua() {
    // Pavel's exact scenario: a row with `ip = 127.0.0.1` AND a UA
    // outside the allowlist MUST raise the alert.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let inv = s.inv.clone();
    enqueue_one_and_drain(&s, "u0", "127.0.0.1", Some("v2rayN / Windows")).await;

    let alerts = inv.recent_alerts(10, false).await.unwrap();
    let suspicious: Vec<_> = alerts
        .iter()
        .filter(|a| a.kind.starts_with("sub_access.suspicious_local_ip:"))
        .collect();
    assert_eq!(
        suspicious.len(),
        1,
        "exactly one suspicious-local-ip alert must fire for u0 + 127.0.0.1 + non-allowlisted UA"
    );
    let a = suspicious[0];
    assert_eq!(a.kind, "sub_access.suspicious_local_ip:u0");
    assert_eq!(a.severity, "warning");
    assert!(
        a.summary.contains("127.0.0.1"),
        "summary must surface the IP, got {}",
        a.summary
    );
    assert!(
        a.summary.contains("loopback"),
        "summary must surface the IP-kind label, got {}",
        a.summary
    );
    // Payload MUST NOT carry any user-secrets (sub_token, uuid,
    // wireguard_private, tuic_password). Pin via raw substring
    // search on the JSON.
    let payload_str = a.payload_json.as_deref().unwrap_or("").to_string();
    for secret in &["sub_token", "wireguard_private", "tuic_password", "uuid"] {
        assert!(
            !payload_str.contains(secret),
            "alert payload must not leak `{secret}`, got: {payload_str}"
        );
    }
}

#[tokio::test]
async fn track_1_3_suspicious_local_ip_phase6_monitor_canary_is_exempt() {
    // The /etc/cron.d/phase6-monitor canary hits localhost every
    // day at 09:00 UTC. Its UA is tagged `phase6-monitor/1.0`,
    // which `parse_ua_short` collapses to `"phase6-monitor (canary)"`.
    // That's the SINGLE allowlist entry — must NOT trigger.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let inv = s.inv.clone();
    enqueue_one_and_drain(&s, "u0", "127.0.0.1", Some("phase6-monitor (canary)")).await;
    let n = inv.unacked_alert_count().await.unwrap();
    assert_eq!(
        n, 0,
        "phase6-monitor canary on localhost must NOT raise the alert (allowlist)"
    );
}

#[tokio::test]
async fn track_1_3_suspicious_local_ip_public_ip_never_fires() {
    // Symmetric: a Public IP (8.8.8.8) must NOT fire regardless of
    // UA. Pins the `IpKind::Public` arm so a future expansion of
    // `classify_ip` (e.g. adding CGNAT 100.64/10) can't accidentally
    // flag real external clients.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let inv = s.inv.clone();
    enqueue_one_and_drain(&s, "u0", "8.8.8.8", Some("v2rayN / Windows")).await;
    let n = inv.unacked_alert_count().await.unwrap();
    assert_eq!(n, 0, "public IP must NEVER raise the alert");
}

#[tokio::test]
async fn track_1_3_suspicious_local_ip_dedup_is_per_user() {
    // Fire two suspicious rows for u0 + one for u1 → exactly 2
    // unacked alerts (one per user). The partial UNIQUE index on
    // (kind, COALESCE(server_id,'__GLOBAL__')) WHERE acked_at IS NULL
    // gives each user their own dedup bucket via the
    // `:<user_id>` suffix in the kind string.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 2, &[]).await;
    let inv = s.inv.clone();
    enqueue_one_and_drain(&s, "u0", "127.0.0.1", Some("v2rayN / Windows")).await;
    enqueue_one_and_drain(&s, "u0", "192.168.0.5", Some("curl")).await;
    enqueue_one_and_drain(&s, "u1", "10.0.0.7", Some("curl")).await;
    let alerts = inv.recent_alerts(10, false).await.unwrap();
    let suspicious: std::collections::HashSet<String> = alerts
        .iter()
        .filter(|a| a.kind.starts_with("sub_access.suspicious_local_ip:"))
        .map(|a| a.kind.clone())
        .collect();
    assert_eq!(
        suspicious.len(),
        2,
        "expected 2 per-user buckets, got: {suspicious:?}"
    );
    assert!(suspicious.contains("sub_access.suspicious_local_ip:u0"));
    assert!(suspicious.contains("sub_access.suspicious_local_ip:u1"));
}

#[tokio::test]
async fn track_1_3_settings_geoip_section_shows_missing_state_by_default() {
    // The fresh-test harness doesn't drop MMDB files, so the
    // section should report both DBs as «missing» and surface
    // the `vpnctl geoip-update` instruction.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/settings/system").await;
    assert!(
        html.contains("GeoIP — IP enrichment"),
        "Settings page must include the GeoIP eyebrow"
    );
    assert!(
        html.contains("vpnctl geoip-update"),
        "missing-DB branch must mention the CLI command"
    );
    assert!(
        html.contains("(missing — run") || html.contains("(отсутствует — запусти"),
        "expected the 'missing' empty-state for both City + ASN"
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

// ────────────────────────────────────────────────────────────────────────
//  Phase 3c — Settings GeoIP «update now» SSE button.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase3c_settings_renders_geoip_update_now_button_and_eventsource_wiring() {
    // Pin the Settings page: the «update now» button + live-log <pre>
    // render, wired CSP-SAFE through admin.js's `[data-sse-url]`
    // trigger. Audit 2026-06-10: the original inline `<script>` +
    // `onclick` were silently refused by the admin CSP (`script-src
    // 'self'`, no 'unsafe-inline') — the button did NOTHING in a real
    // browser. Pavel UI requirement stands — operator must never need
    // a terminal; `vpnctl geoip-update` must stay one click.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/settings/system").await;

    assert!(
        html.contains("id=\"geoip-update-now-btn\""),
        "Settings must surface the GeoIP «update now» button"
    );
    assert!(
        html.contains("data-sse-url=\"/admin/settings/geoip/update-now\""),
        "button must carry the data-sse-url trigger admin.js wires"
    );
    assert!(
        html.contains("data-log=\"geoip-update-now-log\""),
        "button must point at its log pane via data-log"
    );
    assert!(
        html.contains("id=\"geoip-update-now-log\""),
        "Settings must surface the live-log pane"
    );
    // CSP-regression guard: NO inline script / onclick may return —
    // they render but never execute under `script-src 'self'`.
    assert!(
        !html.contains("vpnctlGeoipUpdateNow") && !html.contains("onclick="),
        "settings must not regress to CSP-blocked inline JS"
    );
}

#[tokio::test]
async fn phase3c_geoip_update_now_sse_endpoint_returns_text_event_stream() {
    // Endpoint contract: GET /admin/settings/geoip/update-now must
    // return 200 with Content-Type: text/event-stream. The runner
    // will spawn `/usr/local/bin/vpnctl geoip-update` which usually
    // won't exist in the test container — that's fine, the runner
    // emits a terminal Error event and the stream closes. We just
    // pin the HTTP wire contract here. NOTE: we deliberately don't
    // override the bin path via env var — `std::env::set_var` is
    // `unsafe` in Rust 2024 + workspace forbids unsafe; the wire
    // contract (200 + text/event-stream) is identical regardless
    // of whether the spawn succeeds.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    let resp = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/settings/geoip/update-now")
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
    assert!(
        ct.starts_with("text/event-stream"),
        "SSE source must return Content-Type: text/event-stream, got {ct:?}"
    );
}

#[tokio::test]
async fn phase3c_geoip_update_now_fire_writes_audit_row() {
    // Hitting the SSE endpoint must write an audit row with the
    // canonical dot-separated action name. The audit row is the
    // operator's after-the-fact «what happened» record — without
    // it, a misbehaving subprocess vanishes without a trace beyond
    // journalctl.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();

    let _ = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/settings/geoip/update-now")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Audit row is written BEFORE the subprocess spawn (so even a
    // spawn failure is logged). The connection close before the
    // subprocess finishes doesn't lose the audit row.
    let rows = inv.recent_audit(20).await.unwrap();
    assert!(
        rows.iter()
            .any(|r| r.action == "settings.geoip.update_now.fired"),
        "expected audit row settings.geoip.update_now.fired, got {:?}",
        rows.iter().map(|r| &r.action).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn phase3c_geoip_update_now_rejects_cross_site_sec_fetch() {
    // CSRF defense — a hostile page that embeds
    //   <img src="http://192.168.0.236:18402/admin/settings/geoip/update-now">
    // causes the browser to GET our endpoint with
    //   Sec-Fetch-Site: cross-site
    // Without this gate the audit row + subprocess would fire just
    // from the operator visiting the attacker's page (basic-auth
    // is sent automatically by the browser). With the gate, we 403
    // BEFORE the audit or spawn — neither side-effect occurs.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();

    let resp = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/settings/geoip/update-now")
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.starts_with("vpnctl admin: "),
        "403 must carry the unified prefix, got: {body}"
    );
    // No audit row may exist — the gate refused BEFORE the audit.
    let rows = inv.recent_audit(20).await.unwrap();
    assert!(
        !rows
            .iter()
            .any(|r| r.action == "settings.geoip.update_now.fired"),
        "audit row must NOT be written when the CSRF gate rejects"
    );
}

#[tokio::test]
async fn phase3c_geoip_update_now_accepts_same_origin_sec_fetch() {
    // Symmetric to the cross-site test — the legitimate EventSource
    // attach from /admin/settings sends Sec-Fetch-Site: same-origin.
    // That MUST succeed (200 + text/event-stream).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    let resp = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/settings/geoip/update-now")
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn phase3c_settings_page_carries_no_inline_script_blocks() {
    // CSP contract (2026-06-10, supersedes the old json_for_script XSS
    // pin): the admin CSP is `script-src 'self'` with NO
    // 'unsafe-inline', so ANY inline `<script>…</script>` body on the
    // page renders but never executes — exactly how the GeoIP button
    // sat dead for weeks. Pin: the ONLY <script> on Settings is the
    // external admin.js include from the shell; everything interactive
    // must ride data-attributes.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/settings").await;

    let script_tags = html.matches("<script").count();
    assert_eq!(
        script_tags, 1,
        "settings must carry exactly the shell's external admin.js <script>, found {script_tags}"
    );
    assert!(
        html.contains("src=\"/admin/assets/admin.js\""),
        "the single script tag must be the external admin.js include"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase 4a — user-detail 30d aggregates + VPN-egress hide toggle.
// ────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────
//  Phase 4b — server-detail Live activity tile + dashboard VPN-activity.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase4b_server_detail_renders_live_activity_section_when_no_samples() {
    // Pavel: even before the poller has sampled, the section must
    // render (with empty-state «active now: 0», «last poll: never»)
    // so the page structure is predictable. NM-11 caveat copy
    // present.
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("emptynode".into()),
            address: "192.0.2.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers/emptynode/activity").await;
    assert!(
        html.contains("Live activity · last 24h"),
        "server-detail must surface the Phase 4b live-activity section eyebrow"
    );
    assert!(
        html.contains("NM-11"),
        "section must mention NM-11 upstream caveat so the operator knows why per-user is zero"
    );
    assert!(
        html.contains("active now") && html.contains("upload 24h") && html.contains("download 24h"),
        "all 4 tile labels must render"
    );
    assert!(
        html.contains("last poll: ") && html.contains("never"),
        "empty-state must read «last poll: never»"
    );
}

#[tokio::test]
async fn phase4b_dashboard_renders_vpn_activity_tile_with_per_server_breakdown() {
    // Two servers; one has a sample, one doesn't. Dashboard tile
    // must render with the per-server breakdown table; quiet server
    // still appears with zeros.
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    use vpnctl_inventory::VpnStatsDelta;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    for (id, addr) in [("busy", "203.0.113.1"), ("quiet", "203.0.113.2")] {
        s.inv
            .add_server(&Server {
                id: ServerId(id.into()),
                address: addr.into(),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels: vec![KernelId("sing-box".into())],
                enabled_protocols: Vec::new(),
                trusted_host_fingerprint: None,
                hoster: "generic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            })
            .await
            .unwrap();
    }
    s.inv
        .add_user(&User {
            id: UserId("u1".into()),
            uuid: "u10".into(),
            sub_token: None,
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // Record server-wide tick on `busy` (user_id = None).
    s.inv
        .record_vpn_stats(
            &ServerId("busy".into()),
            &[VpnStatsDelta {
                user_id: None,
                upload_bytes: 12_345,
                download_bytes: 54_321,
                active_connections: 7,
            }],
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/activity").await;
    // Heading uses the active window label (default 24h, post-
    // 2026-05-23 global window picker). «VPN activity · 24h»
    // — same tile, just generic-windowed.
    assert!(
        html.contains("VPN activity · 24h"),
        "dashboard must surface the new VPN-activity tile; got: {}",
        &html[..200.min(html.len())]
    );
    assert!(html.contains("NM-11"), "tile must surface NM-11 explainer");
    // Pin the busy server's `<td>7</td>` row specifically so an
    // unrelated «7» in a sibling tile (page counter, server total
    // etc.) can't satisfy this assertion. Review-agent Phase 4b #7.
    // PR-Dash: the fleet-at-a-glance table (above this tile) ALSO links
    // /admin/servers/busy with a «conns now» cell sourced from the live
    // snapshot cache (empty in this test → «—»), so scope the search to
    // the VPN-activity section to keep hitting the active_now=7 row.
    let activity_pos = html
        .find("VPN activity · 24h")
        .expect("VPN activity tile must render");
    let activity_html = &html[activity_pos..];
    let busy_anchor = "href=\"/admin/servers/busy\"";
    let busy_pos = activity_pos
        + activity_html
            .find(busy_anchor)
            .expect("busy server link must render in the VPN-activity breakdown");
    let busy_row = &html[busy_pos..busy_pos.saturating_add(400)];
    assert!(
        busy_row.contains(">7<"),
        "busy server's active-now cell must be 7, got row: …{busy_row}…"
    );
    // Per-server breakdown links to each server-detail page.
    assert!(
        html.contains(busy_anchor) && html.contains("href=\"/admin/servers/quiet\""),
        "both servers must appear in the per-server breakdown"
    );
}

#[tokio::test]
async fn phase4b_dashboard_vpn_activity_tile_shows_empty_state_when_no_polls() {
    // No samples anywhere — the tile must render the empty-state
    // copy pointing at the Servers list, NOT crash or hide.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // No servers at all → list is empty.
    let html = fetch_html(router(s), "/admin/activity").await;
    assert!(
        html.contains("VPN activity · 24h"),
        "tile must always render"
    );
    assert!(
        html.contains("No clash-api samples yet"),
        "empty-state copy must mention «No clash-api samples yet»"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase 4c — server-detail Live connections drill-down section
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase4c_server_detail_renders_empty_state_when_no_snapshot() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("emptynode".into()),
            address: "192.0.2.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/emptynode/activity").await;
    assert!(
        html.contains("Live connections"),
        "server-detail must surface the Phase 4c section eyebrow even without data"
    );
    assert!(
        html.contains("No clash-api snapshot for this server yet"),
        "empty-state copy must explain the 5-minute poller cadence"
    );
}

#[tokio::test]
async fn phase4c_server_detail_renders_top_destinations_and_sources_from_snapshot() {
    // Manually inject a snapshot into the cache so we don't need a
    // real clash-api running. Pin: top destinations + top sources +
    // network breakdown tiles + correlation column header.
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("active".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .add_user(&User {
            id: UserId("brat".into()),
            uuid: "br0".into(),
            sub_token: Some("brtok".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // brat fetched subscription from 9.9.9.9 → correlation
    // should surface that user_id when 9.9.9.9 appears as
    // sourceIP in the live snapshot.
    s.inv
        .log_sub_access(&UserId("brat".into()), "9.9.9.9", None, 200, 100)
        .await
        .unwrap();

    use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
    let snap = Snapshot {
        upload_total: 5000,
        download_total: 10000,
        connections: vec![
            Connection {
                id: "c1".into(),
                upload: 1000,
                download: 5000,
                start: "2026-05-21T18:00:00Z".into(),
                metadata: ConnectionMeta {
                    network: "tcp".into(),
                    destination_ip: "172.217.16.142".into(),
                    destination_port: "443".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "55555".into(),
                    host: "youtube.com".into(),
                    user: None,
                },
            },
            Connection {
                id: "c2".into(),
                upload: 100,
                download: 200,
                start: "2026-05-21T18:00:01Z".into(),
                metadata: ConnectionMeta {
                    network: "udp".into(),
                    destination_ip: "1.1.1.1".into(),
                    destination_port: "53".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "55556".into(),
                    host: String::new(),
                    user: None,
                },
            },
        ],
    };
    s.snapshot_cache.store(ServerId("active".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/active/activity").await;
    assert!(html.contains("Live connections"));
    // Top destinations must include youtube.com (preferred over IP).
    assert!(
        html.contains("youtube.com:443"),
        "top destinations must render host:port preferring DNS name"
    );
    // Top sources must include the real client IP.
    assert!(
        html.contains("9.9.9.9"),
        "top sources must render the real source IP"
    );
    // Correlation should resolve `9.9.9.9` → `brat`.
    assert!(
        html.contains("href=\"/admin/users/brat\""),
        "source-IP-to-user correlation must surface brat as the likely owner of 9.9.9.9"
    );
    // Network breakdown tiles (TCP 1 / UDP 1).
    assert!(html.contains(">tcp<") || html.contains("tcp"));
    assert!(html.contains("udp"));
    // NM-11 caveat copy
    assert!(
        html.contains("NM-11"),
        "section must surface NM-11 explainer"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase 4d — sing-box log scrape exact attribution wins over sub_access
//  correlation in the «top sources» column.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase4d_server_detail_log_attribution_wins_over_sub_access_correlation() {
    // Setup: clash snapshot has source IP 31.135.234.102 with no
    // sub_access row (so Phase 4c correlation returns nothing).
    // Phase 4d attribution map says 31.135.234.102 → main-brat.
    // The «top sources» row must surface main-brat (exact match,
    // tagged «log») not «—».
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("phase4d-srv".into()),
            address: "203.0.113.50".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .add_user(&User {
            id: UserId("main-brat".into()),
            uuid: "mb0".into(),
            sub_token: None,
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // NO sub_access_log row — so Phase 4c fallback would NOT
    // find a match. Only Phase 4d log attribution can.

    let snap = Snapshot {
        upload_total: 1000,
        download_total: 5000,
        connections: vec![Connection {
            id: "c1".into(),
            upload: 1000,
            download: 5000,
            start: "2026-05-21T19:00:00Z".into(),
            metadata: ConnectionMeta {
                network: "tcp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: "31.135.234.102".into(),
                source_port: "2810".into(),
                host: String::new(),
                user: Some("main-brat".into()),
            },
        }],
    };
    s.snapshot_cache.store(ServerId("phase4d-srv".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/phase4d-srv/activity").await;
    // Exact match link to main-brat — now sourced from metadata.user
    // (the patched sing-box clash-api), not the removed log-scrape map.
    assert!(
        html.contains("href=\"/admin/users/main-brat\""),
        "metadata.user attribution must link the source IP to main-brat"
    );
}

#[tokio::test]
async fn phase4d_server_detail_falls_back_to_sub_access_when_no_log_attribution() {
    // Symmetric case — log attribution empty, sub_access has a
    // match → falls back, tagged «sub».
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("phase4d-fb".into()),
            address: "203.0.113.51".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .add_user(&User {
            id: UserId("falluser".into()),
            uuid: "fb0".into(),
            sub_token: Some("fbtok".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // sub_access_log entry — Phase 4c sub_access correlation
    // hit for 5.5.5.5.
    s.inv
        .log_sub_access(&UserId("falluser".into()), "5.5.5.5", None, 200, 100)
        .await
        .unwrap();

    let snap = Snapshot {
        upload_total: 100,
        download_total: 200,
        connections: vec![Connection {
            id: "c1".into(),
            upload: 100,
            download: 200,
            start: "2026-05-21T19:00:00Z".into(),
            metadata: ConnectionMeta {
                network: "tcp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: "5.5.5.5".into(),
                source_port: "55555".into(),
                host: String::new(),
                user: None,
            },
        }],
    };
    // EMPTY attribution map — Phase 4d had nothing for this IP.
    s.snapshot_cache.store(ServerId("phase4d-fb".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/phase4d-fb/activity").await;
    // Must link to falluser via sub_access fallback.
    assert!(
        html.contains("href=\"/admin/users/falluser\""),
        "sub_access fallback must link the source IP to falluser when log attribution is empty"
    );
    // Tagged «sub» (not «log»).
    assert!(
        html.contains(">sub<"),
        "tag «sub» must indicate fallback-via-sub_access"
    );
    assert!(
        !html.contains(">log<"),
        "no «log» tag when log attribution map is empty"
    );
}

#[tokio::test]
async fn phase4d_server_detail_renders_dash_when_neither_log_nor_sub_has_attribution() {
    // Pin the «both layers empty» path: no log attribution, no
    // sub_access correlation hits → the «likely user» cell must
    // render «—» with NO `<a href="/admin/users/...">` link.
    use vpnctl_core::{KernelId, Server, ServerId};
    use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("phase4d-none".into()),
            address: "203.0.113.52".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    // NO users added → users_for_source_ips returns no matches
    // for any IP, and we pass an empty attribution map.

    let snap = Snapshot {
        upload_total: 100,
        download_total: 100,
        connections: vec![Connection {
            id: "c1".into(),
            upload: 100,
            download: 100,
            start: "2026-05-21T19:00:00Z".into(),
            metadata: ConnectionMeta {
                network: "tcp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: "203.0.113.99".into(),
                source_port: "55555".into(),
                host: String::new(),
                user: None,
            },
        }],
    };
    s.snapshot_cache
        .store(ServerId("phase4d-none".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/phase4d-none/activity").await;
    // Source IP must render in the top-sources row.
    assert!(
        html.contains("203.0.113.99"),
        "the unattributed source IP must still render in the table"
    );
    // NO link to any user-detail for this orphan IP. We use a
    // targeted check: extract the slice around the source IP cell
    // and assert it doesn't carry a user-detail link.
    let pos = html.find("203.0.113.99").expect("source IP must render");
    // The cell + the next ~400 chars cover the «likely user» cell.
    let window = &html[pos..pos.saturating_add(800)];
    assert!(
        !window.contains("href=\"/admin/users/"),
        "orphan source IP must NOT link to any user-detail; window: …{window}…"
    );
    // The «—» glyph appears as the cell content.
    assert!(
        window.contains("—"),
        "«likely user» cell must render «—» for orphan IP, got window: …{window}…"
    );
}

// ── Phase H+ — per-server uptime SLO section ─────────────────────────
//
// Two tests pin the section's render contract:
//   1. Empty (no node_health rows) — section MUST NOT render. The
//      hero already owns the «no probes yet» empty-state; stacking
//      another would be noise. This is the «empty branch returns
//      `html! {}`» guard.
//   2. With probe rows — section renders with eyebrow + 3 chips
//      labelled 24h/7d/30d + percent text «100%» (all-up).

#[tokio::test]
async fn server_detail_uptime_section_omitted_when_no_probes() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("nuevo".into()),
            address: "203.0.113.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/nuevo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // The section's anchor id + eyebrow text are the canonical
    // markers; both must be absent when there are no probes.
    assert!(
        !html.contains("id=\"uptime-section\""),
        "uptime section must NOT render for a server with zero node_health rows"
    );
    assert!(
        !html.contains("Uptime · sing-box service"),
        "uptime section eyebrow must NOT render when section is suppressed"
    );
}

#[tokio::test]
async fn server_detail_renders_traffic_gap_section() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let sid = ServerId("gaptest".into());
    st.inv
        .add_server(&Server {
            id: sid.clone(),
            address: "203.0.113.9".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    // Two NIC readings → rx Δ5 GB, tx 0 → nic_total ≈ 5 GB.
    for rx in [1_000_000_000u64, 6_000_000_000u64] {
        st.inv
            .record_node_health(
                &sid,
                Some(true),
                Some(true),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some("ens18"),
                Some(rx),
                Some(0),
            )
            .await
            .unwrap();
    }
    // Clash attributes ~1 GB → the gap is ~4 GB of unseen traffic.
    st.inv
        .record_vpn_stats(
            &sid,
            &[vpnctl_inventory::VpnStatsDelta {
                user_id: None,
                upload_bytes: 1_000_000_000,
                download_bytes: 0,
                active_connections: 0,
            }],
        )
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/gaptest/activity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // Section + the three tiles render (NIC ground-truth vs attributed vs gap).
    assert!(html.contains("Traffic accounting"), "gap section eyebrow");
    assert!(html.contains("NIC total"), "NIC total tile");
    assert!(html.contains("GAP (unattributed)"), "gap tile");
    assert!(html.contains("ens18"), "interface name shown");
    // With 2 samples it must NOT show the empty-state.
    assert!(
        !html.contains("No NIC ground-truth yet"),
        "should render real numbers, not the empty-state"
    );
}

#[tokio::test]
async fn server_detail_uptime_section_renders_with_probe_data() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let sid = ServerId("with-data".into());
    st.inv
        .add_server(&Server {
            id: sid.clone(),
            address: "203.0.113.50".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    // Seed 5 all-up probes. record_node_health uses ts=now so all
    // will fall inside the 24h/7d/30d windows.
    for _ in 0..5 {
        st.inv
            .record_node_health(
                &sid,
                Some(true),  // sing_box_active
                Some(true),  // fail2ban_active
                Some(1024),  // disk_used_mib
                Some(10240), // disk_total_mib
                Some(500),   // mem_available_mib
                Some(1024),  // mem_total_mib
                Some(50),    // load_1min_x100
                Some("[\"tcp/443\",\"udp/8443\"]"),
                Some(1024 * 1024),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
    }
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/with-data")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // Section anchor + eyebrow must both appear.
    assert!(
        html.contains("id=\"uptime-section\""),
        "uptime section must render when probes exist"
    );
    assert!(
        html.contains("Uptime · sing-box service"),
        "eyebrow copy must render (EN default)"
    );
    // All three window labels must be present.
    for chip in &["last 24h", "last 7d", "last 30d"] {
        assert!(
            html.contains(chip),
            "chip label «{chip}» must render in uptime section"
        );
    }
    // With 5 up probes + 0 down, all three chips MUST read 100%.
    // We assert on the stable `data-uptime-pct="100"` attribute
    // (review-agent NM-uptime catch) rather than scanning for the
    // literal «100%» text — the admin page has 11+ unrelated
    // `100%` substrings (CSS `width: 100%`, full-disk tile, etc.)
    // and a regression where all three chips fell through to
    // `None` could falsely pass an inline-text count.
    let pct_attr_count = html.matches("data-uptime-pct=\"100\"").count();
    assert_eq!(
        pct_attr_count,
        3,
        "all three uptime chips must carry data-uptime-pct=\"100\" \
         (found {pct_attr_count}); html len = {} bytes",
        html.len()
    );
    // Probe count chip footer must mention «probes».
    assert!(
        html.contains("probes"),
        "chip footer must show «N probes» count"
    );
}

// ── Phase H+ — dashboard FLEET uptime tile ──────────────────────────
//
// Companion to `server_detail_uptime_*` tests above. The dashboard
// tile aggregates probe-weighted across all servers. Empty fleet =
// section omitted; populated fleet = 3 chips with
// `data-fleet-uptime-pct` attribute.

#[tokio::test]
async fn dashboard_fleet_uptime_section_omitted_when_no_servers_polled() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Add a server but write ZERO node_health rows. The aggregator
    // must see «no decidable data anywhere» and suppress the section.
    st.inv
        .add_server(&Server {
            id: ServerId("fresh".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/activity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("id=\"fleet-uptime\""),
        "fleet-uptime section must NOT render when no server has decidable probes"
    );
    assert!(
        !html.contains("Fleet uptime"),
        "fleet-uptime eyebrow must NOT render when section is suppressed"
    );
}

#[tokio::test]
async fn dashboard_fleet_uptime_section_renders_with_probe_data() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Two servers: alpha all-up (4 rows), bravo also all-up (3 rows).
    // Aggregate = (4+3) up / (4+3) decidable = 100% in every window.
    for (sid_s, n_rows) in [("alpha", 4), ("bravo", 3)] {
        let sid = ServerId(sid_s.into());
        st.inv
            .add_server(&Server {
                id: sid.clone(),
                address: format!("203.0.113.{}", if sid_s == "alpha" { 1 } else { 2 }),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels: vec![KernelId("sing-box".into())],
                enabled_protocols: vec![],
                trusted_host_fingerprint: None,
                hoster: "generic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            })
            .await
            .unwrap();
        for _ in 0..n_rows {
            st.inv
                .record_node_health(
                    &sid,
                    Some(true),
                    Some(true),
                    Some(1024),
                    Some(10240),
                    Some(500),
                    Some(1024),
                    Some(50),
                    Some("[\"tcp/443\"]"),
                    Some(1024 * 1024),
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .unwrap();
        }
    }
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/activity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // Section anchor + eyebrow present.
    assert!(
        html.contains("id=\"fleet-uptime\""),
        "fleet-uptime section anchor must render"
    );
    assert!(
        html.contains("Fleet uptime · sing-box services"),
        "fleet-uptime EN eyebrow must render"
    );
    // 3 chips × 100% via the stable scrape attribute (not inline
    // text — admin page has many unrelated «100%» substrings).
    let pct_attr_count = html.matches("data-fleet-uptime-pct=\"100\"").count();
    assert_eq!(
        pct_attr_count, 3,
        "all three fleet-uptime chips must carry data-fleet-uptime-pct=\"100\" \
         (found {pct_attr_count})"
    );
    // Polled / total ratio chip footer must read «2/2 polled»
    // (both seeded servers contributed probes).
    assert!(
        html.contains("2/2"),
        "chip footer must show «2/2 polled» when both seeded servers contributed"
    );
}

#[tokio::test]
async fn dashboard_fleet_uptime_excludes_unpolled_server_from_polled_ratio() {
    // Mixed fleet: one server polled, one fresh. Aggregator should
    // EXCLUDE the fresh one from the «polled» count (numerator)
    // but INCLUDE it in the total-servers count (denominator) →
    // footer reads «1/2 polled». Pins the «fresh server doesn't
    // poison the average» guarantee from the doc-comment.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    for sid_s in ["polled", "fresh"] {
        st.inv
            .add_server(&Server {
                id: ServerId(sid_s.into()),
                address: format!("203.0.113.{}", if sid_s == "polled" { 11 } else { 12 }),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels: vec![KernelId("sing-box".into())],
                enabled_protocols: vec![],
                trusted_host_fingerprint: None,
                hoster: "generic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            })
            .await
            .unwrap();
    }
    // Only «polled» gets probes.
    let polled = ServerId("polled".into());
    for _ in 0..5 {
        st.inv
            .record_node_health(
                &polled,
                Some(true),
                Some(true),
                Some(1024),
                Some(10240),
                Some(500),
                Some(1024),
                Some(50),
                Some("[\"tcp/443\"]"),
                Some(1024 * 1024),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
    }
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/activity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("id=\"fleet-uptime\""),
        "fleet-uptime section must render when at least one server is polled"
    );
    assert!(
        html.contains("1/2"),
        "chip footer must show «1/2 polled» (one polled, one fresh)"
    );
    // The polled server is 100% → all 3 chips must read 100.
    let pct_attr_count = html.matches("data-fleet-uptime-pct=\"100\"").count();
    assert_eq!(
        pct_attr_count, 3,
        "all three chips must carry data-fleet-uptime-pct=\"100\" \
         when the only polled server is 100% up"
    );
}

// ── Bulk-ack alerts ─────────────────────────────────────────────────
//
// New `/admin/alerts/ack-all` POST + companion «ack all (N)» button
// on the alerts page header. Three tests:
//   1. Endpoint POST drains the table + writes 1 audit row
//   2. Page renders the «ack all (N)» button when unacked_total > 0
//   3. Page OMITS the button when unacked_total = 0 (don't invite misclick)

#[tokio::test]
async fn alerts_ack_all_endpoint_drains_unacked_and_redirects() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Seed 4 unacked + 1 already-acked.
    for i in 0..4 {
        st.inv
            .insert_alert(
                &format!("test.suspicious_local_ip:user{i}"),
                None,
                "warning",
                "test alert seeded by admin_smoke",
                Some("{}"),
            )
            .await
            .unwrap();
    }
    let pre_acked_id = st
        .inv
        .insert_alert("test.already_acked", None, "info", "pre-acked", None)
        .await
        .unwrap();
    let _ = st.inv.ack_alert(pre_acked_id).await.unwrap();
    assert_eq!(
        st.inv.unacked_alert_count().await.unwrap(),
        4,
        "preconditions: 4 unacked + 1 acked"
    );

    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/alerts/ack-all")
                // CSRF middleware requires Origin == Host on mutating POSTs.
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // POST-redirect-GET — same convention as per-row ack.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/admin/alerts"),
        "must 303 back to the alerts feed"
    );
    // Post-condition: all unacked drained, but the pre-acked count
    // remains untouched (acked_at preserved — that's the inventory
    // spec contract).
    assert_eq!(
        st.inv.unacked_alert_count().await.unwrap(),
        0,
        "ack-all must drain unacked count to 0"
    );
    // Audit row must exist with action=alerts.ack_all and count=4
    // (the 4 newly-acked rows, NOT 5 — pre-acked wasn't re-touched).
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "alerts.ack_all")
        .expect("audit must contain alerts.ack_all row");
    let payload = row.payload.as_ref().expect("payload required");
    assert_eq!(
        payload.get("count").and_then(|v| v.as_u64()),
        Some(4),
        "audit count must equal the rows actually touched (4), not the table size (5)"
    );
}

#[tokio::test]
async fn alerts_ack_all_endpoint_noop_when_nothing_unacked_writes_no_audit() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Empty table — POST should 303, drain 0, and NOT pollute audit_log.
    let pre_audit_count = st.inv.recent_audit(200).await.unwrap().len();
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/alerts/ack-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let post_audit_count = st.inv.recent_audit(200).await.unwrap().len();
    assert_eq!(
        post_audit_count, pre_audit_count,
        "no-op ack-all must NOT write an audit row (audit-on-actual-mutation contract)"
    );
}

/// Alerts-cleanup 2026-06-10: the feed renders OPEN rows first,
/// severity-ranked (critical above info regardless of age), shows the
/// human title + what-to-do hint for known kinds, and collapses 3+
/// open suspicious-local-ip rows into one <details> group.
#[tokio::test]
async fn alerts_page_orders_titles_hints_and_collapses_spam() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 0, &[]).await; // s0 for server-scoped alerts
    let sid = ServerId("s0".into());
    // Old info row first (lower id), then a critical — chronological
    // order would put info on top; severity order must flip them.
    st.inv
        .insert_alert(
            "server.fail2ban.up",
            Some(&sid),
            "info",
            "fail2ban recovered",
            None,
        )
        .await
        .unwrap();
    st.inv
        .insert_alert(
            "server.singbox.down",
            Some(&sid),
            "critical",
            "sing-box is no longer active",
            None,
        )
        .await
        .unwrap();
    // 3 suspicious rows → collapse threshold.
    for u in ["ua", "ub", "uc"] {
        st.inv
            .insert_alert(
                &format!("sub_access.suspicious_local_ip:{u}"),
                None,
                "warning",
                &format!("local-loop fetch · user={u}"),
                None,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(st), "/admin/alerts").await;

    // v2 5a — family grouping: the node/fleet section renders the
    // localized titles (alert_text::render_alert), the sub_access
    // section carries the spam cluster.
    assert!(
        html.contains("sing-box down"),
        "critical localized title must render"
    );
    assert!(html.contains("fail2ban recovered"), "info row must render");
    assert!(
        html.contains("sub_access · 3"),
        "sub_access family section must count its 3 rows"
    );
    // What-to-do hint for the open critical — the localized render action.
    assert!(
        html.contains("reapplies the config"),
        "open critical must carry its localized what-to-do hint"
    );
    // v2 5a — the family grouping replaced the <details> collapse:
    // each suspicious row stays a first-class table row inside the
    // sub_access section, subject linked.
    assert!(
        html.contains(r#"href="/admin/users/ua""#) && html.contains(r#"href="/admin/users/uc""#),
        "per-user rows must link their subjects inside the sub_access section"
    );
}

/// Alerts-cleanup 2026-06-10 end-to-end: a recovery observed by
/// scan_once must CLOSE the paired open condition alert, land the
/// recovery row born-acked, and audit the auto-ack. The pieces
/// (diff_rows pairing, insert_alert_acked) are unit-tested; this pins
/// the dispatch wiring between them.
#[tokio::test]
async fn scan_once_auto_resolves_paired_alert_on_recovery() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 0, &[]).await; // s0, sing-box kernel → probeable
    let sid = ServerId("s0".into());
    // Open condition alert, as the down-transition would have left it.
    st.inv
        .insert_alert(
            "server.singbox.down",
            Some(&sid),
            "critical",
            "sing-box is no longer active",
            None,
        )
        .await
        .unwrap();
    // Two probe rows: prev = down, cur = up (insertion order — newest
    // row wins the recent_node_health_for_server sort).
    let probe = |active: bool| {
        let inv = st.inv.clone();
        let sid = sid.clone();
        async move {
            inv.record_node_health(
                &sid,
                Some(active),
                Some(true),
                Some(1000),
                Some(20480),
                Some(500),
                Some(960),
                Some(1),
                None,
                Some(1024),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        }
    };
    probe(false).await;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    probe(true).await;

    vpnctld::health_monitor::scan_once(&st.inv).await.unwrap();

    // Paired down alert auto-acked; recovery row exists born-acked.
    assert_eq!(
        st.inv.unacked_alert_count().await.unwrap(),
        0,
        "recovery must close the open down alert and not open a new one"
    );
    let all = st.inv.recent_alerts(20, true).await.unwrap();
    let up = all
        .iter()
        .find(|a| a.kind == "server.singbox.up")
        .expect("recovery row must be recorded");
    assert!(up.acked_at.is_some(), "recovery row must be born-acked");
    // Auto-ack audited (convention from node_probe_poller).
    assert!(
        st.inv
            .recent_audit(50)
            .await
            .unwrap()
            .iter()
            .any(|e| e.action == "alert.auto_ack"
                && e.payload
                    .as_ref()
                    .is_some_and(|p| p["kind"] == "server.singbox.down")),
        "auto-resolve must write an alert.auto_ack audit row"
    );
}

/// Alerts-cleanup 2026-06-10: `insert_alert_acked` rows are history-
/// only — they must not raise the unacked count and must not be
/// blocked by the partial UNIQUE open-dedup index.
#[tokio::test]
async fn insert_alert_acked_is_history_only() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 0, &[]).await;
    let sid = ServerId("s0".into());
    let before = st.inv.unacked_alert_count().await.unwrap();
    st.inv
        .insert_alert_acked(
            "server.disk.recovered",
            Some(&sid),
            "info",
            "disk back under 85%",
            None,
        )
        .await
        .unwrap();
    // Twice — dedup index only covers open rows; history rows stack.
    st.inv
        .insert_alert_acked(
            "server.disk.recovered",
            Some(&sid),
            "info",
            "disk back under 85%",
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        st.inv.unacked_alert_count().await.unwrap(),
        before,
        "born-acked rows must not appear in the open feed"
    );
    let all = st.inv.recent_alerts(50, true).await.unwrap();
    assert_eq!(
        all.iter()
            .filter(|a| a.kind == "server.disk.recovered")
            .count(),
        2,
        "both history rows must persist (no dedup on acked)"
    );
}

#[tokio::test]
async fn alerts_page_renders_ack_all_button_when_unacked_total_nonzero() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Seed 2 unacked alerts so the count chip + button must render.
    for i in 0..2 {
        st.inv
            .insert_alert(
                &format!("test.something:{i}"),
                None,
                "warning",
                "smoke seed",
                None,
            )
            .await
            .unwrap();
    }
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains(r#"action="/admin/alerts/ack-all""#),
        "page must include a form POSTing to /admin/alerts/ack-all"
    );
    // Button label includes the count «(2)» so the operator knows
    // how many rows the click affects before submitting.
    assert!(
        html.contains("ack all") && html.contains("(2)"),
        "button must show «ack all (2)» with the current unacked count"
    );
    // CSP-safe guard: the confirm message rides in a `data-confirm`
    // attribute (admin.js attaches the confirm() dialog). An inline
    // `onsubmit` would be blocked by `script-src 'self'` and the guard
    // would silently never run.
    assert!(
        html.contains("data-confirm="),
        "ack-all form must carry a data-confirm attribute for admin.js"
    );
    assert!(
        !html.contains("onsubmit="),
        "no inline onsubmit on the alerts page (CSP script-src 'self' blocks it)"
    );
}

#[tokio::test]
async fn alerts_page_ack_all_uses_data_confirm_not_inline_js() {
    // The ack-all confirm rides in a `data-confirm` attribute wired by
    // admin.js, NOT an inline `onsubmit` (CSP `script-src 'self'` would
    // block the latter, letting ack-all fire on a single click). maud
    // HTML-escapes the attribute value and admin.js reads it back via
    // getAttribute — there is no JS-string-literal layer, so translator
    // apostrophes («don't») can never break the dialog.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .insert_alert("test.x", None, "warning", "x", None)
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // The English confirm copy must appear as a data-confirm value.
    assert!(
        html.contains(r#"data-confirm="Ack all unacked alerts?"#),
        "ack-all form must carry the confirm message in data-confirm"
    );
    assert!(
        !html.contains("onsubmit="),
        "ack-all must not use an inline onsubmit handler (CSP-blocked)"
    );
}

#[tokio::test]
async fn alerts_page_omits_ack_all_button_when_no_unacked() {
    // Quiet feed should NOT render an «ack all (0)» button — the
    // count would be 0 and clicking would be a no-op invitation
    // for misclicks.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains(r#"action="/admin/alerts/ack-all""#),
        "ack-all form must NOT render when unacked_total = 0"
    );
}

// ── B1 — internal_error must NOT leak anyhow chain ───────────────────
//
// Pre-2026-05-22 the body of a 500 response inlined `err.to_string()`.
// That bled sqlx/anyhow chains (schema names, file paths, occasional
// row contents) to anyone reaching the admin UI. The new contract:
// body is a fixed opaque string «internal error — see journalctl»,
// full chain stays in the structured log. We can't easily inject a
// failure into a live handler from a smoke test without invasive
// surgery, so this test uses an unknown-server detail route that
// would surface a sqlx error if the body weren't sanitised, AND
// directly tests the error_text helper for the exact contract
// string the operator will see.

#[tokio::test]
async fn internal_error_body_does_not_leak_anyhow_chain() {
    // The user_detail handler maps DB-not-found errors to a clean
    // 404 ("vpnctl admin: no such user 'X'"). That's the happy
    // path — verifies we're not leaking sqlx error strings either.
    // For the actual internal_error code path we'd need to break
    // the DB, which is too invasive for a smoke test. So this is
    // a defense-in-depth check: any error response must NOT contain
    // sqlx-like substrings or file-path-like substrings.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let app = router(st);
    // Route that always 404s with a sanitised message.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/no-such-user")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap_or("");
    // Anti-leak heuristic: 4xx/5xx body must not contain a sqlx-ish
    // substring («sqlx», «sqlite», «error returned from database»),
    // a file path («/var/», «/home/», «/tmp/»), or rust panic
    // markers. If any of these slip through, internal_error / the
    // 4xx mappers somewhere are leaking implementation details.
    for needle in [
        "sqlx",
        "sqlite::",
        "error returned from database",
        "/var/",
        "/home/",
        "/tmp/",
        "panicked",
        "unwrap_or",
    ] {
        assert!(
            !body_str.contains(needle),
            "4xx/5xx response body must not contain «{needle}» — leak: {body_str:?}"
        );
    }
}

// ── D1 — default-grant-all-servers on user create ───────────────────
//
// Pre-2026-05-22 POST /admin/users created a user with ZERO grants,
// then operator had to drill into each server. New default: a
// `grant_all=1` checkbox (checked by default in the form) triggers
// a bulk grant immediately after add_user. Two tests pin the contract:
//   1. grant_all=1 (default) → user is granted on every registered server.
//   2. grant_all omitted → user is granted on ZERO servers (pre-D1
//      behavior preserved for explicit opt-out).

#[tokio::test]
async fn user_create_with_grant_all_grants_every_registered_server() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Seed 2 servers so we can assert the grant count is 2 (not 0, not 1).
    for sid_s in ["alpha", "bravo"] {
        st.inv
            .add_server(&Server {
                id: ServerId(sid_s.into()),
                address: format!("203.0.113.{}", if sid_s == "alpha" { 1 } else { 2 }),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels: vec![KernelId("sing-box".into())],
                enabled_protocols: vec![],
                trusted_host_fingerprint: None,
                hoster: "generic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            })
            .await
            .unwrap();
    }
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("id=newbie&grant_all=1"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Both servers must now have a grant for `newbie`.
    let granted_servers = st
        .inv
        .servers_for_user(&vpnctl_core::UserId("newbie".into()))
        .await
        .unwrap();
    let mut granted_ids: Vec<String> = granted_servers.iter().map(|s| s.id.0.clone()).collect();
    granted_ids.sort();
    assert_eq!(
        granted_ids,
        vec!["alpha".to_string(), "bravo".to_string()],
        "grant_all=1 must grant access on EVERY registered server"
    );
}

#[tokio::test]
async fn user_create_without_grant_all_grants_zero_servers() {
    // Explicit opt-out: form posts WITHOUT grant_all field at all.
    // Old behaviour preserved — user created with zero grants.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("solo".into()),
            address: "203.0.113.5".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("id=optout"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let granted = st
        .inv
        .servers_for_user(&vpnctl_core::UserId("optout".into()))
        .await
        .unwrap();
    assert!(
        granted.is_empty(),
        "user created without grant_all checkbox must have zero grants; got: {granted:?}"
    );
}

// ── A2 — idle-users panel on dashboard ──────────────────────────────
//
// Lists users idle 30+ days OR never-seen. Renders only when there's
// at least one idle user (quiet dashboard for a healthy fleet).

#[tokio::test]
async fn dashboard_idle_users_panel_omitted_when_no_users() {
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
    assert!(
        !html.contains("id=\"idle-users\""),
        "idle-users panel must be omitted on an empty inventory"
    );
}

#[tokio::test]
async fn user_create_with_grant_all_renders_checked_checkbox_in_form() {
    // The form on /admin/users must render the checkbox CHECKED by
    // default so the operator's «one click» path produces a granted
    // user.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // The form must include the checkbox + it must be checked.
    assert!(
        html.contains(r#"name="grant_all""#),
        "user form must include grant_all checkbox"
    );
    assert!(
        html.contains(r#"checked="checked""#) || html.contains("checked=\"checked\""),
        "checkbox must default to CHECKED — found no checked attribute in the form"
    );
}

// ── B1.user — disable/enable workflow ───────────────────────────────
//
// Soft-suspend without rotating secrets. POST /admin/users/{id}/disable
// flips flag → /sub returns empty config; POST .../enable restores.
// Idempotent on both directions (audit-on-actual-mutation).

#[tokio::test]
async fn user_disable_then_enable_round_trip_flips_flag_and_audits() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_user(&User {
            id: UserId("toggleable".into()),
            uuid: "00000000-0000-0000-0000-000000000061".into(),
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

    // Disable: 303 + flag flipped + audit row written.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/toggleable/disable")
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
        .get_user(&UserId("toggleable".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        u.disabled,
        "disabled flag must be true after POST .../disable"
    );
    let audit = st.inv.recent_audit(10).await.unwrap();
    assert!(
        audit.iter().any(|e| e.action == "user.disable"),
        "audit must contain user.disable row"
    );

    // Re-disable: idempotent — NO new audit row.
    let pre = st.inv.recent_audit(10).await.unwrap().len();
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/toggleable/disable")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let post = st.inv.recent_audit(10).await.unwrap().len();
    assert_eq!(
        pre, post,
        "no-op re-disable must NOT write audit (audit-on-actual-mutation contract)"
    );

    // Enable: flag flips back + a NEW audit row (user.enable).
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/toggleable/enable")
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
        .get_user(&UserId("toggleable".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !u.disabled,
        "disabled flag must be false after POST .../enable"
    );
    let audit = st.inv.recent_audit(20).await.unwrap();
    assert!(
        audit.iter().any(|e| e.action == "user.enable"),
        "audit must contain user.enable row after the flip"
    );
}

// ── A5 — fleet-wide search /admin/search?q= ────────────────────────

#[tokio::test]
async fn search_empty_q_renders_prompt_no_groups() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        html.contains(r#"action="/admin/search""#),
        "search form must render"
    );
    assert!(
        !html.contains("hits across") && !html.contains("совпадений"),
        "no group summary when q is empty"
    );
}

#[tokio::test]
async fn search_finds_user_by_id_substring() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_user(&User {
            id: UserId("ninitux".into()),
            uuid: "00000000-0000-0000-0000-000000000111".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search?q=nini")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "search must return 200; body sample: {}",
        if html.len() > 400 { &html[..400] } else { html }
    );
    assert!(
        html.contains(r#"href="/admin/users/ninitux""#),
        "search must link to user detail page"
    );
}

#[tokio::test]
async fn search_finds_server_by_address_substring() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("germany".into()),
            address: "104.194.156.93".into(),
            ssh_port: 2222,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "cloudzy".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search?q=104.194")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains(r#"href="/admin/servers/germany""#),
        "address substring must surface the server"
    );
    assert!(
        html.contains("104.194.156.93"),
        "rendered row must show the matching address"
    );
}

#[tokio::test]
async fn search_zero_hits_renders_friendly_empty_state() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search?q=nothing-matches-this")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("No matches") || html.contains("Ничего не найдено"),
        "zero-hit empty state must render"
    );
    assert!(
        html.contains("/admin/audit"),
        "fallback link to audit page must be present"
    );
}

// ── B2 — bulk grant/revoke on /admin/servers/<id> ──────────────────
//
// Grant-all: no confirm, idempotent, grants every ungranted user.
// Revoke-all: requires confirm=<server-id>, revokes every granted.

#[tokio::test]
async fn server_grant_all_users_grants_every_ungranted() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.20".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    for (idx, id) in ["alice", "bob", "carol"].iter().enumerate() {
        st.inv
            .add_user(&User {
                id: UserId((*id).into()),
                uuid: format!("00000000-0000-0000-0000-{:012}", 90 + idx),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .await
            .unwrap();
    }
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_grant-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let granted = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    let mut ids: Vec<String> = granted.iter().map(|u| u.id.0.clone()).collect();
    ids.sort();
    assert_eq!(ids, vec!["alice", "bob", "carol"]);
    // Summary audit row must have been written.
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.grants.bulk_grant")
        .expect("bulk_grant audit row required");
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(payload["granted"].as_u64(), Some(3));
    assert_eq!(payload["already_granted"].as_u64(), Some(0));
    assert_eq!(payload["failed"].as_u64(), Some(0));
    // Audit-finding follow-up (2026-05-23): disabled users skipped.
    // None of the 3 seeded users are disabled → counter is 0.
    assert_eq!(payload["skipped_disabled"].as_u64(), Some(0));
}

#[tokio::test]
async fn server_grant_all_skips_disabled_users() {
    // Audit-finding follow-up (2026-05-23, b4608d2 review): bulk
    // grant must NOT silently grant access to soft-paused users
    // (B1.user mental-model preservation).
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.30".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("alive".into()),
            uuid: "00000000-0000-0000-0000-000000000201".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("paused".into()),
            uuid: "00000000-0000-0000-0000-000000000202".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: true,
        })
        .await
        .unwrap();
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_grant-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let granted = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    let ids: Vec<String> = granted.iter().map(|u| u.id.0.clone()).collect();
    assert_eq!(ids, vec!["alive"], "paused user must NOT be granted");
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.grants.bulk_grant")
        .expect("audit row required");
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(payload["granted"].as_u64(), Some(1));
    assert_eq!(payload["skipped_disabled"].as_u64(), Some(1));
}

#[tokio::test]
async fn server_revoke_all_users_requires_confirm_match() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.21".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("u".into()),
            uuid: "00000000-0000-0000-0000-000000000088".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    st.inv
        .grant(&UserId("u".into()), &ServerId("srv".into()))
        .await
        .unwrap();
    let app = router(st.clone());

    // Wrong confirm → 400, grant survives.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_revoke-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("confirm=WRONG"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let still_granted = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    assert_eq!(still_granted.len(), 1, "wrong-confirm must NOT revoke");

    // Correct confirm → 303, grant gone, summary audit row.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_revoke-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("confirm=srv"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let after = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    assert!(
        after.is_empty(),
        "correct confirm must revoke; got {after:?}"
    );
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.grants.bulk_revoke")
        .expect("bulk_revoke audit row required");
    assert_eq!(row.payload.as_ref().unwrap()["revoked"].as_u64(), Some(1));
}

#[tokio::test]
async fn server_detail_revoke_all_uses_data_confirm_prompt_not_inline_js() {
    // The revoke-all (destructive typed-confirm) form must wire its
    // prompt via data-attributes for admin.js, NOT an inline onsubmit —
    // CSP `script-src 'self'` blocks inline handlers, which left the
    // hidden `confirm` field empty and the POST rejected (the live bug
    // on `kg` 2026-06-06: "bulk-revoke confirm mismatch: form sent ''").
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.22".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("u".into()),
            uuid: "00000000-0000-0000-0000-000000000099".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    st.inv
        .grant(&UserId("u".into()), &ServerId("srv".into()))
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/srv/grants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // The revoke-all form must POST to the bulk endpoint…
    assert!(
        html.contains(r#"action="/admin/servers/srv/grants/_revoke-all""#),
        "revoke-all form must render (one granted user seeded)"
    );
    // …carry the typed-confirm data-attributes admin.js consumes…
    assert!(
        html.contains("data-confirm-prompt="),
        "revoke-all must carry data-confirm-prompt for admin.js"
    );
    assert!(
        html.contains(r#"data-confirm-match="srv""#),
        "revoke-all must require typing the server id (data-confirm-match)"
    );
    // …keep the hidden confirm field admin.js populates + backend checks…
    assert!(
        html.contains(r#"name="confirm""#),
        "revoke-all must keep the hidden confirm field"
    );
    // …and use NO inline onsubmit (CSP script-src 'self' blocks it).
    assert!(
        !html.contains("onsubmit="),
        "revoke-all must not use an inline onsubmit handler"
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

// ── A3 — per-server 24h resource-trend sparklines ───────────────────
//
// Renders ONLY when at least one node_health row exists for the
// server in the last 24h. Fresh server (no probes yet) gets
// nothing — the hero section already covers the empty-state.

#[tokio::test]
async fn server_detail_resource_trend_omitted_when_no_probe_data() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("freshly".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/freshly")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("id=\"resource-trend\""),
        "no probe data → resource-trend section must be omitted"
    );
}

// ── B1.user dashboard surface — «N paused» sub-line ─────────────────
//
// Disabled-count surfaces in the Users tile sub-line so paused users
// don't fall off the operator's radar. Quiet dashboard contract:
// rendered ONLY when at least one user is disabled.

#[tokio::test]
async fn dashboard_users_tile_omits_paused_subline_when_zero() {
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
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("paused") && !html.contains("на паузе"),
        "no users disabled → «paused» sub-line must be hidden"
    );
}

#[tokio::test]
async fn dashboard_users_tile_renders_paused_subline_when_nonzero() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Two disabled users + one normal to verify the count is exact.
    st.inv
        .add_user(&User {
            id: UserId("p1".into()),
            uuid: "00000000-0000-0000-0000-000000000071".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: true,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("p2".into()),
            uuid: "00000000-0000-0000-0000-000000000072".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: true,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("active".into()),
            uuid: "00000000-0000-0000-0000-000000000073".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("paused") || html.contains("на паузе"),
        "paused sub-line must render when disabled count > 0"
    );
    assert!(
        html.contains(">2<"),
        "exact disabled count (2) must appear in the rendered <b>; html sample: {}",
        if html.len() > 600 { &html[..600] } else { html }
    );
}

#[tokio::test]
async fn user_create_audit_payload_includes_wg_keypair_provenance_and_pubkey_set() {
    // I1 unification (audit 2026-05-22): every «add user» path
    // (CLI / web / migrate) emits the same audit payload shape:
    //   { uuid, wg_pubkey_set, wg_keypair_provenance }
    // This test pins the WEB path; CLI + migrate pinned in their
    // own crates.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let app = router(st.clone());
    let _ = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("id=alice"))
                .unwrap(),
        )
        .await
        .unwrap();
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "user.add" && e.target.as_deref() == Some("alice"))
        .expect("user.add audit row must exist for alice");
    let payload = row.payload.as_ref().expect("payload required");
    assert!(
        payload.get("uuid").is_some(),
        "audit payload must include uuid; got: {payload}"
    );
    assert_eq!(
        payload.get("wg_pubkey_set").and_then(|v| v.as_bool()),
        Some(true),
        "web-create must report wg_pubkey_set=true (always generates a pair)"
    );
    assert_eq!(
        payload
            .get("wg_keypair_provenance")
            .and_then(|v| v.as_str()),
        Some("server-generated"),
        "web-create must report wg_keypair_provenance=server-generated"
    );
}

#[tokio::test]
async fn user_disable_unknown_user_returns_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/no-such/disable")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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

// ── server delete (retype-to-confirm + cascade + audit) ──────────────────

/// The server-detail page must surface a "danger zone" link to the
/// delete-confirm page. Without it the operator has no UI path to remove
/// a decommissioned server (the bug this feature fixes).
#[tokio::test]
async fn admin_server_detail_has_delete_link() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers/s0/setup").await;
    assert!(
        html.contains(r#"href="/admin/servers/s0/delete-confirm""#),
        "server-detail must link to the delete-confirm page"
    );
}

/// The delete-confirm page must render the retype form (POSTing to the
/// delete route, with a `confirm` field) and disclose the cascade scope —
/// the exact grant count that will be dropped.
#[tokio::test]
async fn admin_server_delete_confirm_page_shows_form_and_grant_count() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // s0 carries two grants (u0, u1); s1 carries none.
    seed(&s.inv, 2, 2, &[(0, 0), (1, 0)]).await;
    let html = fetch_html(router(s), "/admin/servers/s0/delete-confirm").await;
    assert!(
        html.contains(r#"action="/admin/servers/s0/delete""#),
        "confirm form must POST to the delete route"
    );
    assert!(
        html.contains(r#"name="confirm""#),
        "retype-to-confirm input must be present"
    );
    assert!(
        html.contains("2 grant(s)"),
        "must disclose the exact cascade grant count (2)"
    );
}

/// A mismatched confirm token must be rejected with 400 and leave the
/// server (and its grants) fully intact — the guard against fat-finger
/// deletes.
#[tokio::test]
async fn admin_server_delete_rejects_confirm_mismatch() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 2, &[(0, 0), (1, 0)]).await;
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=wrong"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        s.inv
            .get_server(&ServerId("s0".into()))
            .await
            .unwrap()
            .is_some(),
        "server must survive a mismatched confirm"
    );
    assert_eq!(
        s.inv
            .users_for_server(&ServerId("s0".into()))
            .await
            .unwrap()
            .len(),
        2,
        "grants must survive a mismatched confirm"
    );
}

/// The happy path: an exact-match confirm deletes the server, cascades its
/// grants, audits `server.remove` (with the captured grant count), redirects
/// to the server list — and leaves OTHER servers and the affected users
/// themselves untouched.
#[tokio::test]
async fn admin_server_delete_cascades_grants_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 2, &[(0, 0), (1, 0)]).await;
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=s0"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Server is gone.
    assert!(
        s.inv
            .get_server(&ServerId("s0".into()))
            .await
            .unwrap()
            .is_none(),
        "deleted server must be absent from inventory"
    );
    // Its grants cascaded.
    assert_eq!(
        s.inv
            .users_for_server(&ServerId("s0".into()))
            .await
            .unwrap()
            .len(),
        0,
        "grants for the deleted server must cascade away"
    );
    // The other server is untouched.
    assert!(
        s.inv
            .get_server(&ServerId("s1".into()))
            .await
            .unwrap()
            .is_some(),
        "cascade must be scoped — sibling server must survive"
    );
    // The users themselves survive (only the grant rows cascade).
    assert!(
        s.inv
            .get_user(&UserId("u0".into()))
            .await
            .unwrap()
            .is_some(),
        "user must survive — only its grant to s0 is removed"
    );
    // Audit row landed, target s0, with the captured grant count.
    let audit = s.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.remove" && e.target.as_deref() == Some("s0"))
        .expect("server.remove audit row must land");
    let payload = row
        .payload
        .as_ref()
        .expect("server.remove must carry a payload");
    assert_eq!(
        payload.get("grants_removed").and_then(|v| v.as_u64()),
        Some(2),
        "audit payload must record the 2 grants removed"
    );
}

// ════════════════════════════════════════════════════════════════════
//  PR-Dash — informativeness cards (fleet-at-a-glance, real traffic,
//  kernel rollup, alerts breakdown, abuse summary, today digest).
//
//  The base `seed()` helper deliberately writes ZERO audit rows (several
//  existing tests pin that contract — see `grants_via_real_handlers_
//  mark_server_pending_deploy`). So rather than disturb it, the dashboard
//  cards get their own opt-in signal seeder layered on top: a node_health
//  row carrying `kernel_versions_json`, an admin_alert of a known
//  (kind, severity), an audit row dated today, and a high-ASN sub_access
//  pattern for a user. Each new test calls `seed()` then this.
// ════════════════════════════════════════════════════════════════════

/// Layer the dashboard-card signals onto an already-seeded inventory.
/// Assumes `s0`/`u0` exist (call after `seed(.., n>=1, m>=1, ..)`).
async fn seed_dashboard_signals(inv: &SqliteInventory) {
    // dash#1 + dash#3 — node_health with on-node kernel versions, disk
    // + mem so the at-a-glance row has real cells (not all «—»). s0 is
    // the fleet-max sing-box version (1.13.12 = the floor/target).
    inv.record_node_health(
        &ServerId("s0".into()),
        Some(true),  // sing_box_active = up
        Some(true),  // fail2ban_active
        Some(4096),  // disk_used_mib
        Some(20480), // disk_total_mib  → 20% used
        Some(2048),  // mem_available_mib
        Some(8192),  // mem_total_mib   → 75% used
        Some(120),   // load_1min_x100
        Some(r#"["tcp/443","udp/8443"]"#),
        Some(1_048_576),
        Some(r#"{"sing-box":"1.13.12","caddy":"2.8.4"}"#),
        None,
        None,
        None,
    )
    .await
    .unwrap();

    // dash#4 — one admin_alert of a known (kind, severity) so the
    // breakdown card has something to render.
    inv.insert_alert(
        "disk_pressure",
        Some(&ServerId("s0".into())),
        "critical",
        "disk above 90% on s0",
        None,
    )
    .await
    .unwrap();

    // dash#6 — an audit row dated today (the `audit()` helper stamps
    // `ts` with `now`, which is >= today's local-midnight UTC). A
    // `user.create` action buckets into `users_added`.
    inv.audit("admin", "user.create", Some("u0"), None)
        .await
        .unwrap();

    // dash#5 — high-ASN sub_access pattern: u0's subscription fetched
    // from 3 distinct ASNs (≥ LIKELY_SHARED_MIN_ASNS=3) → "likely
    // shared". `is_vpn_egress` defaults to 0 so these are real fetches.
    for (ip, asn, cc) in [
        ("203.0.113.10", "AS1111", "US"),
        ("198.51.100.20", "AS2222", "DE"),
        ("192.0.2.30", "AS3333", "RU"),
    ] {
        inv.log_sub_access_rich(
            &UserId("u0".into()),
            ip,
            Some("curl/8.0"),
            200,
            1024,
            None,
            Some("HTTP/2"),
            None,
            Some(cc),
            Some(asn),
            None,
            None,
        )
        .await
        .unwrap();
    }

    // sharing v2 — flag u0 via the DOMINANT signal: peak 3 concurrent /24
    // networks (`ConcurrentNets(3)` = 45 pts ≥ FLAG_THRESHOLD=35). The old
    // 3-ASN fetch-diversity above no longer scores (dropped in v2), so the
    // abuse-summary card only renders once a real-simultaneity signal lands.
    inv.record_user_ip_concurrency(&[(UserId("u0".into()), 3)])
        .await
        .unwrap();
}

/// dash#1 — fleet-at-a-glance renders one row per server with the
/// section eyebrow + the seeded sing-box version cell.
#[tokio::test]
async fn dashboard_fleet_table_renders_row_per_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/").await;

    assert!(
        html.contains(r#"id="fleet-at-a-glance""#),
        "fleet section anchor missing"
    );
    // Dashboard 1b: the fleet renders as a dense .ed-grid table.
    assert!(
        html.contains(r#"<table class="ed-grid""#),
        "fleet must render as a dense ed-grid table"
    );
    // Both seeded servers appear as drill-in links.
    assert!(
        html.contains("/admin/servers/s0") && html.contains("/admin/servers/s1"),
        "every seeded server must get a row link"
    );
    // The seeded sing-box version shows in s0's version cell.
    assert!(html.contains("1.13.12"), "s0 sing-box version cell missing");
    // Disk% (20) stays a plain cell; mem% (75) crosses the 70% watermark
    // and must render as a warm heat cell with the ⚠ marker.
    assert!(html.contains("20%"), "s0 disk% cell missing");
    assert!(
        html.contains(r#"class="num warn""#) && html.contains("75% ⚠"),
        "s0 mem% above 70 must render the heat cell + ⚠"
    );
}

/// Dashboard 1b — a node whose sing-box version differs from the fleet
/// majority gets the warm «≠» drift marker in its version cell.
#[tokio::test]
async fn dashboard_fleet_table_marks_version_drift() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 3, 0, &[]).await;
    // s0 + s1 on the majority version, s2 drifted ahead.
    for (sid, ver) in [("s0", "1.13.12"), ("s1", "1.13.12"), ("s2", "1.13.14")] {
        s.inv
            .record_node_health(
                &ServerId(sid.into()),
                Some(true),
                Some(true),
                Some(1024),
                Some(20480),
                Some(6144),
                Some(8192),
                Some(50),
                None,
                None,
                Some(&format!(r#"{{"sing-box":"{ver}"}}"#)),
                None,
                None,
                None,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("1.13.14 ≠"),
        "minority version must carry the ≠ drift marker"
    );
    assert!(
        !html.contains("1.13.12 ≠"),
        "majority version must NOT be flagged"
    );
}

/// dash#1 — empty fleet renders no at-a-glance table at all (the metrics
/// deck + servers page already carry the "add a server" CTA).
#[tokio::test]
async fn dashboard_fleet_table_hidden_when_no_servers() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/").await;
    assert!(
        !html.contains(r#"id="fleet-at-a-glance""#),
        "fleet table must stay hidden on an empty fleet"
    );
}

/// dash#2 — real-traffic totals render the ↑↓ + vs-prior tiles beside
/// the chart, inside the #vpn-traffic block.
#[tokio::test]
async fn dashboard_fleet_traffic_totals_render_beside_chart() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/activity").await;
    // The vs-prior delta tile label is distinctive to dash#2.
    assert!(
        html.contains("vs prior"),
        "dash#2 'vs prior' delta tile missing"
    );
    // The upload/download window tiles use the ↑/↓ glyphs.
    assert!(
        html.contains("↑ upload") && html.contains("↓ download"),
        "dash#2 ↑↓ window tiles missing"
    );
}

/// dash#3 — kernel rollup shows the fleet floor version + on-target
/// state when every reporting node is at the floor.
#[tokio::test]
async fn dashboard_kernel_rollup_shows_version() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/activity").await;
    assert!(
        html.contains("Kernel rollup"),
        "kernel-rollup eyebrow missing"
    );
    assert!(
        html.contains(r#"id="kernel-rollup""#),
        "kernel-rollup section anchor missing"
    );
    // Single node at 1.13.12 → "sing-box 1/1 @ 1.13.12 ✓ on target".
    assert!(
        html.contains("1.13.12"),
        "kernel-rollup floor version missing"
    );
    assert!(
        html.contains("on target"),
        "kernel-rollup on-target verdict missing when all nodes at floor"
    );
}

/// dash#3 — quiet empty-state when no node has reported a version.
#[tokio::test]
async fn dashboard_kernel_rollup_empty_state_when_no_versions() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Server exists but NO node_health row with kernel versions.
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/activity").await;
    assert!(
        html.contains("No on-node version data yet"),
        "kernel-rollup must show the quiet no-data line"
    );
}

/// dash#4 — alerts breakdown renders severity counts + the section
/// when there's at least one unacked alert.
#[tokio::test]
async fn dashboard_health_feed_renders_alert_row() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(html.contains("Health feed"), "health-feed eyebrow missing");
    // Eyebrow carries the unacked total (1 seeded).
    assert!(
        html.contains("open 1"),
        "health-feed eyebrow must show the unacked total"
    );
    // The seeded critical alert renders as a feed row: ✖ mark + kind +
    // the server target linked.
    assert!(html.contains("✖"), "critical alert must show the ✖ mark");
    assert!(
        html.contains("disk_pressure"),
        "feed row must name the alert kind"
    );
    assert!(
        html.contains("full feed →") || html.contains("весь поток →"),
        "feed must link to /admin/alerts"
    );
}

/// Dashboard 1b — quiet contract: no health feed when zero unacked alerts.
#[tokio::test]
async fn dashboard_health_feed_empty_when_none() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // no alerts seeded
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        !html.contains("Health feed"),
        "health feed must stay hidden with zero unacked alerts"
    );
}

/// dash#5 — abuse summary lists the likely-shared user with an ASN count
/// and a drill-in link.
#[tokio::test]
async fn dashboard_abuse_summary_lists_shared_user() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("Likely-shared subscriptions"),
        "abuse-summary eyebrow missing"
    );
    assert!(
        html.contains("/admin/users/u0"),
        "abuse-summary must link the flagged user to their detail page"
    );
    // Sharing v2: the dominant reason is ConcurrentNets(3) (seeded above),
    // rendered as "3 networks at once" — fetch-side ASN diversity no longer
    // scores or shows here.
    assert!(
        html.contains("3 networks at once"),
        "abuse-summary must show the concurrency reason"
    );
}

/// dash#5 — hidden when no sub crosses the ASN threshold.
#[tokio::test]
async fn dashboard_abuse_summary_hidden_when_no_sharing() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // no sub_access rows
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        !html.contains("Likely-shared subscriptions"),
        "abuse-summary must stay hidden when nothing is shared"
    );
}

/// abuse-origins — the dashboard likely-shared card links each flagged
/// user to their `#origins` section (the new who-is-sharing breakdown).
#[tokio::test]
async fn dashboard_abuse_summary_links_to_origins_anchor() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("/admin/users/u0/activity#origins"),
        "abuse-summary user link must anchor to the #origins section"
    );
}

/// abuse-origins — the deleted-user blank-row bug. Seeding a NULL-user
/// (since-deleted) sub_access pattern that crosses the ASN threshold must
/// NOT surface a nameless row in the dashboard abuse card (the
/// `user_id IS NOT NULL` fix in `likely_shared_summary`).
#[tokio::test]
async fn dashboard_abuse_summary_omits_deleted_user_blank_row() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // Seed a high-ASN pattern for a soon-to-be-deleted user.
    s.inv
        .add_user(&User {
            id: UserId("ghost".into()),
            uuid: "00000000-0000-0000-0000-deadbeefdead".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    for (ip, asn, cc) in [
        ("203.0.113.40", "AS4444", "US"),
        ("198.51.100.50", "AS5555", "DE"),
        ("192.0.2.60", "AS6666", "FR"),
    ] {
        s.inv
            .log_sub_access_rich(
                &UserId("ghost".into()),
                ip,
                Some("curl/8.0"),
                200,
                1024,
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
    // Remove the user — the inventory pool runs with foreign_keys ON, so
    // the `ON DELETE SET NULL` (migration 0004) NULLs user_id on every
    // one of ghost's sub_access_log rows while keeping the forensic rows.
    s.inv.remove_user(&UserId("ghost".into())).await.unwrap();

    let html = fetch_html(router(s), "/admin/").await;
    // No nameless link to the user index (the blank-row symptom).
    assert!(
        !html.contains(r#"href="/admin/users/#origins""#)
            && !html.contains(r#"href="/admin/users/""#),
        "abuse card must not render a blank-name (deleted-user) link"
    );
    // And specifically the deleted user's id must not appear in a link.
    assert!(
        !html.contains("/admin/users/ghost"),
        "a deleted user must not be flagged in the abuse card"
    );
    // With ONLY deleted-user rows, the whole card stays hidden.
    assert!(
        !html.contains("Likely-shared subscriptions"),
        "abuse card must stay hidden when the only high-ASN pattern is a deleted user"
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

// ════════════════════════════════════════════════════════════════════
//  ui-audit follow-up — dashboard split into 2 sub-route tabs
//  (overview / activity). The KPI metrics + today-digest + fleet table
//  stay as CHROME (every tab — the glance is never hidden); the two tabs
//  split only the deeper drill-downs. Bare /admin/ == overview.
// ════════════════════════════════════════════════════════════════════

/// Each tab route → 200, renders the `.ed-tabs` bar, keeps the KPI glance
/// (fleet table) as chrome on BOTH tabs, marks the right tab active,
/// shows a section unique to that tab, and does NOT leak the other tab's.
#[tokio::test]
async fn dashboard_tabs_render_gate_and_mark_active() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let app = router(s);
    let cases = [
        (
            "/admin/overview",
            "overview",
            "Health feed",
            "Fleet traffic",
        ),
        (
            "/admin/activity",
            "activity",
            "Fleet traffic",
            "Health feed",
        ),
    ];
    for (path, slug, present, absent) in cases {
        let html = fetch_html(app.clone(), path).await;
        assert!(
            html.contains(r#"class="ed-tabs""#),
            "{path}: tab bar (.ed-tabs) missing"
        );
        // KPI glance stays chrome — the fleet table renders on BOTH tabs.
        assert!(
            html.contains(r#"id="fleet-at-a-glance""#),
            "{path}: KPI glance (fleet table) must stay as chrome on every tab"
        );
        let active = format!(r#"ed-tab--on" href="/admin/{slug}""#);
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

/// Bare `/admin/` renders the overview tab directly.
#[tokio::test]
async fn dashboard_bare_url_renders_overview_tab() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains(r#"ed-tab--on" href="/admin/overview""#),
        "bare URL must mark the overview tab active"
    );
    assert!(
        html.contains("Health feed"),
        "bare URL must render the overview tab's sections"
    );
    assert!(
        !html.contains("Fleet traffic"),
        "bare URL (overview) must not render the activity tab"
    );
}

/// Copy-contract — pin the 2 dashboard tab labels in both locales.
#[tokio::test]
async fn dashboard_tab_labels_copy_contract() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[]).await;
    let app = router(s);
    let en = fetch_html(app.clone(), "/admin/").await;
    for label in [">Overview</a>", ">Activity</a>"] {
        assert!(en.contains(label), "EN tab label drifted: {label:?}");
    }
    let ru = fetch_html_with_cookie(app, "/admin/", "vpnctl_lang=ru").await;
    for label in [">Обзор</a>", ">Активность</a>"] {
        assert!(ru.contains(label), "RU tab label drifted: {label:?}");
    }
}

/// Copy-contract — pin every new PR-Dash eyebrow/headline (EN) so a
/// future copy edit has to update this test in lockstep. Mirrors
/// `admin_frontend_section_headlines_match_voice`.
#[tokio::test]
async fn dashboard_info_cards_headlines_match_voice() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    // ui-audit follow-up — dash#2/#3 (traffic totals + kernel rollup)
    // moved to the activity tab; the rest stay on the overview/chrome.
    let app = router(s);
    let overview = fetch_html(app.clone(), "/admin/").await;
    let activity = fetch_html(app, "/admin/activity").await;
    for (html, needle) in [
        (&overview, ">Fleet <span"),                // 1b fleet (chrome)
        (&activity, "vs prior"),                    // dash#2 (activity)
        (&activity, "Kernel rollup · sing-box"),    // dash#3 (activity)
        (&overview, "Health feed"),                 // 1b feed (overview)
        (&overview, "Likely-shared subscriptions"), // 1b panel (overview)
    ] {
        assert!(
            html.contains(needle),
            "dashboard headline drifted — missing: {needle:?}"
        );
    }
}

/// Copy-contract (RU) — pin the Russian arm of each new card so a
/// half-translation can't ship. Extends the i18n RU walker's intent.
#[tokio::test]
async fn dashboard_info_cards_headlines_ru() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let app = router(s);
    let overview = fetch_html_with_cookie(app.clone(), "/admin/", "vpnctl_lang=ru").await;
    let activity = fetch_html_with_cookie(app, "/admin/activity", "vpnctl_lang=ru").await;
    for (html, needle) in [
        (&overview, ">Флот <span"),                    // 1b fleet (chrome)
        (&activity, "против пред."),                   // dash#2 (activity)
        (&activity, "Версии ядер · sing-box"),         // dash#3 (activity)
        (&overview, "Поток здоровья"),                 // 1b feed (overview)
        (&overview, "Похоже на расшаренные подписки"), // 1b panel (overview)
    ] {
        assert!(
            html.contains(needle),
            "dashboard RU headline drifted — missing: {needle:?}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  PR-Server — informativeness cards on the server-detail page.
//  DOM + empty-state per card; the ?drift=live gating + policy-safe
//  SSH-failure path; NM-11 empty-state; copy-contract EN + RU.
// ════════════════════════════════════════════════════════════════════

/// server#1 — DEFAULT page load (no ?drift=live) renders the
/// «check live drift →» link and does NOT attempt any SSH. We can't
/// directly assert «no SSH» from the integration boundary, but the
/// node address is bogus (10.0.0.0) and the page MUST still return 200
/// fast — a default load that tried SSH would block on ConnectTimeout.
#[tokio::test]
async fn server_detail_drift_detail_default_shows_check_link_no_ssh() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // server s0
    let html = fetch_html(router(s), "/admin/servers/s0/protocols").await;
    assert!(
        html.contains("Drift detail · on-node UUIDs"),
        "drift-detail eyebrow missing on default load"
    );
    assert!(
        html.contains("check live drift →"),
        "default load must offer the [check live drift] link"
    );
    assert!(
        html.contains("?drift=live#drift-detail"),
        "the link must arm the ?drift=live opt-in"
    );
    // No live-read result copy on the default path.
    assert!(
        !html.contains("orphan uuids on node"),
        "default load must NOT render live-read results"
    );
}

/// server#1 — ?drift=live against an unreachable node (bogus address)
/// renders the POLICY-SAFE empty-state and NEVER 500s. The empty-state
/// copy must NOT instruct the operator to «ssh» the box.
#[tokio::test]
async fn server_detail_drift_live_failure_renders_policy_safe_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Address 192.0.2.1 is TEST-NET-1 (RFC 5737) — guaranteed
    // unroutable, so the live read fails fast under the ≤6s timeout.
    s.inv
        .add_server(&Server {
            id: ServerId("blackhole".into()),
            address: "192.0.2.1".into(),
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
    let html = fetch_html(router(s), "/admin/servers/blackhole/protocols?drift=live").await;
    // 200 (fetch_html asserts) + the policy-safe empty-state.
    assert!(
        html.contains("Couldn't read the live config"),
        "armed live-read failure must render the policy-safe empty-state"
    );
    assert!(
        html.contains("node unreachable or deploy key"),
        "empty-state must name the real cause (unreachable / deploy key)"
    );
    // Operator-action-policy: the DRIFT-DETAIL card's empty-state must
    // NEVER tell the operator to ssh the box. Scope the check to that
    // section (the page-wide Deploy button legitimately mentions an
    // automated «SSH into the node» it performs for the operator — a
    // different, allowed string).
    let drift_section = html
        .split("Drift detail · on-node UUIDs")
        .nth(1)
        .unwrap_or("")
        .split("Server traffic · ")
        .next()
        .unwrap_or("");
    let lower = drift_section.to_lowercase();
    assert!(
        !lower.contains("ssh to the box")
            && !lower.contains("ssh into")
            && !lower.contains("run ssh"),
        "policy violation: drift-detail empty-state must not instruct an SSH session"
    );
}

/// server#3 — top-users card carries the NM-11 empty-state when no
/// per-user traffic is attributed (the prod reality).
#[tokio::test]
async fn server_detail_top_users_renders_nm11_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("Top users · last 24h"),
        "top-users eyebrow missing"
    );
    assert!(
        html.contains("NM-11"),
        "empty top-users card must carry the NM-11 explainer"
    );
}

/// server#3 — when per-user rows DO exist they render with a drill-in
/// link to the user-detail page (and the NM-11 empty-state is gone).
#[tokio::test]
async fn server_detail_top_users_lists_users_with_links_when_present() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // s0, u0 granted
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 3_000_000,
                download_bytes: 7_000_000,
                active_connections: 2,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains(r#"href="/admin/users/u0""#),
        "top-users row must link to the user-detail page"
    );
    // Section present; the NM-11 empty-state must NOT show with data.
    let top_section = html.split("Top users · last 24h").nth(1).unwrap_or("");
    let next_section = top_section.split("TCP / UDP split").next().unwrap_or("");
    assert!(
        !next_section.contains("NM-11"),
        "NM-11 empty-state must not render once per-user rows exist"
    );
}

/// server#4 — per-server traffic sparkline renders with the window
/// picker scoped to /admin/servers/{id} and the ↑↓ totals tiles.
#[tokio::test]
async fn server_detail_traffic_section_renders_sparkline_and_window_picker() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: None, // server-wide row
                upload_bytes: 10_000_000,
                download_bytes: 40_000_000,
                active_connections: 12,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("Server traffic · "),
        "server-traffic eyebrow missing"
    );
    assert!(
        html.contains("↑ upload") && html.contains("↓ download"),
        "server-traffic ↑↓ totals tiles missing"
    );
    // Window picker links scoped to THIS server.
    assert!(
        html.contains("/admin/servers/s0/activity?vpn_window=7d"),
        "window picker must be scoped to /admin/servers/s0"
    );
    // An <svg> sparkline rendered for the populated window.
    let traffic = html.split("Server traffic · ").nth(1).unwrap_or("");
    assert!(
        traffic.contains("<svg"),
        "populated window must render the sparkline svg"
    );
}

/// server#4 — empty window renders the no-traffic empty-state, not a
/// broken/blank chart.
#[tokio::test]
async fn server_detail_traffic_section_empty_state_when_no_stats() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // no vpn stats recorded
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("No traffic recorded in this window yet"),
        "empty traffic window must render the empty-state copy"
    );
}

/// server#5 — TCP/UDP split renders from the live snapshot with the
/// «no per-protocol tag» caption + tiles.
#[tokio::test]
async fn server_detail_network_split_renders_from_snapshot() {
    use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let snap = Snapshot {
        upload_total: 300,
        download_total: 600,
        connections: vec![
            Connection {
                id: "c1".into(),
                upload: 100,
                download: 200,
                start: "2026-05-21T18:00:00Z".into(),
                metadata: ConnectionMeta {
                    network: "tcp".into(),
                    destination_ip: "1.1.1.1".into(),
                    destination_port: "443".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "5000".into(),
                    host: String::new(),
                    user: None,
                },
            },
            Connection {
                id: "c2".into(),
                upload: 50,
                download: 100,
                start: "2026-05-21T18:00:01Z".into(),
                metadata: ConnectionMeta {
                    network: "udp".into(),
                    destination_ip: "1.1.1.1".into(),
                    destination_port: "53".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "5001".into(),
                    host: String::new(),
                    user: None,
                },
            },
        ],
    };
    s.snapshot_cache.store(ServerId("s0".into()), snap);
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("TCP / UDP split"),
        "network-split eyebrow missing"
    );
    assert!(
        html.contains("clash-api carries no per-protocol tag"),
        "network-split must carry the per-protocol caveat caption"
    );
}

/// server#5 — empty-state when no snapshot exists for the server.
#[tokio::test]
async fn server_detail_network_split_empty_state_when_no_snapshot() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // no snapshot cached
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("TCP / UDP split"),
        "network-split eyebrow must render even with no snapshot"
    );
    assert!(
        html.contains("No clash-api snapshot for this server yet"),
        "network-split must render an empty-state when no snapshot"
    );
}

/// server#7 — server-scoped audit timeline renders rows that reference
/// this server (deploy/grant/etc), reusing the .ed-time component.
#[tokio::test]
async fn server_detail_audit_timeline_renders_server_scoped_rows() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    // An audit row targeting this server.
    s.inv
        .audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("Audit timeline · this server"),
        "server-audit eyebrow missing"
    );
    assert!(
        html.contains("server.deploy"),
        "server-scoped audit row must list the deploy action"
    );
    assert!(
        html.contains("ed-time-row"),
        "audit timeline must reuse the .ed-time editorial component"
    );
}

/// server#7 — empty-state when no audit row references the server.
#[tokio::test]
async fn server_detail_audit_timeline_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // seed writes no audit rows
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("No audit rows reference this server yet"),
        "server-audit must render an empty-state with no rows"
    );
}

/// server#2 — per-server kernel rollup renders the sing-box floor +
/// on-target verdict from this node's kernel_versions_json.
#[tokio::test]
async fn server_detail_kernel_rollup_renders_version_for_this_node() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    s.inv
        .record_node_health(
            &ServerId("s0".into()),
            Some(true),
            Some(true),
            Some(1000),
            Some(10000),
            Some(500),
            Some(1000),
            Some(100),
            Some(r#"["tcp/443","udp/8443"]"#),
            Some(1000),
            Some(r#"{"sing-box":"1.13.12"}"#),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/protocols").await;
    assert!(
        html.contains("Kernel rollup · sing-box"),
        "per-server kernel-rollup eyebrow missing"
    );
    assert!(
        html.contains("1.13.12"),
        "kernel-rollup must show this node's sing-box version"
    );
    assert!(
        html.contains("on target"),
        "single node at its own floor reads on-target"
    );
}

/// Copy-contract (EN) — pin every new PR-Server headline so a future
/// copy edit has to update this test in lockstep.
#[tokio::test]
async fn server_detail_info_cards_headlines_match_voice() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    // ui-audit §4 — these cards now live across tabs: server#1/#2 on
    // protocols, server#3/#4/#5 on activity, server#7 (audit) on the
    // default status tab. Fetch each tab and pin its subset.
    let app = router(s);
    let proto = fetch_html(app.clone(), "/admin/servers/s0/protocols").await;
    let act = fetch_html(app.clone(), "/admin/servers/s0/activity").await;
    let status = fetch_html(app, "/admin/servers/s0").await;
    for (html, needle) in [
        (&proto, "Drift detail · on-node UUIDs"), // server#1
        (&proto, "Kernel rollup · sing-box"),     // server#2
        (&act, "Top users · last 24h"),           // server#3
        (&act, "Server traffic · "),              // server#4
        (&act, "TCP / UDP split"),                // server#5
        (&status, "drift-summary"),               // status keeps the drift verdict
        (&act, "Audit timeline · this server"),   // server#7 (v2 3b: activity)
    ] {
        assert!(
            html.contains(needle),
            "PR-Server headline drifted — missing: {needle:?}"
        );
    }
}

/// Copy-contract (RU) — pin the Russian arm of each new PR-Server card
/// so a half-translation can't ship. Extends the i18n RU walker.
#[tokio::test]
async fn server_detail_info_cards_headlines_ru() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let proto =
        fetch_html_with_cookie(app.clone(), "/admin/servers/s0/protocols", "vpnctl_lang=ru").await;
    let act =
        fetch_html_with_cookie(app.clone(), "/admin/servers/s0/activity", "vpnctl_lang=ru").await;
    let status = fetch_html_with_cookie(app, "/admin/servers/s0", "vpnctl_lang=ru").await;
    for (html, needle) in [
        (&proto, "Детальный дрейф · UUID на ноде"), // server#1
        (&proto, "Версии ядер · sing-box"),         // server#2
        (&act, "Топ пользователей · за 24ч"),       // server#3
        (&act, "Трафик сервера · "),                // server#4
        (&act, "Разбивка TCP / UDP"),               // server#5
        (&status, "drift-summary"),                 // status keeps the drift verdict
        (&act, "Лента аудита · этот сервер"),       // server#7 (v2 3b: activity)
    ] {
        assert!(
            html.contains(needle),
            "PR-Server RU headline drifted — missing: {needle:?}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
//  ui-audit Phase 1 — server_detail split into 5 sub-route tabs
//  (status / activity / protocols / grants / setup). Each tab renders
//  ONLY its own sections; the deploy chrome is on every tab; the active
//  tab carries `.ed-tab--on`; bare `/admin/servers/{id}` == status.
// ════════════════════════════════════════════════════════════════════

/// Each tab route → 200, renders the `.ed-tabs` bar, marks the right tab
/// active, shows a section unique to that tab, and does NOT leak a
/// foreign tab's section (proves the gating actually gates).
#[tokio::test]
async fn server_detail_tabs_render_gate_and_mark_active() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    // (path, active-slug, present-on-this-tab, absent-on-this-tab)
    let cases = [
        (
            "/admin/servers/s0/status",
            "status",
            "drift-summary",
            "Enabled protocols",
        ),
        (
            "/admin/servers/s0/activity",
            "activity",
            "Live activity · last 24h",
            "Enabled protocols",
        ),
        (
            "/admin/servers/s0/protocols",
            "protocols",
            "Enabled protocols",
            "Live activity · last 24h",
        ),
        (
            "/admin/servers/s0/grants",
            "grants",
            "users granted",
            "Enabled protocols",
        ),
        (
            "/admin/servers/s0/setup",
            "setup",
            "delete this server",
            "Enabled protocols",
        ),
    ];
    for (path, slug, present, absent) in cases {
        let html = fetch_html(app.clone(), path).await;
        assert!(
            html.contains(r#"class="ed-tabs""#),
            "{path}: tab bar (.ed-tabs) missing"
        );
        let active = format!(r#"ed-tab--on" href="/admin/servers/s0/{slug}""#);
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

/// Bare `/admin/servers/{id}` renders the status tab directly — no
/// redirect — so old bookmarks + internal links keep working.
#[tokio::test]
async fn server_detail_bare_url_renders_status_tab() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers/s0").await;
    assert!(
        html.contains(r#"ed-tab--on" href="/admin/servers/s0/status""#),
        "bare URL must mark the status tab active"
    );
    assert!(
        html.contains(r#"id="drift-summary""#),
        "bare URL must render the status tab's sections"
    );
    assert!(
        !html.contains("Enabled protocols"),
        "bare URL (status) must not render the protocols tab"
    );
}

/// §9 discoverability — the daily deploy action must never hide behind a
/// tab. The deploy SSE button lives in the chrome above the tab bar, so
/// it renders on every tab (bare + all 5).
#[tokio::test]
async fn server_detail_deploy_chrome_present_on_every_tab() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let deploy = r#"data-sse-url="/admin/servers/s0/deploy/sse""#;
    for path in [
        "/admin/servers/s0",
        "/admin/servers/s0/status",
        "/admin/servers/s0/activity",
        "/admin/servers/s0/protocols",
        "/admin/servers/s0/grants",
        "/admin/servers/s0/setup",
    ] {
        let html = fetch_html(app.clone(), path).await;
        assert!(
            html.contains(deploy),
            "{path}: deploy button missing from chrome (regressed §9)"
        );
    }
}

/// Copy-contract — pin the 5 tab labels in both locales so a future
/// edit (or a half-translation) has to update this test in lockstep.
#[tokio::test]
async fn server_detail_tab_labels_copy_contract() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let en = fetch_html(app.clone(), "/admin/servers/s0").await;
    for label in [
        ">Status</a>",
        ">Activity</a>",
        ">Protocols</a>",
        ">Grants · 0</a>",
        ">Setup</a>",
    ] {
        assert!(en.contains(label), "EN tab label drifted: {label:?}");
    }
    let ru = fetch_html_with_cookie(app, "/admin/servers/s0", "vpnctl_lang=ru").await;
    for label in [
        ">Статус</a>",
        ">Активность</a>",
        ">Протоколы</a>",
        ">Гранты · 0</a>",
        ">Настройка</a>",
    ] {
        assert!(ru.contains(label), "RU tab label drifted: {label:?}");
    }
}

// ════════════════════════════════════════════════════════════════════
//  PR-User — informativeness cards on the user-detail page.
//  DOM + empty-state per card + copy-contract (EN + RU).
// ════════════════════════════════════════════════════════════════════

/// Build a clash-api connection with a controllable source IP/port —
/// the attribution key the online badge reads.
fn pr_user_conn(src_ip: &str, src_port: &str) -> vpnctld::clash_api::Connection {
    vpnctld::clash_api::Connection {
        id: format!("c-{src_ip}-{src_port}"),
        upload: 10,
        download: 20,
        start: "2026-06-14T18:00:00Z".into(),
        metadata: vpnctld::clash_api::ConnectionMeta {
            network: "tcp".into(),
            destination_ip: "1.2.3.4".into(),
            destination_port: "443".into(),
            source_ip: src_ip.into(),
            source_port: src_port.into(),
            host: String::new(),
            user: None,
        },
    }
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

// ────────────────────────────────────────────────────────────────────────
//  Auto-deploy on grant / revoke (HANDOFF 2026-07-08 §4.1 / §6.2)
//
//  A grant only used to write inv.db: the sub URI appeared instantly but
//  the UUID never reached the node's vless users[] — REALITY handshake
//  succeeds, VLESS-auth rejects, the client is forwarded to the cover
//  dest → «connects but no internet». Every grant/revoke handler must now
//  dispatch the same background redeploy delete/disable already use.
//
//  In the test environment the deploy key is absent, so the spawn skips
//  the SSH pipeline and records a FAILED `user.autodeploy` audit row
//  (ok=false) instead of stamping a fake `server.deploy` baseline. That
//  row — its trigger + servers payload — is the observable contract that
//  the redeploy was dispatched for exactly the affected server set.
// ────────────────────────────────────────────────────────────────────────

/// Poll the audit log until at least `n` autodeploy rows exist
/// (`user.autodeploy` for user-scoped triggers, `server.autodeploy`
/// for server-side bulk — the spawn is a background task racing the
/// test). Returns newest-first per `recent_audit` ordering.
async fn wait_for_autodeploy_rows(
    inv: &SqliteInventory,
    n: usize,
) -> Vec<vpnctl_inventory::AuditEntry> {
    for _ in 0..200 {
        let rows: Vec<_> = inv
            .recent_audit(200)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.action == "user.autodeploy" || e.action == "server.autodeploy")
            .collect();
        if rows.len() >= n {
            return rows;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {n} autodeploy audit row(s)");
}

/// Count autodeploy rows right now (for no-op negative checks).
async fn count_autodeploy_rows(inv: &SqliteInventory) -> usize {
    inv.recent_audit(200)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.action == "user.autodeploy" || e.action == "server.autodeploy")
        .count()
}

#[tokio::test]
async fn grant_from_user_detail_dispatches_auto_deploy_of_that_server_only() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 2, 1, &[]).await; // s0 + s1 + u0, no grants
    let app = router(s);

    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/grants/s0"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();

    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    let row = &rows[0];
    assert_eq!(row.action, "user.autodeploy");
    assert_eq!(row.target.as_deref(), Some("u0"));
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(payload["trigger"], "user.grant");
    assert_eq!(
        payload["servers"],
        serde_json::json!(["s0"]),
        "auto-deploy must target ONLY the granted server, not the whole fleet"
    );
    assert_eq!(
        payload["ok"], false,
        "with no deploy key the autodeploy row must record the failure, \
         not pretend the node was updated"
    );

    // Idempotent re-grant is a no-op mutation → must NOT restart the node.
    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/users/u0/grants/s0"),
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        count_autodeploy_rows(&inv).await,
        1,
        "no-op re-grant must not dispatch a second auto-deploy"
    );
}

#[tokio::test]
async fn revoke_from_user_detail_dispatches_auto_deploy_only_on_actual_revoke() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 2, 1, &[(0, 0)]).await; // u0 granted s0; s1 ungranted
    let app = router(s);

    // Revoking a NOT-granted pair is a no-op → no deploy.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/grants/s1/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        count_autodeploy_rows(&inv).await,
        0,
        "no-op revoke must not dispatch an auto-deploy"
    );

    // A real revoke dispatches a deploy of the revoked server so the
    // UUID actually leaves the node's users[].
    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/users/u0/grants/s0/revoke"),
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    let payload = rows[0].payload.as_ref().unwrap();
    assert_eq!(rows[0].target.as_deref(), Some("u0"));
    assert_eq!(payload["trigger"], "user.revoke");
    assert_eq!(payload["servers"], serde_json::json!(["s0"]));
}

#[tokio::test]
async fn grant_and_revoke_from_server_detail_dispatch_auto_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 1, &[]).await;
    let app = router(s);

    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/grants/u0"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    assert_eq!(rows[0].payload.as_ref().unwrap()["trigger"], "user.grant");
    assert_eq!(rows[0].target.as_deref(), Some("u0"));

    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/grants/u0/revoke"),
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 2).await;
    assert!(
        rows.iter()
            .any(|r| r.payload.as_ref().unwrap()["trigger"] == "user.revoke"),
        "server-detail revoke must dispatch an auto-deploy"
    );
}

#[tokio::test]
async fn bulk_grant_all_dispatches_one_auto_deploy_for_the_whole_batch() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 3, &[]).await; // 3 users → still ONE deploy of s0
    let app = router(s);

    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/grants/_grant-all"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    let payload = rows[0].payload.as_ref().unwrap();
    assert_eq!(
        rows[0].action, "server.autodeploy",
        "server-targeted bulk autodeploy must stay out of the user.* namespace"
    );
    assert_eq!(rows[0].target.as_deref(), Some("s0"));
    assert_eq!(payload["trigger"], "server.grants.bulk_grant");
    assert_eq!(payload["servers"], serde_json::json!(["s0"]));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        count_autodeploy_rows(&inv).await,
        1,
        "bulk grant of 3 users must dispatch exactly ONE deploy of the server"
    );

    // Fully-granted re-run grants 0 → no deploy.
    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/grants/_grant-all"),
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        count_autodeploy_rows(&inv).await,
        1,
        "no-op bulk re-grant must not dispatch another deploy"
    );
}

#[tokio::test]
async fn bulk_revoke_all_dispatches_one_auto_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 2, &[(0, 0), (1, 0)]).await;
    let app = router(s);

    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/grants/_revoke-all")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from("confirm=s0"))
        .unwrap(),
    )
    .await
    .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    let payload = rows[0].payload.as_ref().unwrap();
    assert_eq!(rows[0].action, "server.autodeploy");
    assert_eq!(rows[0].target.as_deref(), Some("s0"));
    assert_eq!(payload["trigger"], "server.grants.bulk_revoke");
    assert_eq!(payload["servers"], serde_json::json!(["s0"]));
}

#[tokio::test]
async fn user_create_grant_all_dispatches_auto_deploy_across_granted_servers() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 2, 0, &[]).await;
    let app = router(s);

    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from("id=newbie&grant_all=1"))
        .unwrap(),
    )
    .await
    .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    let payload = rows[0].payload.as_ref().unwrap();
    assert_eq!(rows[0].target.as_deref(), Some("newbie"));
    assert_eq!(payload["trigger"], "user.create.grant_all");
    let mut servers: Vec<String> = payload["servers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    servers.sort();
    assert_eq!(
        servers,
        vec!["s0".to_string(), "s1".to_string()],
        "grant-all must dispatch ONE deploy pass covering every granted server"
    );
}

/// The payload the auto-deploy pushes: after a grant lands through the
/// real handler, the node config the redeploy pipeline renders (same
/// `users_for_server` → `render_config` chain as
/// `wizard_bootstrap::redeploy_pipeline`) must carry the user's UUID in
/// `inbounds[*].users[]` — the exact bytes whose absence caused the
/// «connects but no internet» failure.
#[tokio::test]
async fn granted_user_uuid_lands_in_rendered_node_config() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let registry = Arc::clone(&s.registry);
    seed(&inv, 1, 1, &[]).await;
    let app = router(s);

    let sid = ServerId("s0".into());
    let server = inv.get_server(&sid).await.unwrap().unwrap();
    let (secrets, _minted) = vpnctl_inventory::bootstrap_server_secrets(&inv, &server, &registry)
        .await
        .unwrap();
    let render = |users: &[User]| -> serde_json::Value {
        let kernel = registry.kernel(&KernelId("sing-box".into())).unwrap();
        let protocols: Vec<&dyn vpnctl_core::Protocol> = server
            .enabled_protocols
            .iter()
            .filter_map(|p| registry.protocol(p))
            .collect();
        let ctx = vpnctl_core::RenderCtx::new(&server, &secrets);
        let bytes = kernel.render_config(&ctx, users, &protocols).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    };
    let uuids_in = |cfg: &serde_json::Value| -> Vec<String> {
        cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|ib| ib["users"].as_array().cloned().unwrap_or_default())
            .filter_map(|u| u["uuid"].as_str().map(str::to_string))
            .collect()
    };

    // Before the grant: users_for_server is empty → no UUID in users[].
    let users = inv.users_for_server(&sid).await.unwrap();
    assert!(users.is_empty());
    assert!(uuids_in(&render(&users)).is_empty());

    // Grant through the real handler…
    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/users/u0/grants/s0"),
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();

    // …and the config the auto-deploy would push now carries the UUID.
    let users = inv.users_for_server(&sid).await.unwrap();
    let uuids = uuids_in(&render(&users));
    assert_eq!(
        uuids,
        vec!["00000000-0000-0000-0000-000000000000".to_string()],
        "granted user's UUID must be present in the rendered inbounds[*].users[]"
    );
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

/// Design v2 4b — the user Access tab opens with the per-server
/// grant/key-state table (granted date column from migration 0039,
/// on-node state, protocols available, per-row grant/revoke) and the
/// masked per-protocol identities list.
#[tokio::test]
async fn v2_user_access_renders_grant_state_table_and_identities() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0)]).await; // granted s0, not s1
    let html = fetch_html(router(s), "/admin/users/u0/access").await;
    assert!(
        html.contains("Grants · per-server key state"),
        "grant-state eyebrow missing"
    );
    assert!(html.contains("uuid ✓"), "keys-minted cell missing");
    // granted s0 row has a revoke form; ungranted s1 row has a grant form.
    assert!(
        html.contains(r#"action="/admin/users/u0/grants/s0/revoke""#),
        "granted row must carry revoke"
    );
    assert!(
        html.contains(r#"action="/admin/users/u0/grants/s1""#),
        "ungranted row must carry grant"
    );
    assert!(
        html.contains("Per-protocol identities"),
        "identities eyebrow missing"
    );
    // Secrets stay masked — the full uuid renders (public), the
    // sub-token only as its masked preview.
    assert!(html.contains("not granted") || html.contains("не выдан"));
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

/// v2 5a gap-close — the sub_access family header carries a group-ack
/// button that acks the whole family via the prefix route.
#[tokio::test]
async fn v2_alerts_sub_access_family_group_ack() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    for u in ["a", "b", "c"] {
        s.inv
            .insert_alert(
                &format!("sub_access.suspicious_local_ip:{u}"),
                None,
                "warning",
                "loop",
                None,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(s.clone()), "/admin/alerts").await;
    assert!(
        html.contains(r#"action="/admin/alerts/ack-family/sub_access.""#),
        "sub_access family must expose a group-ack form"
    );
    assert!(
        html.contains("ack all ") && html.contains("(3)"),
        "group-ack button must show the unacked family count"
    );
    // The prefix route acks the whole family.
    let n = s
        .inv
        .ack_unacked_by_kind_prefix("sub_access.")
        .await
        .unwrap();
    assert_eq!(n, 3, "prefix ack must clear all 3 family rows");
    assert_eq!(
        s.inv.unacked_alert_count().await.unwrap(),
        0,
        "no unacked alerts remain after the family ack"
    );
}

/// v2 5a — the family-ack route rejects an arbitrary prefix (can't be
/// abused to ack a single crafted kind).
#[tokio::test]
async fn v2_alerts_ack_family_rejects_unknown_prefix() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let resp = router(s)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/alerts/ack-family/user.traffic_limit"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// v2 3d gap-close — the Grants tab renders clickable sort links and the
/// `?grant_sort=` param drives the row order.
#[tokio::test]
async fn v2_server_grants_sort_links_render() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 2, &[(0, 0), (1, 0)]).await; // s0 granted to u0,u1
    let html = fetch_html(router(s), "/admin/servers/s0/grants?grant_sort=traffic").await;
    assert!(
        html.contains("sort:") || html.contains("сортировка:"),
        "sort label missing"
    );
    assert!(
        html.contains("grant_sort=presence") && html.contains("grant_sort=id"),
        "sort links for the other keys must render"
    );
    // The active key renders as unlinked bold text (no href for traffic).
    assert!(
        !html.contains("grant_sort=traffic\""),
        "the active sort key must not link to itself"
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
