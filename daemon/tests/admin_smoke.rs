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
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();
    AppState {
        inv,
        registry: Arc::new(reg),
    }
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

    // The chrome was rendered.
    assert!(html.contains("ed-mast"), "missing masthead in html");
    assert!(html.contains("ed-mast__nav-inline"), "missing nav");
    assert!(html.contains("Tweaks"), "missing tweaks panel");
    assert!(html.contains("vpnctl"), "missing wordmark text");
    // The page-root class should default to bare "ed" (no theme/accent
    // cookies set in this test).
    assert!(
        html.contains(r#"class="ed""#),
        "expected default page class \"ed\", got: {}",
        &html[..html.len().min(400)]
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
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("referer", "/admin/")
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
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tweak/theme")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", hostile)
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
                Request::builder()
                    .method("POST")
                    .uri("/admin/tweak/theme")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", referer)
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
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("content-type", "application/x-www-form-urlencoded")
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

/// Locate the `<a ...>` open tag for a given href in the rendered html
/// and return its attribute soup. Returns None if no such anchor exists.
/// Lets active-nav assertions check `class="on"` without depending on
/// the order maud serialises attributes in.
fn anchor_attrs<'a>(html: &'a str, href_value: &str) -> Option<&'a str> {
    let needle = format!("href=\"{href_value}\"");
    for chunk in html.split("<a ") {
        if let Some(end) = chunk.find('>') {
            let open = &chunk[..end];
            if open.contains(&needle) {
                return Some(open);
            }
        }
    }
    None
}

/// Each route (incl. dashboard) must respond 200 and mark its own nav
/// item active. Uses an unordered attribute check so future maud version
/// changes that re-order attribute serialisation don't break the test.
#[tokio::test]
async fn admin_section_routes_render_with_active_nav() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for (path, href_in_nav) in [
        ("/admin/", "/admin/"),
        ("/admin/monitoring", "/admin/monitoring"),
        ("/admin/servers", "/admin/servers"),
        ("/admin/users", "/admin/users"),
        ("/admin/audit", "/admin/audit"),
        ("/admin/settings", "/admin/settings"),
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
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        let attrs = anchor_attrs(html, href_in_nav)
            .unwrap_or_else(|| panic!("no anchor with href={href_in_nav} on {path}"));
        assert!(
            attrs.contains("class=\"on\""),
            "expected active nav for {path} (anchor attrs: {attrs:?})"
        );
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

/// The placeholder body must use `var(--acc)` somewhere so the operator
/// sees the accent toggle take visible effect. Earlier Phase A page only
/// used neutral colours so the accent change felt inert.
#[tokio::test]
async fn admin_placeholder_uses_accent_variable() {
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
        html.contains("border-left: 3px solid var(--acc)"),
        "tweak indicator stripe should be coloured by var(--acc)"
    );
    assert!(
        html.contains("ed-acc"),
        "tweak indicator labels should use the .ed-acc class which reads var(--acc)"
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
            kernel: KernelId("sing-box".into()),
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
            sub_token: None,
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

/// Empty inventory must render the dashboard with all four metric tiles
/// at zero (or "live" for the daemon tile) and the empty-state copy for
/// recent activity. Each integer is anchored to its tile, so swapping
/// tile order in a refactor doesn't fool the test.
#[tokio::test]
async fn admin_dashboard_renders_zero_state_on_empty_db() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/").await;

    assert!(html.contains(r#"class="ed-metrics""#), "metric row missing");
    assert_metric_tile(&html, "Servers", "0");
    assert_metric_tile(&html, "Users", "0");
    assert_metric_tile(&html, "Protocols", "0");
    // Daemon tile uses <em>live</em> instead of an integer; assert that.
    assert!(
        html.contains(
            r#"<span class="ed-metric__lbl">Daemon</span><span class="ed-metric__v"><em>live</em></span>"#
        ),
        "Daemon tile must read 'live'"
    );
    assert!(
        html.contains("No actions logged yet"),
        "audit empty-state copy missing"
    );
}

/// Assert that a metric tile labelled `label` shows value `value` on the
/// dashboard. Anchors the integer to its tile (`<span class="ed-metric__lbl">Servers</span><span class="ed-metric__v">3</span>`)
/// so a refactor that swaps two tiles can't pass the test by accident.
fn assert_metric_tile(html: &str, label: &str, value: &str) {
    let needle = format!(
        r#"<span class="ed-metric__lbl">{label}</span><span class="ed-metric__v">{value}</span>"#
    );
    assert!(
        html.contains(&needle),
        "metric tile {label}={value} not found (looked for {needle:?})"
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

    assert_metric_tile(&html, "Servers", "3");
    assert_metric_tile(&html, "Users", "2");
    // distinct enabled_protocols is 1 (every seeded server gets vless+reality)
    assert_metric_tile(&html, "Protocols", "1");
    assert!(
        html.contains("across <b>4</b> grants"),
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

    // One card per server.
    assert_eq!(
        html.matches(r#"<article class="ed-server">"#).count(),
        3,
        "expected three ed-server cards"
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
        html.contains("across <b>1</b> grant"),
        "singular form 'grant' expected for 1 grant"
    );
    assert!(
        !html.contains("across <b>1</b> grants"),
        "must not pluralise when grant count is 1"
    );

    // 2 grants — plural.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("across <b>2</b> grants"),
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
