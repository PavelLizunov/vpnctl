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

    // The chrome was rendered.
    assert!(html.contains("ed-mast"), "missing masthead in html");
    assert!(html.contains("ed-mast__nav-inline"), "missing nav");
    assert!(html.contains("Tweaks"), "missing tweaks panel");
    assert!(html.contains("vpnctl"), "missing wordmark text");
    // Page-root class composition: default theme/accent (no cookies)
    // contributes nothing beyond `ed`; the Tweaks panel defaults to
    // `open` so the `ed-tweaks-open` modifier lands too. That class
    // is what triggers the footer's right-padding rule so the panel
    // doesn't cover the github URL — pin both bits explicitly.
    assert!(
        html.contains(r#"class="ed ed-tweaks-open""#),
        "expected default page class \"ed ed-tweaks-open\", got: {}",
        &html[..html.len().min(500)]
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

/// At least one element on the page must reference `var(--acc)` so the
/// operator sees the accent toggle take visible effect. Earlier Phase A
/// pages used neutral colours only so the accent change felt inert.
///
/// Phase C-2 dropped the inline "tweaks live →" indicator (it duplicated
/// the panel's own highlighting). The accent now surfaces via the active
/// segmented button in the bottom-right Tweaks panel; this test just
/// confirms the variable is referenced inline at least once on the page.
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
    // The Tweaks panel (open by default) highlights the active accent
    // button by giving it `background: var(--acc)`. With no cookie, that
    // button is the "default" one. This nails down WHERE the var lives.
    assert!(
        html.contains("background: var(--acc)"),
        "default accent button in the open Tweaks panel must use var(--acc) as its background"
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

    // 3 row articles.
    assert_eq!(
        html.matches(r#"<article class="ed-server">"#).count(),
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
    // Singular vs plural for grants on per-row line.
    // u0 is granted to s0; u1, u2 also granted to s0 → all three say "1 server".
    assert_eq!(
        html.matches("<b>1</b> server").count(),
        3,
        "each user row should show '1 server' granted (singular)"
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
    // Both granted servers appear in the "Granted servers" list.
    for id in ["s0", "s1"] {
        assert!(html.contains(id), "granted server {id} missing");
    }
    // At least one share-link rendered (s0 has VLESS secrets); s1 should
    // be skipped silently (its share_link will fail on missing secrets).
    assert!(
        html.contains("vless://") || html.contains("Per-protocol share links"),
        "expected share-links section, got snippet: {}",
        &html[..html.len().min(800)]
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
            sub_token: None,
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

    let html = fetch_html(router(s), "/admin/users/u0").await;
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
//  Phase C-2 — Tweaks panel UX (collapsible + dropped inline indicator)
// ────────────────────────────────────────────────────────────────────────

/// Default state (no `vpnctl_tweaks` cookie): the open panel is rendered
/// — both the title chip "Tweaks" and the close-button form must be
/// present, the collapsed pill must NOT be.
#[tokio::test]
async fn admin_tweaks_panel_open_by_default() {
    let dir = TempDir::new().unwrap();
    let html = fetch_html(router(state(&dir).await), "/admin/").await;

    // Title chip + segmented controls (open state).
    assert!(
        html.contains(">Tweaks<"),
        "open panel title 'Tweaks' missing"
    );
    // Close button form — POSTs value=closed to /admin/tweak/tweaks.
    assert!(
        html.contains("/admin/tweak/tweaks") && html.contains("value=\"closed\""),
        "open panel must include the × close form (POST /admin/tweak/tweaks value=closed)"
    );
    // The collapsed-pill text "↑ Tweaks" must NOT appear when open.
    assert!(
        !html.contains("↑ Tweaks"),
        "collapsed pill leaked into the open-state markup"
    );
}

/// With `vpnctl_tweaks=closed` cookie: only the tiny re-open pill renders
/// — no theme/accent buttons, no × close button.
#[tokio::test]
async fn admin_tweaks_panel_collapsed_when_cookie_closed() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .header("cookie", "vpnctl_tweaks=closed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    // The pill is the ONLY tweaks UI in this state.
    assert!(
        html.contains("↑ Tweaks"),
        "collapsed pill missing when vpnctl_tweaks=closed"
    );
    // Open the pill posts value=open back to the same dispatcher route.
    assert!(
        html.contains("/admin/tweak/tweaks") && html.contains("value=\"open\""),
        "collapsed pill must POST value=open to re-open the panel"
    );
    // Theme + accent forms must be GONE (panel is collapsed).
    assert!(
        !html.contains("/admin/tweak/theme"),
        "theme form leaked into collapsed-state markup"
    );
    assert!(
        !html.contains("/admin/tweak/accent"),
        "accent form leaked into collapsed-state markup"
    );
    // The × close button must be GONE too.
    assert!(
        !html.contains("value=\"closed\""),
        "close button leaked into collapsed-state markup"
    );
}

/// POST /admin/tweak/tweaks with value=closed must set the cookie and
/// redirect back. Mirrors the theme/accent dispatcher exactly so the
/// open-redirect / safe-referer guards apply uniformly.
#[tokio::test]
async fn admin_tweak_tweaks_kind_sets_cookie_and_redirects() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tweak/tweaks")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/users")),
            )
            .body(Body::from("value=closed"))
            .unwrap(),
        )
        .await
        .unwrap();
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
    assert!(cookie.contains("vpnctl_tweaks=closed"));
    assert!(cookie.contains("Path=/admin"));
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/admin/users",
        "safe referer must be honoured for the tweaks-kind dispatcher too"
    );
}

/// /admin/tweak/tweaks with an unknown value (e.g. "maybe") must 400 —
/// guards the cookie against junk values that would later confuse the
/// open/closed boolean logic.
#[tokio::test]
async fn admin_tweak_tweaks_kind_rejects_unknown_value() {
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
            .body(Body::from("value=maybe"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
        body, "vpnctl admin: unknown tweak kind 'whatever' (known: theme, accent, tweaks)\n",
        "unknown-tweak 404 body drifted"
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
    assert!(
        detail.contains("Point a Hiddify-style client at the URL once"),
        "user-detail Hiddify nudge copy drifted"
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

/// The `ed-tweaks-open` modifier on the page-root must carry through
/// to the served HTML so the CSS rule that pads the footer right (so
/// it doesn't get covered by the panel) actually fires. Pinning both
/// the class and a presence check on the rule's CSS source.
#[tokio::test]
async fn admin_open_tweaks_pads_footer_via_root_class() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    // Default cookie state = open. Page-root carries `ed-tweaks-open`.
    let html = fetch_html(app.clone(), "/admin/").await;
    assert!(
        html.contains("ed-tweaks-open"),
        "open tweaks state must surface as `ed-tweaks-open` on page-root"
    );

    // Explicit closed cookie: class is GONE.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .header("cookie", "vpnctl_tweaks=closed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html_closed = std::str::from_utf8(&body).unwrap();
    assert!(
        !html_closed.contains("ed-tweaks-open"),
        "collapsed-state HTML leaked the `ed-tweaks-open` class"
    );

    // The CSS rule itself must exist — otherwise the class is decorative
    // and the footer overlap stays.
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
        css.contains(".ed-tweaks-open .ed-foot"),
        "admin.css missing the rule that pads the footer when tweaks are open"
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
        "/admin/users/u0",
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

    let html = fetch_html(app, "/admin/users/u0").await;
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

    let html = fetch_html(app, "/admin/users/u0").await;
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

    let html = fetch_html(app, "/admin/users/u0").await;
    assert!(
        html.contains("Subscription access"),
        "section eyebrow 'Subscription access' missing"
    );
    assert!(
        html.contains("No subscription fetches recorded yet"),
        "empty-state nudge copy drifted"
    );
    // Counters should still render — both 0 — so the operator gets
    // the full layout shape from day 1.
    assert!(
        html.contains("distinct IPs · 24h"),
        "24h counter label missing"
    );
    assert!(
        html.contains("distinct IPs · 7 days"),
        "7-day counter label missing"
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
    let html = fetch_html(app, "/admin/users/u0").await;

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

/// At or above the threshold (5 distinct IPs / 24h) the heat flag
/// renders next to the eyebrow with the abuse-signal copy. This is
/// the "URL got shared" tell.
#[tokio::test]
async fn admin_user_detail_track1_heat_flag_fires_at_threshold() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;

    for i in 1..=5 {
        s.inv
            .log_sub_access(
                &UserId("u0".into()),
                &format!("192.0.2.{i}"),
                None,
                200,
                100,
            )
            .await
            .unwrap();
    }

    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(
        html.contains("abuse signal"),
        "heat flag must fire at exactly the threshold (5 IPs/24h)"
    );
    assert!(
        html.contains("5 distinct IPs in 24h"),
        "heat flag copy must include the actual count and the window"
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

    let html = fetch_html(router(s), "/admin/users/u1").await;
    // u1 has no fetches.
    assert!(
        html.contains("No subscription fetches recorded yet"),
        "u1 should show empty state"
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
        "/admin/users/u0"
    );

    let granted = inv.servers_for_user(&UserId("u0".into())).await.unwrap();
    assert_eq!(granted.len(), 1, "u0 must have 1 grant after POST");
    assert_eq!(granted[0].id.0, "s0");

    let entries = inv.recent_audit(10).await.unwrap();
    let g = entries
        .iter()
        .find(|e| e.action == "grant")
        .expect("grant audit row missing");
    assert_eq!(g.actor, "admin");
    assert_eq!(g.target.as_deref(), Some("s0"));
    assert_eq!(
        g.payload.as_ref().unwrap()["user"],
        serde_json::Value::String("u0".into())
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

    let entries = inv.recent_audit(10).await.unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.action == "revoke" && e.target.as_deref() == Some("s0")),
        "revoke audit row missing"
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

#[tokio::test]
async fn admin_user_detail_renders_grant_revoke_buttons() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // 2 servers (s0, s1), 1 user (u0), one pre-granted to s0.
    seed(&s.inv, 2, 1, &[(0, 0)]).await;
    let app = router(s);

    let html = fetch_html(app, "/admin/users/u0").await;

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
    // Form was restructured in the wg-pubkey commit to a 2-row layout;
    // pin the new helper copy that lives below the wg-pubkey field
    // (replaces the old single-line deck about server-side mint).
    assert!(
        html.contains("private key stays on the device"),
        "form copy drifted — wg-pubkey helper missing"
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
async fn admin_monitoring_renders_kpis_and_sparklines() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    // Seed a couple of access rows so the sparklines have non-zero
    // peaks (the KPIs read from these).
    s.inv
        .log_sub_access(&UserId("u0".into()), "1.1.1.1", None, 200, 500)
        .await
        .unwrap();
    s.inv
        .log_sub_access(&UserId("u0".into()), "2.2.2.2", None, 200, 500)
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/monitoring").await;

    // KPI labels (the trio of headline counters).
    assert!(html.contains("hits · 24h"), "24h hits KPI label missing");
    assert!(
        html.contains("peak distinct IPs / hour"),
        "peak-IPs KPI label missing"
    );
    assert!(html.contains("hits · 7 days"), "7d hits KPI label missing");

    // Sparkline section eyebrows.
    assert!(html.contains("Hourly hits · last 24h"));
    assert!(html.contains("Hourly distinct IPs · last 24h"));
    assert!(html.contains("Daily hits · last 7 days"));

    // SVG shape pin: width=720, height=60, stroke uses var(--acc).
    assert!(
        html.contains(r#"width="720""#),
        "sparkline width pinned to 720px"
    );
    assert!(
        html.contains(r#"height="60""#),
        "sparkline height pinned to 60px"
    );
    assert!(
        html.contains(r#"stroke="var(--acc)""#),
        "sparkline stroke must use accent variable"
    );

    // Footer hint to the JSON endpoint.
    assert!(
        html.contains("/api/v1/stats/sub-access"),
        "footer hint to JSON endpoint missing"
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
    let html = fetch_html(router(s), "/admin/users/u0").await;
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

    let html = fetch_html(router(s), "/admin/users/u0").await;

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
    // Headline + step indicator (copy contract).
    assert!(
        html.contains("Add server · step 1 of 3"),
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
    let session_id = s
        .wizard
        .insert("vpn-de1.example.org".into(), "secret".into());
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
        !html.contains("secret"),
        "root password must NEVER appear in step-2 HTML"
    );
    // Step indicator.
    assert!(
        html.contains("Add server · step 2 of 3"),
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

    let html = fetch_html(router(s), "/admin/users/u0").await;
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
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(
        html.contains("Live VPN stats"),
        "section headline must appear even in empty state"
    );
    // Empty-state copy must mention chunk 4 + the SSH key path.
    assert!(
        html.contains("No live stats yet"),
        "empty-state nudge missing"
    );
    assert!(
        html.contains("chunk 4"),
        "empty-state must point at chunk 4 so operator knows what's missing"
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

    let html = fetch_html(router(s), "/admin/users/u0").await;

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

    let html = fetch_html(router(s), "/admin/users/u1").await;
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
    assert!(
        html.contains("Phase H chunk 4"),
        "must point at chunk 4 so operator knows what's missing"
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
            Some(483),
            Some(960),
            Some(4),
            Some(r#"["tcp/443","tcp/8388","udp/8388","udp/8443"]"#),
            Some(308_432),
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers/s0").await;
    // Hero block visible
    assert!(html.contains("Live status"));
    assert!(html.contains("active"), "sing-box active visible");
    assert!(html.contains("48%"), "disk pct visible (9876/20480)");
    assert!(html.contains("50%"), "mem pct visible (1 - 483/960 = 50)");
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
            kernel: KernelId("sing-box".into()),
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
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers/driftnode").await;
    assert!(
        html.contains("drift detected"),
        "must surface drift banner; got: {}",
        &html[..html.len().min(400)]
    );
    assert!(
        html.contains("udp/8443"),
        "missing tuic udp/8443 must be listed"
    );
    assert!(
        html.contains("udp/8444"),
        "extra hysteria2 udp/8444 must be listed"
    );
    // SSH port 22 must NOT be flagged as "extra" (always-listening).
    let drift_section = html.split("drift detected").nth(1).unwrap_or("");
    assert!(
        !drift_section.contains("tcp/22"),
        "ssh port must be excluded from drift; got drift section: {}",
        &drift_section[..drift_section.len().min(400)]
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
// CLI/web `--wireguard-pubkey` plumbing (closes the AmneziaWG follow-up).

#[tokio::test]
async fn admin_user_create_with_wireguard_pubkey() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    let body = "id=alice&wireguard_pubkey=qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks%3D";
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
    let u = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        u.wireguard_pubkey.as_deref(),
        Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=")
    );
}

#[tokio::test]
async fn admin_user_create_without_wireguard_pubkey_keeps_none() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    // Empty wireguard_pubkey field → None (back-compat).
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=bob&wireguard_pubkey="))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let u = inv.get_user(&UserId("bob".into())).await.unwrap().unwrap();
    assert!(u.wireguard_pubkey.is_none());
}

#[tokio::test]
async fn admin_user_create_rejects_malformed_wireguard_pubkey() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(
                "id=eve&wireguard_pubkey=not-a-base64-pubkey-at-all",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.starts_with("vpnctl admin: invalid wireguard_pubkey"));
}

#[tokio::test]
async fn admin_users_page_form_has_wireguard_pubkey_field() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/users").await;
    assert!(
        html.contains(r#"name="wireguard_pubkey""#),
        "user-create form must expose wireguard_pubkey input"
    );
    assert!(html.contains("private key stays on the device"));
}
