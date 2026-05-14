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
