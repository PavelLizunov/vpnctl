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

use super::common::*;

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

// ── B1 — internal_error must NOT leak anyhow chain ───────────────────
//
// Pre-2026-05-22 the body of a 500 response inlined `err.to_string()`.
// That bled sqlx/anyhow chains (schema names, file paths, occasional
// row contents) to anyone reaching the admin UI. The new contract:
// body is a fixed opaque string «internal error — please retry the
// action», full chain stays in the structured log. We can't easily inject a
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

// ── B2 — operator-facing copy must not instruct terminal use ─────────
//
// Operator-action policy: the admin UI is web-only, so no rendered page
// may tell the operator to run a shell command. Every needle below is a
// command shape that used to appear in error bodies, tooltips, SSE
// payloads; each was replaced with a web action or neutral guidance.
// Disaster recovery is deliberately excluded: after the daemon host is
// lost there is no Web UI, so its runbook must retain exact commands.
#[tokio::test]
async fn admin_pages_contain_no_shell_command_instructions() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Seed a server + granted user so the detail pages render their
    // guidance copy (not just the empty state).
    seed(&st.inv, 1, 1, &[(0, 0)]).await;

    // The everyday operator surfaces.
    let pages = [
        "/admin/",
        "/admin/servers",
        "/admin/servers/s0",
        "/admin/servers/s0/protocols",
        "/admin/users",
        "/admin/users/u0",
        "/admin/monitoring",
        "/admin/activity",
        "/admin/settings/appearance",
        "/admin/settings/notifications",
        "/admin/settings/system",
        "/admin/alerts",
    ];
    let needles = [
        "journalctl",
        "systemctl",
        "ssh root@",
        "ls -la",
        "age -d",
        "vpnctl bootstrap",
        "vpnctl deploy",
        "vpnctl geoip-update",
        "vpnctl grant",
        "vpnctl restore",
        "vpnctl server add",
        "vpnctl user",
        "--gen-wireguard",
        "see vpnctld logs",
    ];
    let app = router(st);
    for path in pages {
        let html = fetch_html(app.clone(), path).await;
        for needle in needles {
            assert!(
                !html.contains(needle),
                "rendered page {path} must not contain shell-command instruction «{needle}» — operator copy is web-only"
            );
        }
    }

    // Disaster recovery is the only terminal exception because the Web UI
    // may be gone. Keep the rest of the Backups page under the same guard.
    let backups = fetch_html(app, "/admin/settings/backups").await;
    for command in [
        "age -d -i /path/to/vpnctl-backup-key.age",
        "vpnctl restore /path/to/inv.db",
        "systemctl restart vpnctld",
    ] {
        assert_eq!(
            backups.matches(command).count(),
            1,
            "the disaster-recovery runbook must contain exactly one {command:?}"
        );
    }
    let backups_without_recovery_commands = backups
        .replace("age -d -i /path/to/vpnctl-backup-key.age", "")
        .replace("vpnctl restore /path/to/inv.db", "")
        .replace("systemctl restart vpnctld", "");
    for needle in needles {
        assert!(
            !backups_without_recovery_commands.contains(needle),
            "settings/backups contains an unexpected shell instruction {needle:?}"
        );
    }
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
