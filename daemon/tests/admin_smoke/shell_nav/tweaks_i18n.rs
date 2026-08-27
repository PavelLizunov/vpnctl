use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctld::router;

use crate::common::*;

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
        "/admin/..//evil.example.com", // path traversal protocol-relative escape
        "/admin/..\\evil.example.com", // backslash path traversal escape
        "/admin/users/../..",          // path traversal escape out of /admin
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
