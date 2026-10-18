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

#[tokio::test]
async fn admin_tweak_rejects_external_referer() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for hostile in [
        "https://evil.example.com/foo",
        "http://evil.example.com/admin/",
        "//evil.example.com/admin/",
        "/etc/passwd",
        "/admin/../evil.com",
        "/admin//evil.com",
        "/admin/\\evil.com",
        "javascript:alert(1)",
        "data:text/html,<script>1</script>",
    ] {
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

#[tokio::test]
async fn admin_tweaks_no_longer_float_on_dashboard() {
    let dir = TempDir::new().unwrap();
    let html = fetch_html(router(state(&dir).await), "/admin/").await;
    assert!(
        !html.contains(">Tweaks<"),
        "dashboard must not render the deprecated floating Tweaks chip"
    );
    assert!(
        !html.contains("↑ Tweaks"),
        "dashboard must not render the deprecated collapse pill"
    );
    assert!(
        !html.contains("/admin/tweak/theme"),
        "dashboard must not carry the theme form (it lives on /admin/settings now)"
    );
    assert!(
        !html.contains("/admin/tweak/accent"),
        "dashboard must not carry the accent form (it lives on /admin/settings now)"
    );
}

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
    assert!(
        text.contains("known: theme, accent") && !text.contains("tweaks)"),
        "known-kinds list must drop 'tweaks', got {text:?}"
    );
}

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

#[tokio::test]
async fn admin_ed_tweaks_open_class_and_css_rule_are_gone() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let html = fetch_html(app.clone(), "/admin/").await;
    assert!(
        !html.contains("ed-tweaks-open"),
        "deprecated `ed-tweaks-open` class leaked into rendered HTML"
    );

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

#[tokio::test]
async fn i18n_default_locale_is_english_with_english_nav() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/").await;
    let nav = html
        .split_once(r#"class="ed-tb__nav""#)
        .unwrap()
        .1
        .split_once("</nav>")
        .unwrap()
        .0;
    let dashboard = nav
        .split_once(r#"href="/admin/""#)
        .unwrap()
        .1
        .split_once("</a>")
        .unwrap()
        .0;
    assert!(
        dashboard.contains(r#"<use href="/admin/assets/icons.svg#layout-dashboard""#),
        "Dashboard nav must carry its own icon"
    );
    assert_eq!(
        dashboard.split_once("</svg>").unwrap().1.trim(),
        "Dashboard",
        "nav must render Dashboard label in English by default"
    );
    let toggle = html
        .split_once(r#"action="/admin/tweak/lang""#)
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert!(
        toggle.contains(r#"name="value" value="ru""#),
        "language toggle must submit the alternate locale"
    );
    let button = toggle
        .split_once("<button ")
        .unwrap()
        .1
        .split_once("</button>")
        .unwrap()
        .0;
    assert!(
        button.contains(r#"<use href="/admin/assets/icons.svg#languages""#),
        "locale button must carry the languages icon"
    );
    assert_eq!(
        button.split_once("</svg>").unwrap().1.trim(),
        "RU",
        "topbar toggle must offer RU when EN is active"
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
    let nav = html
        .split_once(r#"class="ed-tb__nav""#)
        .unwrap()
        .1
        .split_once("</nav>")
        .unwrap()
        .0;
    for (href, icon, label) in [
        ("/admin/", "layout-dashboard", "Дашборд"),
        ("/admin/servers", "server", "Серверы"),
    ] {
        let link = nav
            .split_once(&format!(r#"href="{href}""#))
            .unwrap()
            .1
            .split_once("</a>")
            .unwrap()
            .0;
        assert!(
            link.contains(&format!(r#"<use href="/admin/assets/icons.svg#{icon}""#)),
            "{href}: Russian nav icon missing"
        );
        assert_eq!(
            link.split_once("</svg>").unwrap().1.trim(),
            label,
            "{href}: Russian nav label drifted"
        );
    }
    assert!(
        html.contains(r#"<html lang="ru""#) || html.contains(r#"<html lang=\"ru\""#),
        "ru cookie must set `<html lang=\"ru\">` for hyphenation + screen readers"
    );
}

#[tokio::test]
async fn i18n_ru_renders_translated_body_copy_on_each_page() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
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

    let h = fetch("/admin/").await;
    assert!(
        h.contains("одним взглядом"),
        "dashboard H1 must read 'homelab одним взглядом' under ru"
    );
    assert!(
        h.contains("Счётчики читаются напрямую из SQLite-инвентаря"),
        "dashboard deck must be translated"
    );
    let h_activity = fetch("/admin/activity").await;
    assert!(
        h_activity.contains("Версии ядер · sing-box"),
        "PR-Dash kernel-rollup eyebrow must be translated under ru"
    );

    let h = fetch("/admin/monitoring").await;
    assert!(
        h.contains("Здоровье"),
        "monitoring H1 must read 'Здоровье флота' under ru"
    );
    assert!(
        h.contains("Пороги алертов"),
        "monitoring thresholds eyebrow must be translated"
    );

    let h = fetch("/admin/servers").await;
    assert!(
        h.contains("в инвентаре"),
        "servers H1 must read 'N серверов в инвентаре'"
    );
    assert!(
        h.contains("Читаются напрямую из SQLite-инвентаря"),
        "servers deck must be translated"
    );

    let h = fetch("/admin/users").await;
    assert!(
        h.contains("в базе"),
        "users H1 must read 'N пользователей в базе'"
    );
    assert!(
        h.contains("публичный URL подписки"),
        "users deck must be translated"
    );

    let h = fetch("/admin/audit").await;
    assert!(
        h.contains("каждое") && h.contains("изменение"),
        "audit H1 must read 'каждое изменение в базе'"
    );

    let h = fetch("/admin/alerts").await;
    assert!(
        h.contains("открытых алертов"),
        "alerts H1 must read 'N открытых алертов' under ru"
    );

    let h = fetch("/admin/settings").await;
    assert!(
        h.contains("homelab") && h.contains("управление"),
        "settings H1 must read 'homelab управление'"
    );
    assert!(
        h.contains("Здесь лежат настройки уровня всего демона"),
        "settings deck must be translated"
    );

    let h = fetch("/admin/servers/s0/protocols").await;
    assert!(
        h.contains("Детальный дрейф · UUID на ноде"),
        "PR-Server drift-detail eyebrow must be translated under ru"
    );

    let h = fetch("/admin/users/u0/activity").await;
    assert!(
        h.contains("Присутствие"),
        "PR-User presence eyebrow must be translated under ru"
    );
    assert!(
        h.contains("Источники подписки"),
        "abuse-origins 'Subscription origins' eyebrow must be translated under ru"
    );
}

#[tokio::test]
async fn i18n_en_default_renders_english_body_copy() {
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
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
