use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctld::router;

use crate::common::*;

fn assert_inert_icon_sprite(svg: &str) -> std::collections::BTreeSet<&str> {
    let mut ids = std::collections::BTreeSet::new();
    let mut rest = svg;
    while !rest.trim().is_empty() {
        rest = rest.trim_start();
        if let Some(comment) = rest.strip_prefix("<!--") {
            rest = comment.split_once("-->").expect("closed comment").1;
            continue;
        }
        let (tag, tail) = rest
            .strip_prefix('<')
            .expect("sprite contains only markup")
            .split_once('>')
            .expect("closed SVG tag");
        rest = tail;
        let tag = tag.trim_start_matches('/').trim_end_matches('/').trim();
        let (name, mut attrs) = tag.split_once(char::is_whitespace).unwrap_or((tag, ""));
        assert!(
            [
                "svg", "symbol", "path", "circle", "ellipse", "rect", "line", "polyline", "polygon"
            ]
            .contains(&name),
            "unexpected/active SVG element: {name}"
        );
        while !attrs.trim().is_empty() {
            let (attr, value) = attrs.trim_start().split_once('=').expect("SVG attribute");
            let attr = attr.trim();
            assert!(
                [
                    "xmlns",
                    "id",
                    "viewBox",
                    "fill",
                    "stroke",
                    "stroke-width",
                    "stroke-linecap",
                    "stroke-linejoin",
                    "d",
                    "cx",
                    "cy",
                    "r",
                    "rx",
                    "ry",
                    "x",
                    "y",
                    "x1",
                    "x2",
                    "y1",
                    "y2",
                    "width",
                    "height",
                    "points"
                ]
                .contains(&attr),
                "unexpected/active SVG attribute: {attr}"
            );
            let value = value.trim_start();
            let quote = value.chars().next().expect("quoted attribute");
            assert!(matches!(quote, '\'' | '"'));
            let (value, tail) = value[1..].split_once(quote).expect("closed attribute");
            attrs = tail;
            if attr == "xmlns" {
                assert_eq!(value, "http://www.w3.org/2000/svg");
            } else {
                assert!(
                    !value.contains(['&', '<', ':', '/']),
                    "external/entity value: {value}"
                );
                assert!(!value.to_ascii_lowercase().contains("url("));
            }
            if attr == "id" {
                assert_eq!(name, "symbol");
                assert!(ids.insert(value), "duplicate icon ID: {value}");
            }
            if attr == "viewBox" {
                assert_eq!(value, "0 0 24 24");
            }
        }
    }
    for required in [
        "layout-dashboard",
        "activity",
        "server",
        "users",
        "history",
        "bell",
        "settings-2",
        "link",
        "search",
        "plus",
        "check",
        "triangle-alert",
        "circle-x",
        "download",
        "list-filter",
        "rotate-cw",
        "save",
        "arrow-left",
        "arrow-right",
    ] {
        assert!(ids.contains(required), "missing icon symbol: {required}");
    }
    ids
}

#[tokio::test]
async fn admin_icon_sprite_served_with_svg_mime_and_no_active_content() {
    let dir = TempDir::new().unwrap();
    let response = router(state(&dir).await)
        .oneshot(
            Request::builder()
                .uri("/admin/assets/icons.svg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "image/svg+xml");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_inert_icon_sprite(std::str::from_utf8(&body).unwrap());
}

#[tokio::test]
async fn admin_nav_icons_keep_visible_localized_labels_in_every_theme() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    for theme in ["default", "newsprint", "foxed", "ink"] {
        for lang in ["en", "ru"] {
            let html = fetch_html_with_cookie(
                app.clone(),
                "/admin/",
                &format!("vpnctl_theme={theme}; vpnctl_lang={lang}"),
            )
            .await;
            let nav = html
                .split_once(r#"<nav class="ed-tb__nav">"#)
                .unwrap()
                .1
                .split_once("</nav>")
                .unwrap()
                .0;
            let anchors: Vec<_> = nav
                .split("<a ")
                .skip(1)
                .map(|part| part.split_once("</a>").unwrap().0)
                .collect();
            assert_eq!(anchors.len(), 8, "all main navigation items remain");
            for (path, icon, en, ru) in [
                ("/admin/", "layout-dashboard", "Dashboard", "Дашборд"),
                ("/admin/monitoring", "activity", "Monitoring", "Мониторинг"),
                ("/admin/servers", "server", "Servers", "Серверы"),
                ("/admin/users", "users", "Users", "Пользователи"),
                ("/admin/audit", "history", "Audit", "Аудит"),
                ("/admin/alerts", "bell", "Alerts", "Алерты"),
                ("/admin/settings", "settings-2", "Settings", "Настройки"),
                ("/admin/boosty", "link", "Boosty", "Boosty"),
            ] {
                let anchor = anchors
                    .iter()
                    .find(|a| a.contains(&format!("href=\"{path}\"")))
                    .unwrap_or_else(|| panic!("missing navigation {path}"));
                assert!(anchor.contains(&format!("/admin/assets/icons.svg#{icon}")));
                assert!(anchor.contains(r#"aria-hidden="true""#));
                assert!(anchor.contains(r#"focusable="false""#));
                let label = if lang == "en" { en } else { ru };
                assert_eq!(anchor.split_once("</svg>").unwrap().1.trim(), label);
            }
        }
    }
}

#[tokio::test]
async fn admin_page_icons_are_decorative_and_reference_existing_symbols() {
    let ids = assert_inert_icon_sprite(include_str!("../../../assets/icons.svg"));
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let session = s
        .wizard
        .insert("192.0.2.42".into(), "root".into(), "synthetic".into(), 22);
    let app = router(s);
    for &(_, path) in crate::icon_fixtures::ICON_PAGES {
        if path.starts_with("/admin/settings") {
            continue;
        }
        for lang in ["en", "ru"] {
            let html = fetch_html_with_cookie(
                app.clone(),
                path,
                &format!("vpnctl_lang={lang}; vpnctl_wizard={session}"),
            )
            .await;
            let mut count = 0;
            for svg in html.split("<svg").skip(1) {
                let (attrs, body) = svg.split_once('>').unwrap();
                if !attrs.contains("ed-icon") {
                    continue;
                }
                count += 1;
                assert!(
                    attrs.contains(r#"aria-hidden="true""#),
                    "{path}: decorative icon exposed"
                );
                assert!(
                    attrs.contains(r#"focusable="false""#),
                    "{path}: icon is focusable"
                );
                let body = body.split_once("</svg>").unwrap().0;
                let id = body
                    .split_once("/admin/assets/icons.svg#")
                    .expect("local icon reference")
                    .1
                    .split_once('"')
                    .unwrap()
                    .0;
                assert!(ids.contains(id), "{path}: unknown symbol {id}");
            }
            assert!(count >= 8, "{path}: icons missing");
        }
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

    assert!(html.contains(r#"class="ed-tb""#), "missing topbar in html");
    assert!(html.contains(r#"class="ed-tb__nav""#), "missing topbar nav");
    assert!(
        html.contains(r#"id="tb-search""#),
        "missing topbar search input"
    );
    assert!(html.contains("vpnctl"), "missing wordmark text");
    assert!(
        !html.contains(">Tweaks<"),
        "dashboard must not carry the (deprecated) floating Tweaks chip"
    );
    assert!(
        !html.contains("↑ Tweaks"),
        "dashboard must not carry the (deprecated) collapse pill"
    );
    assert!(
        html.contains(r#"class="ed""#),
        "expected default page class to be just 'ed', got: {}",
        &html[..html.len().min(500)]
    );
}

#[tokio::test]
async fn v2_topbar_renders_active_pill_search_and_live_alert_count() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
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
        detail.contains("Legacy")
            && detail.contains("LAN-only")
            && detail.contains("scripts/import_from_subscription_server.py"),
        "user-detail legacy-fallback copy drifted (no-device_id branch)"
    );
    let detail_activity = fetch_html(app.clone(), "/admin/users/u0/activity").await;
    assert!(
        detail_activity.contains("Subscription origins"),
        "user-detail 'Subscription origins' section headline drifted"
    );
}

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

#[tokio::test]
async fn admin_audit_empty_state_renders_nudge() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/audit").await;
    assert!(
        html.contains("No audit rows yet"),
        "empty-state nudge missing"
    );
    assert!(
        html.contains(r#"action="/admin/audit""#),
        "filter form action drifted"
    );
    assert!(html.contains(">filter<"), "filter button label drifted");
    assert!(html.contains(">export csv<"), "csv export link missing");
}

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

    let html = fetch_html(app.clone(), "/admin/audit").await;
    assert!(html.contains("user.add"));
    assert!(html.contains("server.deploy"));

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

#[tokio::test]
async fn admin_audit_pagination_links_render_correctly() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    for i in 0..60 {
        s.inv
            .audit("admin", "user.add", Some(&format!("u{i}")), None)
            .await
            .unwrap();
    }
    let app = router(s);

    let html = fetch_html(app.clone(), "/admin/audit").await;
    assert!(
        html.contains(r#"href="/admin/audit?page=1""#),
        "page 0 must link forward to page=1"
    );
    assert!(
        !html.contains("page=-1"),
        "disabled prev must not produce a page=-1 link"
    );
    let row_count_p0 = html.matches("class=\"ed-time-row\"").count();
    assert_eq!(
        row_count_p0, 50,
        "page 0 must show exactly PAGE_SIZE=50 rows, got {row_count_p0}"
    );

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
    let cc = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        cc, "no-store",
        "Cache-Control must be no-store for audit CSV export, got {cc:?}"
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
    let expected_payload = r#""{""uuid"":""uuid-with-\""quote\"", and-comma""}""#;
    assert!(
        row.contains(expected_payload),
        "payload not RFC4180-escaped as expected;\n  expected to contain: {expected_payload}\n  got row:             {row}"
    );
}

#[tokio::test]
async fn admin_audit_csv_export_redacts_sensitive_payload_fields() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .audit(
            "admin",
            "user.sub_token.regen",
            Some("bob"),
            Some(&serde_json::json!({
                "sub_token": "secret-token-12345",
                "password_hash": "secret-hash-67890",
                "user": "bob"
            })),
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

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let csv = std::str::from_utf8(&body).unwrap();

    assert!(
        !csv.contains("secret-token-12345"),
        "CSV export leaked sub_token secret"
    );
    assert!(
        !csv.contains("secret-hash-67890"),
        "CSV export leaked password secret"
    );
    assert!(
        csv.contains("<redacted>"),
        "CSV export missing <redacted> placeholder"
    );
    assert!(
        csv.contains("bob"),
        "CSV export missing non-secret user field"
    );
}

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
async fn tooltips_audit_filter_form_carries_explainers() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/audit").await;
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
