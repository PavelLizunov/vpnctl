use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{User, UserId};
use vpnctld::router;

use crate::common::*;

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

#[tokio::test]
async fn admin_user_detail_pending_banner_has_inline_deploy_all_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;
    s.inv
        .audit("admin", "user.grant", Some("u0"), None)
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(
        html.contains("Config not yet deployed to") || html.contains("ещё не задеплоен"),
        "pending-deploy banner must render when grants aren't deployed"
    );
    assert!(
        html.contains(r#"data-sse-url="/admin/users/u0/deploy-pending/sse""#),
        "in-view deploy button must target the per-user pending SSE endpoint"
    );
    assert!(
        !html.contains(r#"data-sse-url="/admin/servers/deploy-all/sse""#),
        "user page must NOT wire the fleet-wide deploy-all any more"
    );
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

#[tokio::test]
async fn user_detail_tabs_render_gate_and_mark_active() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0)]).await;
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

#[tokio::test]
async fn user_detail_tab_labels_copy_contract() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[]).await;
    let app = router(s);
    let en = fetch_html(app.clone(), "/admin/users/u0").await;
    let ru = fetch_html_with_cookie(app, "/admin/users/u0", "vpnctl_lang=ru").await;
    for (slug, icon, en_label, ru_label) in [
        ("overview", "layout-dashboard", "Overview", "Обзор"),
        ("delivery", "send", "Delivery", "Выдача"),
        ("access", "key-round", "Access · 0", "Доступ · 0"),
        ("activity", "activity", "Activity", "Активность"),
        ("traffic", "chart-no-axes-combined", "Traffic", "Трафик"),
    ] {
        for (html, label) in [(&en, en_label), (&ru, ru_label)] {
            let tabs = html
                .split_once(r#"class="ed-tabs""#)
                .unwrap()
                .1
                .split_once("</div>")
                .unwrap()
                .0;
            let link = tabs
                .split_once(&format!(r#"href="/admin/users/u0/{slug}""#))
                .unwrap()
                .1
                .split_once("</a>")
                .unwrap()
                .0;
            assert!(
                link.contains(&format!(r#"<use href="/admin/assets/icons.svg#{icon}""#)),
                "{slug}: tab icon missing"
            );
            assert_eq!(
                link.split_once("</svg>").unwrap().1.trim(),
                label,
                "{slug}: tab label drifted"
            );
        }
    }
}

#[tokio::test]
async fn user_detail_mint_tuic_button_shows_when_absent_and_mints_on_post() {
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
    assert!(
        html.contains(r#"action="/admin/users/paused/enable""#),
        "must offer enable button for a disabled user"
    );
    assert!(
        !html.contains(r#"action="/admin/users/paused/disable""#),
        "must NOT also show disable button (already disabled)"
    );
}

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

#[tokio::test]
async fn pr_user_info_cards_headlines_en() {
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
    let overview = fetch_html(app.clone(), "/admin/users/u0").await;
    let traffic = fetch_html(app, "/admin/users/u0/traffic").await;
    for (html, needle) in [
        (&overview, "Presence"),
        (&traffic, "Live VPN stats"),
        (&overview, "Sharing verdict"),
        (&overview, "Lifecycle"),
        (&overview, "Traffic limit"),
    ] {
        assert!(
            html.contains(needle),
            "PR-User EN headline drifted — missing: {needle:?}"
        );
    }
}

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
        (&overview, "Присутствие"),
        (&traffic, "Живая статистика VPN"),
        (&overview, "Вердикт по расшариванию"),
        (&overview, "Жизненный цикл"),
        (&overview, "Лимит трафика"),
    ] {
        assert!(
            html.contains(needle),
            "PR-User RU headline drifted — missing: {needle:?}"
        );
    }
}

#[tokio::test]
async fn user_detail_loads_other_users_credentials_only_for_delivery() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 2, &[(0, 0), (1, 0)]).await;
    // Fail decoding a peer's credential without changing the displayed user.
    let status = std::process::Command::new("python3")
        .args(["-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE users SET uuid = x'ff' WHERE id = 'u1'\"); c.commit(); c.close()"])
        .arg(dir.path().join("inv.db"))
        .status()
        .unwrap();
    assert!(status.success());
    let app = router(s);
    for tab in ["overview", "access", "activity", "traffic"] {
        let html = fetch_html(app.clone(), &format!("/admin/users/u0/{tab}")).await;
        assert!(html.contains("u0"));
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/u0/delivery")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
