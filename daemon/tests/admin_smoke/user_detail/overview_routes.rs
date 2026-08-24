use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{User, UserId};
use vpnctld::router;

use crate::common::*;

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
