use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::*;

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
async fn admin_server_detail_lists_all_users_with_grant_buttons() {
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
