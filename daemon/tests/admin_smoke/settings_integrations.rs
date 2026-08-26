use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::UserId;
use vpnctld::router;

use super::common::*;

// ════════════════════════════════════════════════════════════════════
//  ui-audit Phase 3 — settings split into 4 sub-route tabs
//  (appearance / backups / notifications / system). Each tab renders
//  ONLY its own sections; bare /admin/settings == appearance.
// ════════════════════════════════════════════════════════════════════

/// Each tab route → 200, renders the `.ed-tabs` bar, marks the right tab
/// active, shows a section unique to that tab, and does NOT leak a
/// foreign tab's section.
#[tokio::test]
async fn settings_tabs_render_gate_and_mark_active() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let cases = [
        (
            "/admin/settings/appearance",
            "appearance",
            "Appearance — theme + accent",
            "Backups — inventory snapshots",
        ),
        (
            "/admin/settings/backups",
            "backups",
            "Backups — inventory snapshots",
            "Appearance — theme + accent",
        ),
        (
            "/admin/settings/notifications",
            "notifications",
            r#"id="telegram-notifications""#,
            "Appearance — theme + accent",
        ),
        (
            "/admin/settings/system",
            "system",
            r#"id="deploy-ssh-key""#,
            "Appearance — theme + accent",
        ),
    ];
    for (path, slug, present, absent) in cases {
        let html = fetch_html(app.clone(), path).await;
        assert!(
            html.contains(r#"class="ed-tabs""#),
            "{path}: tab bar (.ed-tabs) missing"
        );
        let active = format!(r#"ed-tab--on" href="/admin/settings/{slug}""#);
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

/// Bare `/admin/settings` renders the appearance tab directly.
#[tokio::test]
async fn settings_bare_url_renders_appearance_tab() {
    let dir = TempDir::new().unwrap();
    let html = fetch_html(router(state(&dir).await), "/admin/settings").await;
    assert!(
        html.contains(r#"ed-tab--on" href="/admin/settings/appearance""#),
        "bare URL must mark the appearance tab active"
    );
    assert!(
        html.contains("Appearance — theme + accent"),
        "bare URL must render the appearance tab's sections"
    );
    assert!(
        !html.contains("Backups — inventory snapshots"),
        "bare URL (appearance) must not render the backups tab"
    );
}

/// Copy-contract — pin the 4 settings tab labels in both locales.
#[tokio::test]
async fn settings_tab_labels_copy_contract() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let en = fetch_html(app.clone(), "/admin/settings").await;
    for label in [
        ">Appearance</a>",
        ">Backups</a>",
        ">Notifications</a>",
        ">System</a>",
    ] {
        assert!(en.contains(label), "EN tab label drifted: {label:?}");
    }
    let ru = fetch_html_with_cookie(app, "/admin/settings", "vpnctl_lang=ru").await;
    for label in [
        ">Внешний вид</a>",
        ">Бэкапы</a>",
        ">Уведомления</a>",
        ">Система</a>",
    ] {
        assert!(ru.contains(label), "RU tab label drifted: {label:?}");
    }
}

#[tokio::test]
async fn admin_settings_page_hosts_theme_and_accent_pickers() {
    let dir = TempDir::new().unwrap();
    let html = fetch_html(router(state(&dir).await), "/admin/settings").await;
    // Inline section title.
    assert!(
        html.contains("Appearance — theme + accent"),
        "Settings page must have the Appearance section heading"
    );
    // Both forms — same POST endpoints as before, just embedded inline.
    assert!(
        html.contains("action=\"/admin/tweak/theme\""),
        "Settings page must carry the theme form"
    );
    assert!(
        html.contains("action=\"/admin/tweak/accent\""),
        "Settings page must carry the accent form"
    );
    // Every theme + accent option must be present as a button.
    for name in &["default", "newsprint", "foxed", "ink"] {
        assert!(
            html.contains(&format!("value=\"{name}\"")),
            "Settings page missing theme/accent option button '{name}'"
        );
    }
    for name in &["rust", "forest", "plum"] {
        assert!(
            html.contains(&format!("value=\"{name}\"")),
            "Settings page missing accent option button '{name}'"
        );
    }
}

#[tokio::test]
async fn boosty_page_renders_and_is_in_nav() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/boosty").await;
    assert!(
        html.contains("Boosty"),
        "page must render the Boosty heading"
    );
    assert!(
        html.contains("/admin/boosty"),
        "nav must link to the boosty page"
    );
    // Default seeded settings: disabled, no creds → secrets show masked/unset.
    assert!(
        html.contains("(unset)"),
        "unset creds must render as (unset)"
    );
    // 2026-07-10 editorial restyle — the page now uses the shared
    // component system, not the bespoke `.ed-title` / `.ed-eyebrow`
    // scaffold, and the status renders as a tile strip.
    assert!(
        html.contains(r#"class="ed-art-h1""#) && html.contains(r#"class="ed-art-deck""#),
        "boosty page must use the editorial h1 + deck"
    );
    assert!(
        html.contains(r#"class="ed-status-strip""#),
        "bridge status must render as a status-tile strip"
    );
    assert!(
        !html.contains(r#"class="ed-title""#) && !html.contains(r#"class="ed-eyebrow""#),
        "legacy .ed-title / .ed-eyebrow scaffold must be gone"
    );
    // Regression: the sync-health callouts referenced an undefined
    // `--bad` CSS var (rendered black, not red) before the restyle.
    assert!(
        !html.contains("var(--bad)"),
        "must not reference the undefined --bad token"
    );
    // Disabled bridge → the «polling off» pill.
    assert!(
        html.contains("polling off"),
        "a disabled bridge must show the polling-off pill"
    );
}

#[tokio::test]
async fn boosty_link_then_unlink_via_web() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&mk_user("alice", false)).await.unwrap();
    let app = router(s);

    // Link.
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/boosty/link")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/boosty")),
            )
            .body(Body::from("user=alice&subscriber_id=4242"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "link must redirect");
    let links = inv.list_boosty_links().await.unwrap();
    assert_eq!(links, vec![(UserId("alice".into()), 4242)]);

    // Unlink.
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/boosty/unlink/alice")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/boosty")),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "unlink must redirect");
    assert!(inv.list_boosty_links().await.unwrap().is_empty());
}

#[tokio::test]
async fn boosty_settings_save_via_web() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/boosty/settings")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/boosty")),
            )
            .body(Body::from(
                "blog_url=ninitux&poll_interval_secs=1800&grace_days=14&enabled=on&auto_create_users=on",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let got = inv.get_boosty_settings().await.unwrap();
    assert!(got.enabled);
    assert_eq!(got.blog_url.as_deref(), Some("ninitux"));
    assert_eq!(got.poll_interval_secs, 1800);
    assert_eq!(got.grace_days, 14);
    assert!(got.auto_create_users);
}

#[tokio::test]
async fn boosty_page_explains_refresh_credentials_are_preferred() {
    let dir = TempDir::new().unwrap();
    let html = fetch_html(router(state(&dir).await), "/admin/boosty").await;

    assert!(html.contains("refresh token · preferred"));
    assert!(html.contains("device id · with refresh"));
    assert!(html.contains("access token · fallback"));
    assert!(html.contains(
        "Access token is a short-lived fallback used only when that pair is incomplete."
    ));
}

#[tokio::test]
async fn boosty_disable_button_soft_mutes_user() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&mk_user("bob", false)).await.unwrap();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/boosty/disable/bob")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/boosty")),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let users = inv.list_users().await.unwrap();
    let bob = users.iter().find(|u| u.id.0 == "bob").unwrap();
    assert!(bob.disabled, "disable button must soft-mute the user");
}

/// The page renders its actionable sections from the LAST STORED sync
/// report — no live Boosty call on GET (no mock server exists here, so a
/// live sync would error or hang; csrf contract: admin GETs don't mutate).
#[tokio::test]
async fn boosty_page_renders_stored_report_without_live_sync() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let mut cfg = inv.get_boosty_settings().await.unwrap();
    cfg.enabled = true;
    cfg.blog_url = Some("ninitux".into());
    cfg.refresh_token = Some("r".into());
    cfg.device_id = Some("d".into());
    inv.set_boosty_settings(&cfg).await.unwrap();
    inv.set_boosty_report_and_events(
        &serde_json::json!({
            "observed_at": 1_754_000_000_i64,
            "total_subscribers": 2,
            "active_subscribers": 1,
            "linked": 1,
            "enabled": [],
            "disabled": [],
            "lapsed_pending": ["bob"],
            "grace_pending": ["eve"],
            "new_subscribers": [{"subscriber_id": 300, "name": "Carol"}],
            "provisioned": ["boosty-301"],
            "errors": [],
            "suppressed_disables": ["dave"],
            "subscribers": [{
                "subscriber_id": 300,
                "name": "Carol",
                "present": true,
                "status": "active",
                "subscribed": true,
                "price": "500",
                "payments": "1500",
                "level_id": 7,
                "level_name": "Supporter",
                "level_price": "500",
                "can_write": true
            }]
        })
        .to_string(),
        &[(
            "boosty.subscriber.changed".into(),
            Some("300".into()),
            serde_json::json!({
                "kind": "changed",
                "name": "Carol",
                "payments": "1500"
            }),
        )],
    )
    .await
    .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/boosty").await;
    assert!(
        html.contains("/admin/boosty/disable/bob"),
        "lapsed user gets a confirm-disable button: {html}"
    );
    assert!(html.contains("Carol"), "new subscriber from stored report");
    assert!(html.contains("boosty-301"), "auto-created user renders");
    assert!(html.contains("eve"), "grace-period user renders");
    assert!(html.contains("dave"), "suppressed-disables banner renders");
    assert!(html.contains("Boosty roster snapshot"));
    assert!(html.contains("1500"), "cumulative payments value renders");
    assert!(html.contains("boosty.subscriber.changed"));
    assert!(html.contains("{…}"), "full event payload is expandable");
    assert!(
        html.contains("configured"),
        "refresh + device is sufficient"
    );
}

/// BB-3 (link-UX): a subscriber the operator already linked must NOT linger
/// in the "new subscribers to link" list rendered from the (stale) stored
/// report — the redirect after a link must show them gone WITHOUT waiting
/// for the next sync. The linked subscriber still appears under "Linked
/// users", so we assert the *new-subscriber link form* (`boosty-link-<id>`)
/// is what's absent.
#[tokio::test]
async fn boosty_page_drops_already_linked_subscriber_from_new_list() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&mk_user("pyrojokk", false)).await.unwrap();
    let mut cfg = inv.get_boosty_settings().await.unwrap();
    cfg.enabled = true;
    cfg.blog_url = Some("ninitux".into());
    inv.set_boosty_settings(&cfg).await.unwrap();
    // Stored report (pre-link snapshot) still lists 45221733 as "new".
    inv.set_boosty_last_report(
        &serde_json::json!({
            "total_subscribers": 2,
            "active_subscribers": 2,
            "linked": 0,
            "new_subscribers": [
                {"subscriber_id": 45221733, "name": "Alyona"},
                {"subscriber_id": 999, "name": "Other"}
            ]
        })
        .to_string(),
    )
    .await
    .unwrap();
    // Operator links 45221733 → pyrojokk (no sync yet).
    inv.link_boosty_subscriber(&vpnctl_core::UserId("pyrojokk".into()), 45221733)
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/boosty").await;
    assert!(
        !html.contains("boosty-link-45221733"),
        "already-linked subscriber must not have a new-subscriber link form"
    );
    assert!(
        html.contains("boosty-link-999"),
        "the still-unlinked subscriber keeps its link form"
    );
    assert!(html.contains("pyrojokk"), "linked user rendered");
}

/// AC-B3 (NM-10 audit-on-actual-mutation): double-submitting the confirm
/// button writes exactly ONE `boosty.disable` audit row — the second POST
/// is a no-op (user already disabled) and must not spam the timeline or
/// trigger a second redeploy.
#[tokio::test]
async fn boosty_disable_double_submit_audits_once() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&mk_user("bob", false)).await.unwrap();
    let app = router(s);

    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(
                add_same_origin(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/boosty/disable/bob")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .header("referer", format!("http://{SAME_ORIGIN_HOST}/admin/boosty")),
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    let audits = inv.recent_audit(20).await.unwrap();
    let disable_rows = audits
        .iter()
        .filter(|a| a.action == "boosty.disable")
        .count();
    assert_eq!(disable_rows, 1, "double-submit must audit exactly once");
}

// ────────────────────────────────────────────────────────────────────────
//  Coverage batch (audit 2026-06-10) — routes that had ZERO test
//  references: logout, set-fingerprint, reserved-ports, timezone,
//  auto-suppress, display-name; plus pins for the W5 fixes (no-op
//  audit gating, LIKE-escape).
// ────────────────────────────────────────────────────────────────────────

/// POST /admin/logout must expire the session cookie (Max-Age=0) —
/// auth surface; a broken logout means sessions can't be ended and
/// nothing else would catch it.
#[tokio::test]
async fn admin_logout_expires_session_cookie() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let resp = router(s)
        .oneshot(
            add_same_origin(Request::builder().method("POST").uri("/admin/logout"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_redirection(), "logout must redirect");
    let cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("logout must set a cookie header");
    assert!(
        cookie.contains("Max-Age=0"),
        "logout cookie must expire the session, got: {cookie}"
    );
}

/// POST set-fingerprint (manual): 303 + ONE dot-convention audit row
/// (`server.fingerprint.set`); a same-value re-pin is a no-op (no
/// second row — NM-10); junk shape is a 400.
#[tokio::test]
async fn admin_set_fingerprint_manual_audits_once_and_validates() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 0, &[]).await;
    let app = router(s);
    let fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 b64 chars
    let post = |body: String| {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/set-fingerprint")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from(body))
        .unwrap()
    };

    let resp = app
        .clone()
        .oneshot(post(format!("mode=manual&fingerprint={fp}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let count = |entries: &[vpnctl_inventory::AuditEntry]| {
        entries
            .iter()
            .filter(|e| e.action == "server.fingerprint.set")
            .count()
    };
    assert_eq!(count(&inv.recent_audit(20).await.unwrap()), 1);

    // Same-value re-pin → no second row.
    app.clone()
        .oneshot(post(format!("mode=manual&fingerprint={fp}")))
        .await
        .unwrap();
    assert_eq!(
        count(&inv.recent_audit(20).await.unwrap()),
        1,
        "same-value re-pin must not write an audit row (NM-10)"
    );

    // Junk shape → 400.
    let resp = app
        .oneshot(post("mode=manual&fingerprint=not-a-fingerprint".into()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// POST reserved-ports: valid list 303s; junk 400s (form-parsing layer
/// — the query layer is covered by spec_reserved_ports.rs).
#[tokio::test]
async fn admin_reserved_ports_post_validates() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let post = |body: &str| {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/reserved-ports")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from(body.to_string()))
        .unwrap()
    };
    let resp = app.clone().oneshot(post("ports=443%2C8443")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let resp = app.oneshot(post("ports=not-a-port")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// POST settings/timezone: valid IANA name accepted, junk 400s.
#[tokio::test]
async fn admin_timezone_post_validates() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);
    let post = |body: &str| {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/timezone")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from(body.to_string()))
        .unwrap()
    };
    let resp = app
        .clone()
        .oneshot(post("tz=Europe%2FMoscow"))
        .await
        .unwrap();
    assert!(
        resp.status().is_redirection() || resp.status().is_success(),
        "valid IANA tz must be accepted, got {}",
        resp.status()
    );
    let resp = app.oneshot(post("tz=Not%2FAZone")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// POST auto-suppress + display-name: the HTTP/form layer round-trips
/// (until now only the inventory queries were tested).
#[tokio::test]
async fn admin_auto_suppress_and_display_name_post_roundtrip() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/auto-suppress")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("enabled=true"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/display-name")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("display_name=Frankfurt+Box"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let html = fetch_html(app, "/admin/servers/s0/setup").await;
    assert!(
        html.contains("Frankfurt Box"),
        "display name must round-trip to the detail page"
    );
}

#[tokio::test]
async fn settings_telegram_section_renders_with_disabled_status_by_default() {
    // Phase G chunk 3 part 1 — fresh DB, Telegram section appears
    // with «disabled» status + the input form.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(
        html.contains("Notifications — Telegram bot"),
        "Telegram section eyebrow must render"
    );
    assert!(
        html.contains("Status:") && html.contains("disabled"),
        "fresh config must show disabled status"
    );
    assert!(
        html.contains(r#"name="telegram_bot_token""#),
        "form must include token input"
    );
    assert!(
        html.contains(r#"name="telegram_chat_id""#),
        "form must include chat_id input"
    );
    assert!(
        html.contains(r#"action="/admin/settings/telegram""#),
        "form must POST to the correct route"
    );
    assert!(
        html.contains("@BotFather"),
        "deck copy must point operator at BotFather for bot creation"
    );
}

#[tokio::test]
async fn settings_telegram_save_roundtrip_masks_token_on_render() {
    // POST a valid config, GET the page back, assert:
    //   * status shows «enabled»
    //   * token rendered as ••••<last4>, NOT verbatim
    //   * chat_id rendered verbatim (operator wants to see it)
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let body = "telegram_bot_token=1234567890%3AABCDEFghijklmn&telegram_chat_id=987654321";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    // POST-redirect-GET pattern; expect 303 See Other.
    assert!(
        resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::OK,
        "expected redirect or OK after POST, got {}",
        resp.status()
    );

    // GET back the settings page.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(html.contains("enabled"), "status must flip to enabled");
    // Token VERBATIM must NOT appear — last 4 only.
    assert!(
        !html.contains("1234567890:ABCDEFghijklmn"),
        "verbatim token must NOT appear in rendered HTML — security"
    );
    assert!(
        html.contains("klmn"),
        "last 4 chars of token must appear (••••klmn rendering)"
    );
    // chat_id IS shown verbatim.
    assert!(
        html.contains("987654321"),
        "chat_id must appear in rendered HTML"
    );
}

#[tokio::test]
async fn settings_telegram_post_rejects_malformed_token() {
    // Shape gate at the handler: bot token must contain `:` and be
    // at least ~20 chars.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let body = "telegram_bot_token=tooshort&telegram_chat_id=123";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "malformed token must 400"
    );
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        text.contains("@BotFather"),
        "error body must point operator at BotFather"
    );
}

#[tokio::test]
async fn settings_telegram_post_rejects_garbage_chat_id() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let body =
        "telegram_bot_token=1234567890%3AABCDEFghijklmn&telegram_chat_id=not%20a%20chat%20id";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "garbage chat_id must 400"
    );
}

#[tokio::test]
async fn settings_telegram_proxy_dropdown_lists_inventory_servers() {
    // Phase G chunk 3.5 — when servers exist in inventory, the
    // «egress» dropdown must list them as «via server: <id> (<addr>)»
    // options. Pavel's specific use case: РФ blocks api.telegram.org
    // from the daemon host but a VPN server can reach it.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    inv.add_server(&vpnctl_core::Server {
        id: vpnctl_core::ServerId("vps-de1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
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
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(
        html.contains(r#"name="proxy_via_server_id""#),
        "dropdown must be named proxy_via_server_id"
    );
    assert!(
        html.contains("direct (local network)"),
        "must include the 'direct' default option"
    );
    assert!(
        html.contains("via server: vps-de1 (203.0.113.7)"),
        "must include each inventory server as a via-option"
    );
}

#[tokio::test]
async fn settings_telegram_proxy_dropdown_shows_hint_when_no_servers() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("direct (local network)"));
    assert!(
        html.contains("No servers in inventory yet"),
        "must include the explanatory hint when inventory is empty"
    );
    assert!(
        !html.contains("via server:"),
        "no via-options when inventory empty"
    );
}

#[tokio::test]
async fn settings_telegram_save_persists_proxy_via_server_id() {
    // POST with proxy_via_server_id selected → next GET shows the
    // option pre-selected. Round-trips the new column through both
    // handlers + the inventory layer.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    inv.add_server(&vpnctl_core::Server {
        id: vpnctl_core::ServerId("vps-de1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();

    let app = router(st);
    let body = "telegram_bot_token=1234567890%3AABCDEFghijklmn\
                &telegram_chat_id=987654321\
                &proxy_via_server_id=vps-de1";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    app.clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        html.contains(r#"<option value="vps-de1" selected"#)
            || html.contains(r#"<option selected value="vps-de1""#),
        "vps-de1 option must be marked selected after save"
    );
}

#[tokio::test]
async fn settings_telegram_test_send_button_appears_only_when_enabled() {
    // Phase G chunk 3 part 2 — the «send test message» button must
    // appear ONLY when the transport is enabled. Disabled / partial
    // / error states show an explanatory hint instead.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();

    let app = router(st.clone());

    // Default state: no config → no button.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("send test message"),
        "button must NOT appear when transport disabled"
    );
    assert!(
        html.contains("Test-send button appears after both fields are saved"),
        "explanatory hint must appear instead"
    );

    // Enable and re-render.
    inv.set_telegram_config(Some("1234567890:ABCDEFghijklmn"), Some("987654321"), None)
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("send test message"),
        "button must appear when transport enabled"
    );
    assert!(
        html.contains(r#"action="/admin/settings/telegram/test""#),
        "button must POST to test route"
    );
}

#[tokio::test]
async fn settings_telegram_test_send_when_disabled_returns_400() {
    // POST to test endpoint with no config set → 400, NOT 502 (502
    // is for «config is set but Telegram rejected us»; 400 is for
    // «no config to test»).
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram/test");
    req = add_same_origin(req);
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "no config → 400, not 500/502"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("not configured") && text.contains("fill in both fields"),
        "must explain the missing-config state"
    );
}

#[tokio::test]
async fn settings_telegram_partial_config_renders_red_warning() {
    // Phase G chunk 3 part 1 — when only one half is set (token OR
    // chat_id but not both), the status line MUST surface this as
    // a red «partial config» banner rather than collapsing into
    // the bland «disabled» state. Catches the «I pasted only the
    // token and walked away» mistake.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    // Set only the token; chat_id stays NULL.
    inv.set_telegram_config(Some("1234567890:ABCDEFghijklmn"), None, None)
        .await
        .unwrap();

    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("partial config"),
        "stranded half must surface as 'partial config'"
    );
    assert!(
        html.contains("chat-id missing"),
        "must name which half is missing"
    );
    // Token NOT visible verbatim even in this state.
    assert!(
        !html.contains("1234567890:ABCDEFghijklmn"),
        "verbatim token must NOT leak even in partial-config state"
    );
}

#[tokio::test]
async fn settings_telegram_clear_both_disables_transport() {
    // Save valid config, then post two empty inputs → status flips
    // back to «disabled».
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    // Enable.
    let body = "telegram_bot_token=1234567890%3AABCDEFghijklmn&telegram_chat_id=987654321";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    app.clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();

    // Clear.
    let body = "telegram_bot_token=&telegram_chat_id=";
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/settings/telegram")
        .header("content-type", "application/x-www-form-urlencoded");
    req = add_same_origin(req);
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert!(resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::OK);

    // GET back, expect disabled.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/settings/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("disabled"),
        "clearing both inputs must disable the transport"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Phase C-4 — Settings backups section + manual snapshot trigger +
// per-file download. The hourly scheduler is unit-tested in
// `crates/inventory/src/backup.rs`; these tests pin the WEB surface.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_settings_shows_backups_section_with_snapshot_button() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/settings/backups").await;
    assert!(
        html.contains("Backups — inventory snapshots"),
        "Settings page must have a Backups section heading"
    );
    assert!(
        html.contains("action=\"/admin/backup/snapshot\""),
        "Settings must include the manual snapshot POST form"
    );
    assert!(
        html.contains(">snapshot now<"),
        "Settings must include the 'snapshot now' button"
    );
    // Operator-facing copy: explain the off-site model + restore
    // procedure. Catch regressions if someone reverts the
    // operator-driven design.
    assert!(
        html.contains("Off-site is operator-driven"),
        "Settings must explain the operator-driven off-site model"
    );
    assert!(
        html.contains("restore"),
        "Settings must mention the restore procedure"
    );
}

#[tokio::test]
async fn admin_backup_snapshot_now_posts_and_redirects_back() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s.clone());
    // Use a tempdir-scoped backup dir so the test doesn't touch
    // /var/lib/vpnctl/. The handler currently uses
    // crate::app::DEFAULT_BACKUP_DIR which points at the production
    // path — but inside `cargo test` we don't have write access there,
    // so the snapshot will fail with a 500. That's actually what we
    // want to confirm: the POST is reachable and audits even on
    // failure.
    //
    // (The successful-path is tested in the inventory crate's
    // backup::tests::snapshot_now_creates_file_and_lists.)
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/backup/snapshot"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    // Either 303 (snapshot succeeded — production root daemon) OR
    // 500 (snapshot failed — typical test env without write to
    // /var/lib/vpnctl/backups). Both are acceptable; what we're
    // asserting is the endpoint is wired + the audit path runs.
    assert!(
        matches!(
            resp.status(),
            StatusCode::SEE_OTHER | StatusCode::INTERNAL_SERVER_ERROR
        ),
        "expected 303 or 500, got {:?}",
        resp.status()
    );
    // Audit row should be present regardless (success OR failure path
    // both write `backup.snapshot`).
    let audits = s.inv.recent_audit(50).await.unwrap();
    assert!(
        audits.iter().any(|a| a.action == "backup.snapshot"),
        "manual snapshot must write an audit row even when the snapshot itself fails"
    );
}

#[tokio::test]
async fn admin_backup_download_rejects_path_traversal() {
    // Validation gate: a name with `..` or `/` MUST 400 before the
    // handler ever touches the filesystem. Otherwise an
    // unauthenticated attacker (or a misconfigured proxy) could
    // exfiltrate arbitrary files in the backup dir's neighbourhood.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    for name in [
        "../etc/passwd",
        "..%2Fetc%2Fpasswd",
        "inv.db.../../etc.bak",
        "name_with_slash/inv.db.x.bak",
        // Right prefix+suffix but wrong charset (contains '/').
        "inv.db.2026-01-01T00-00-00.000Z/bad.bak",
    ] {
        let encoded: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~') {
                    c.to_string()
                } else {
                    format!("%{:02X}", c as u8)
                }
            })
            .collect();
        let uri = format!("/admin/backup/download/{encoded}");
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::NOT_FOUND,
            "name {name:?} must be 400/404, got {:?}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn admin_backup_scheduler_produces_snapshot_and_audits() {
    // Pin the wiring: scheduler actually fires → file appears in
    // backup_dir → `backup.snapshot` audit row written with
    // `trigger: "scheduler"`. Without this test the production
    // scheduler path could regress silently (the manual handler is
    // a different code path).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let backup_dir = dir.path().join("bkp");

    // Short delays: 50ms startup, 50ms tick. Two-three ticks should
    // fire within 500ms, giving us at least one snapshot + audit
    // row. We then abort the task.
    let handle = vpnctld::spawn_backup_scheduler_with_for_test(
        inv.clone(),
        backup_dir.clone(),
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(50),
    );
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    handle.abort();

    let snapshots = vpnctl_inventory::list_snapshots(&backup_dir).unwrap();
    assert!(
        !snapshots.is_empty(),
        "scheduler must have produced at least one snapshot in 500ms; got 0"
    );
    let audits = inv.recent_audit(50).await.unwrap();
    let scheduler_rows: Vec<_> = audits
        .iter()
        .filter(|a| {
            a.action == "backup.snapshot"
                && a.payload
                    .as_ref()
                    .and_then(|p| p.get("trigger"))
                    .and_then(|v| v.as_str())
                    == Some("scheduler")
        })
        .collect();
    assert!(
        !scheduler_rows.is_empty(),
        "scheduler must write at least one audit row with trigger=scheduler"
    );
}

#[tokio::test]
async fn admin_backup_download_404_on_missing_snapshot() {
    // Valid-shaped filename but file doesn't exist. The handler
    // should 404 with a canonical body — not 500.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/backup/download/inv.db.2026-01-01T00-00-00.000Z.bak")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Production-default backup dir might not even exist in tests
    // (canonicalize errors with NotFound → 500), OR it exists but
    // file is missing (404). Either keeps the operator's path
    // safe; we accept both.
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);

    assert!(
        matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::INTERNAL_SERVER_ERROR
        ),
        "missing snapshot should be 404 or 500, got {:?}",
        status
    );

    if status == StatusCode::INTERNAL_SERVER_ERROR {
        assert_eq!(
            body_str.trim(),
            "vpnctl admin: internal error — please retry the action",
            "500 response body must not leak internal filesystem paths or details"
        );
    }
}

#[tokio::test]
async fn track_1_3_settings_geoip_section_shows_missing_state_by_default() {
    // The fresh-test harness doesn't drop MMDB files, so the
    // section should report both DBs as «missing» and surface
    // the web «update now» button.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/settings/system").await;
    assert!(
        html.contains("GeoIP — IP enrichment"),
        "Settings page must include the GeoIP eyebrow"
    );
    assert!(
        html.contains("update now"),
        "missing-DB branch must mention the web update button"
    );
    assert!(
        html.contains("(missing — use the") || html.contains("(отсутствует — нажми"),
        "expected the 'missing' empty-state for both City + ASN"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase 3c — Settings GeoIP «update now» SSE button.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase3c_settings_renders_geoip_update_now_button_and_eventsource_wiring() {
    // Pin the Settings page: the «update now» button + live-log <pre>
    // render, wired CSP-SAFE through admin.js's `[data-sse-url]`
    // trigger. Audit 2026-06-10: the original inline `<script>` +
    // `onclick` were silently refused by the admin CSP (`script-src
    // 'self'`, no 'unsafe-inline') — the button did NOTHING in a real
    // browser. Pavel UI requirement stands — operator must never need
    // a terminal; `vpnctl geoip-update` must stay one click.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/settings/system").await;

    assert!(
        html.contains("id=\"geoip-update-now-btn\""),
        "Settings must surface the GeoIP «update now» button"
    );
    assert!(
        html.contains("data-sse-url=\"/admin/settings/geoip/update-now\""),
        "button must carry the data-sse-url trigger admin.js wires"
    );
    assert!(
        html.contains("data-log=\"geoip-update-now-log\""),
        "button must point at its log pane via data-log"
    );
    assert!(
        html.contains("id=\"geoip-update-now-log\""),
        "Settings must surface the live-log pane"
    );
    // CSP-regression guard: NO inline script / onclick may return —
    // they render but never execute under `script-src 'self'`.
    assert!(
        !html.contains("vpnctlGeoipUpdateNow") && !html.contains("onclick="),
        "settings must not regress to CSP-blocked inline JS"
    );
}

#[tokio::test]
async fn phase3c_geoip_update_now_sse_endpoint_returns_text_event_stream() {
    // Endpoint contract: GET /admin/settings/geoip/update-now must
    // return 200 with Content-Type: text/event-stream. The runner
    // will spawn `/usr/local/bin/vpnctl geoip-update` which usually
    // won't exist in the test container — that's fine, the runner
    // emits a terminal Error event and the stream closes. We just
    // pin the HTTP wire contract here. NOTE: we deliberately don't
    // override the bin path via env var — `std::env::set_var` is
    // `unsafe` in Rust 2024 + workspace forbids unsafe; the wire
    // contract (200 + text/event-stream) is identical regardless
    // of whether the spawn succeeds.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    let resp = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/settings/geoip/update-now")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "SSE source must return Content-Type: text/event-stream, got {ct:?}"
    );
}

#[tokio::test]
async fn phase3c_geoip_update_now_fire_writes_audit_row() {
    // Hitting the SSE endpoint must write an audit row with the
    // canonical dot-separated action name. The audit row is the
    // operator's after-the-fact «what happened» record — without
    // it, a misbehaving subprocess vanishes without a trace beyond
    // journalctl.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();

    let _ = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/settings/geoip/update-now")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Audit row is written BEFORE the subprocess spawn (so even a
    // spawn failure is logged). The connection close before the
    // subprocess finishes doesn't lose the audit row.
    let rows = inv.recent_audit(20).await.unwrap();
    assert!(
        rows.iter()
            .any(|r| r.action == "settings.geoip.update_now.fired"),
        "expected audit row settings.geoip.update_now.fired, got {:?}",
        rows.iter().map(|r| &r.action).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn phase3c_geoip_update_now_rejects_cross_site_sec_fetch() {
    // CSRF defense — a hostile page that embeds
    //   <img src="http://192.168.0.236:18402/admin/settings/geoip/update-now">
    // causes the browser to GET our endpoint with
    //   Sec-Fetch-Site: cross-site
    // Without this gate the audit row + subprocess would fire just
    // from the operator visiting the attacker's page (basic-auth
    // is sent automatically by the browser). With the gate, we 403
    // BEFORE the audit or spawn — neither side-effect occurs.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();

    let resp = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/settings/geoip/update-now")
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.starts_with("vpnctl admin: "),
        "403 must carry the unified prefix, got: {body}"
    );
    // No audit row may exist — the gate refused BEFORE the audit.
    let rows = inv.recent_audit(20).await.unwrap();
    assert!(
        !rows
            .iter()
            .any(|r| r.action == "settings.geoip.update_now.fired"),
        "audit row must NOT be written when the CSRF gate rejects"
    );
}

#[tokio::test]
async fn phase3c_geoip_update_now_accepts_same_origin_sec_fetch() {
    // Symmetric to the cross-site test — the legitimate EventSource
    // attach from /admin/settings sends Sec-Fetch-Site: same-origin.
    // That MUST succeed (200 + text/event-stream).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    let resp = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/settings/geoip/update-now")
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn phase3c_settings_page_carries_no_inline_script_blocks() {
    // CSP contract (2026-06-10, supersedes the old json_for_script XSS
    // pin): the admin CSP is `script-src 'self'` with NO
    // 'unsafe-inline', so ANY inline `<script>…</script>` body on the
    // page renders but never executes — exactly how the GeoIP button
    // sat dead for weeks. Pin: the ONLY <script> on Settings is the
    // external admin.js include from the shell; everything interactive
    // must ride data-attributes.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let html = fetch_html(router(s), "/admin/settings").await;

    let script_tags = html.matches("<script").count();
    assert_eq!(
        script_tags, 1,
        "settings must carry exactly the shell's external admin.js <script>, found {script_tags}"
    );
    assert!(
        html.contains("src=\"/admin/assets/admin.js\""),
        "the single script tag must be the external admin.js include"
    );
}

// ════════════════════════════════════════════════════════════════════
//  POST notification-language / digest-now / backup/self-test gates
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn settings_notification_language_method_and_csrf_gates() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    // 1. GET method is rejected with 405 Method Not Allowed
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/settings/notification-language")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "GET on POST-only notification-language endpoint must 405"
    );

    // 2. POST without Origin header is rejected with 403 Forbidden
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/notification-language")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("language=ru"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "POST without Origin must be rejected by CSRF middleware"
    );
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        body_str.starts_with("vpnctl admin: csrf"),
        "CSRF reject body must use unified prefix: {body_str}"
    );

    // 3. POST with cross-origin Origin is rejected with 403 Forbidden
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/notification-language")
                .header("host", "127.0.0.1:3080")
                .header("origin", "http://evil.com")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("language=ru"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Cross-origin POST must be rejected by CSRF middleware"
    );

    // Rejections must not write audit rows or alter state
    let audits = inv.recent_audit(20).await.unwrap();
    assert!(
        audits.is_empty(),
        "CSRF rejection must write zero audit records"
    );
    let cfg = inv.get_telegram_config().await.unwrap().unwrap();
    assert_eq!(
        cfg.language, None,
        "CSRF rejection must not modify notification language in DB"
    );
}

#[tokio::test]
async fn settings_notification_language_valid_values_persist_state_and_audit() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    // 1. Valid language "ru" -> 303 Redirect to /admin/settings/notifications
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/settings/notification-language")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("language=ru"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "Valid notification language update must redirect 303"
    );
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/admin/settings/notifications"),
        "Redirect location must be /admin/settings/notifications"
    );

    // State check in DB
    let cfg = inv.get_telegram_config().await.unwrap().unwrap();
    assert_eq!(
        cfg.language.as_deref(),
        Some("ru"),
        "Notification language in DB must be updated to 'ru'"
    );

    // Audit check
    let audits = inv.recent_audit(20).await.unwrap();
    let audit = audits
        .iter()
        .find(|a| a.action == "settings.notification.language")
        .expect("must write settings.notification.language audit entry");
    assert_eq!(audit.actor, "admin");
    assert_eq!(
        audit.payload,
        Some(serde_json::json!({ "language": "ru" })),
        "audit payload must record the updated language"
    );

    // 2. Valid language "en" -> 303 Redirect and DB updated
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/settings/notification-language")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("language=en"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let cfg = inv.get_telegram_config().await.unwrap().unwrap();
    assert_eq!(
        cfg.language.as_deref(),
        Some("en"),
        "Notification language in DB must be updated to 'en'"
    );

    let audits = inv.recent_audit(20).await.unwrap();
    let count = audits
        .iter()
        .filter(|a| a.action == "settings.notification.language")
        .count();
    assert_eq!(
        count, 2,
        "Second language update must write second audit row"
    );
}

#[tokio::test]
async fn settings_notification_language_invalid_values_return_400_and_leave_state_unchanged() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    let invalid_bodies = [
        "language=de",
        "language=fr",
        "language=",
        "other_field=ru",
        "language=RU",
    ];

    for body in invalid_bodies {
        let resp = app
            .clone()
            .oneshot(
                add_same_origin(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/settings/notification-language")
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
            "Invalid body {body:?} must be rejected with 400 Bad Request"
        );
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(
            body_str.contains("notification language must be 'ru' or 'en'"),
            "Error body for {body:?} must explain valid language options: {body_str}"
        );
    }

    // State in DB remains unconfigured (None)
    let cfg = inv.get_telegram_config().await.unwrap().unwrap();
    assert_eq!(
        cfg.language, None,
        "Invalid requests must not modify notification language"
    );

    // No audit rows written
    let audits = inv.recent_audit(20).await.unwrap();
    assert!(
        audits.is_empty(),
        "Rejected invalid requests must not write audit rows"
    );
}

#[tokio::test]
async fn settings_digest_now_method_and_csrf_gates() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    // 1. GET method is rejected with 405 Method Not Allowed
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/settings/digest-now")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "GET on POST-only digest-now endpoint must 405"
    );

    // 2. POST without Origin header is rejected with 403 Forbidden
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/digest-now")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "POST without Origin must be rejected by CSRF middleware"
    );
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        body_str.starts_with("vpnctl admin: csrf"),
        "CSRF reject body must use unified prefix: {body_str}"
    );

    // 3. POST with cross-origin Origin is rejected with 403 Forbidden
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/digest-now")
                .header("host", "127.0.0.1:3080")
                .header("origin", "http://attacker.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Cross-origin POST must be rejected by CSRF middleware"
    );

    let audits = inv.recent_audit(20).await.unwrap();
    assert!(
        audits.is_empty(),
        "CSRF rejection must write zero audit records"
    );
}

#[tokio::test]
async fn settings_digest_now_fires_audits_and_redirects_to_anchor() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    // Trigger digest-now on demand
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/settings/digest-now"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "digest-now must return 303 See Other"
    );
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/admin/settings/notifications#telegram-notifications"),
        "digest-now must redirect back to telegram notifications section anchor"
    );

    let audits = inv.recent_audit(20).await.unwrap();
    let audit = audits
        .iter()
        .find(|a| a.action == "settings.digest.send")
        .expect("must write settings.digest.send audit entry");
    assert_eq!(audit.actor, "admin");

    // Second invocation writes a second audit entry
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/settings/digest-now"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let audits = inv.recent_audit(20).await.unwrap();
    let count = audits
        .iter()
        .filter(|a| a.action == "settings.digest.send")
        .count();
    assert_eq!(
        count, 2,
        "Second digest-now trigger must write second audit row"
    );
}

#[tokio::test]
async fn backup_self_test_method_and_csrf_gates() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    // 1. GET method is rejected with 405 Method Not Allowed
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/backup/self-test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "GET on POST-only backup/self-test endpoint must 405"
    );

    // 2. POST without Origin header is rejected with 403 Forbidden
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup/self-test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "POST without Origin must be rejected by CSRF middleware"
    );
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        body_str.starts_with("vpnctl admin: csrf"),
        "CSRF reject body must use unified prefix: {body_str}"
    );

    // 3. POST with cross-origin Origin is rejected with 403 Forbidden
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/backup/self-test")
                .header("host", "127.0.0.1:3080")
                .header("origin", "http://malicious-site.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Cross-origin POST must be rejected by CSRF middleware"
    );

    let audits = inv.recent_audit(20).await.unwrap();
    assert!(
        audits.is_empty(),
        "CSRF rejection must write zero audit records"
    );
}
