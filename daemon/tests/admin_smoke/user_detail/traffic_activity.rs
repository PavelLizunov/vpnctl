use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{ServerId, User, UserId};
use vpnctl_inventory::VpnStatsDelta;
use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn admin_user_detail_track1_empty_state_renders_nudge() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let app = router(s);

    let html = fetch_html(app, "/admin/users/u0/activity").await;
    assert!(
        html.contains("Sub-access log"),
        "v2 geo-log eyebrow missing"
    );
    assert!(
        html.contains("no real-client fetches in 30d"),
        "no-data verdict note missing on a fresh user"
    );
    assert!(
        html.contains("sharing verdict"),
        "verdict tile must render from day 1"
    );
}

#[tokio::test]
async fn admin_user_detail_track1_renders_counters_and_recent_table() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;

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
    let html = fetch_html(app, "/admin/users/u0/activity").await;

    assert!(html.contains(">2<"), "distinct-IP counter 2 missing");
    assert!(html.contains(">3<"), "recent-fetches counter 3 missing");

    assert!(
        html.contains("192.0.2.10") && html.contains("198.51.100.42"),
        "recent table missing one of the logged IPs"
    );
    assert!(html.contains("Hiddify/Android/2.5.0"));
    assert!(html.contains("sing-box/1.10.0"));
    assert!(html.contains(">200<"));
    assert!(
        !html.contains("No subscription fetches recorded yet"),
        "empty-state nudge leaked into populated render"
    );
    assert!(
        !html.contains("abuse signal"),
        "heat flag fired below threshold ({} distinct IPs)",
        2
    );
}

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

    let html = fetch_html(router(s), "/admin/users/u1/activity").await;
    assert!(
        html.contains("no real-client fetches in 30d"),
        "u1 should show the no-data verdict note"
    );
    assert!(
        !html.contains("10.10.10.10"),
        "leaked u0's IP onto u1's detail page"
    );
    assert!(
        !html.contains("UA-FOR-U0"),
        "leaked u0's UA onto u1's detail page"
    );
}

#[tokio::test]
async fn admin_user_detail_track4_ua_section_hidden_when_empty() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
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

    let html = fetch_html(router(s), "/admin/users/u0/activity").await;

    assert!(
        html.contains("UA fingerprint"),
        "UA section headline missing"
    );
    assert!(
        html.contains("Heuristic"),
        "UA section deck must caveat the verdict"
    );
    assert!(
        html.contains("likely shared URL"),
        "expected 'likely shared URL' verdict; html (truncated): {}",
        &html[..html.len().min(800)]
    );
    assert!(html.contains("Hiddify/Android/2.5.0"));
    assert!(
        html.matches(">3<").count() >= 3,
        "expected at least 3 columns rendering '3' (hits/ips/slash16); got {}",
        html.matches(">3<").count()
    );
}

#[tokio::test]
async fn admin_user_detail_track4_ua_section_detects_roaming() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    for ip in ["192.0.2.10", "192.0.2.11", "192.0.2.12"] {
        s.inv
            .log_sub_access(&UserId("u0".into()), ip, Some("sing-box/1.10.0"), 200, 100)
            .await
            .unwrap();
    }

    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(
        html.contains("likely roaming"),
        "expected 'likely roaming' verdict for 3 IPs in 1 /16; html (truncated): {}",
        &html[..html.len().min(800)]
    );
    assert!(
        !html.contains("likely shared URL"),
        "roaming pattern should not trip the shared-URL verdict"
    );
}

#[tokio::test]
async fn admin_user_detail_track3_empty_state_quotes_chunk4_status() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let html = fetch_html(router(s), "/admin/users/u0/traffic").await;
    assert!(
        html.contains("Live VPN stats"),
        "section headline must appear even in empty state"
    );
    assert!(
        html.contains("No live stats yet"),
        "empty-state nudge missing"
    );
    assert!(
        html.contains("every 5 minutes"),
        "empty-state must state the live poller cadence"
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
    seed(&s.inv, 2, 1, &[]).await;

    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[
                VpnStatsDelta {
                    user_id: Some(UserId("u0".into())),
                    upload_bytes: 1_000_000,
                    download_bytes: 5_000_000,
                    active_connections: 3,
                },
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

    let html = fetch_html(router(s), "/admin/users/u0/traffic").await;

    assert!(html.contains("uploaded"), "uploaded KPI label missing");
    assert!(html.contains("downloaded"), "downloaded KPI label missing");
    assert!(html.contains("peak conns"), "peak conns KPI label missing");
    assert!(html.contains("s0"), "server s0 row missing");
    assert!(html.contains("s1"), "server s1 row missing");
    assert!(
        !html.contains("99.9 MiB") && !html.contains("99,999,999"),
        "server-wide row must not leak into per-user view"
    );
    assert!(
        !html.contains("No live stats yet"),
        "empty-state copy leaked into populated render"
    );
    assert!(
        html.contains("Aggregated from 2 snapshots"),
        "snapshot count footer missing or wrong"
    );
}

#[tokio::test]
async fn admin_user_detail_track3_does_not_leak_other_users_stats() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 2, &[]).await;

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

    let html = fetch_html(router(s), "/admin/users/u1/traffic").await;
    assert!(
        html.contains("No live stats yet"),
        "u1 must show empty state when only u0 has data"
    );
}

#[tokio::test]
async fn admin_user_detail_shows_traffic_limit_section() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "uuid-a".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/users/alice/overview").await;
    assert!(html.contains("Traffic limit"), "section heading missing");
    assert!(
        html.contains(r#"action="/admin/users/alice/traffic-limit""#),
        "form action missing"
    );
    assert!(
        html.contains(r#"name="limit_gib""#),
        "limit_gib input missing"
    );
    assert!(
        html.contains(r#"name="threshold_pct""#),
        "threshold_pct input missing"
    );
}

#[tokio::test]
async fn admin_user_set_traffic_limit_persists_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "uuid-a".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/alice/traffic-limit")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("limit_gib=5.0&threshold_pct=75"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let (lim, thr) = inv
        .get_user_traffic_limit(&UserId("alice".into()))
        .await
        .unwrap();
    assert_eq!(lim, Some(5_368_709_120));
    assert_eq!(thr, Some(75));
    let audit = inv.recent_audit(5).await.unwrap();
    let row = audit
        .iter()
        .find(|a| a.action == "user.traffic_limit.set")
        .expect("audit row");
    let payload = row
        .payload
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_default();
    assert!(payload.contains("75"));
    assert!(payload.contains("5368709120"));
}

#[tokio::test]
async fn admin_user_set_traffic_limit_zero_clears_cap() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "uuid-a".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    inv.set_user_traffic_limit(&UserId("alice".into()), Some(10_737_418_240), Some(80))
        .await
        .unwrap();
    let app = router(s);
    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/users/alice/traffic-limit")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from("limit_gib=0&threshold_pct=80"))
        .unwrap(),
    )
    .await
    .unwrap();
    let (lim, _) = inv
        .get_user_traffic_limit(&UserId("alice".into()))
        .await
        .unwrap();
    assert!(lim.is_none(), "limit must be NULL after limit_gib=0");
}

#[tokio::test]
async fn tooltips_user_detail_traffic_limit_fields_explain_units() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("tip".into()),
            uuid: "00000000-0000-0000-0000-000000000020".to_string(),
            sub_token: Some("ttip".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/tip/overview").await;
    assert!(
        html.contains("Monthly cap in GiB"),
        "limit_gib input must explain unit + 0=no cap semantic"
    );
    assert!(
        html.contains("Fire a dashboard alert"),
        "threshold_pct input must explain alert semantic"
    );
}

#[tokio::test]
async fn track_1_2_geo_log_renders_country_and_asn() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&User {
        id: UserId("zoidberg".into()),
        uuid: "z0".into(),
        sub_token: Some("ztok".into()),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();

    inv.log_sub_access_rich(
        &UserId("zoidberg".into()),
        "8.8.8.8",
        Some("Hiddify/Android/2.5.0"),
        200,
        4096,
        Some("ru-RU,ru;q=0.9"),
        Some("HTTP/2.0"),
        Some("Hiddify"),
        Some("US"),
        Some("AS15169 GOOGLE"),
        None,
        None,
    )
    .await
    .unwrap();

    let html = fetch_html(router(s), "/admin/users/zoidberg/activity").await;
    assert!(html.contains("8.8.8.8"), "raw IP must render");
    assert!(
        html.contains(">US<"),
        "geo_country chip 'US' must render alongside the IP"
    );
    assert!(
        html.contains("AS15169 GOOGLE"),
        "geo_asn chip 'AS15169 GOOGLE' must render"
    );
    assert!(
        html.contains("Hiddify/Android/2.5.0"),
        "raw UA must render in the UA column"
    );
}

#[tokio::test]
async fn track_1_2_subscription_access_legacy_row_renders_bare_ip() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&User {
        id: UserId("nibbler".into()),
        uuid: "n0".into(),
        sub_token: Some("ntok".into()),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.log_sub_access(&UserId("nibbler".into()), "1.2.3.4", None, 200, 0)
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users/nibbler/activity").await;
    assert!(html.contains("1.2.3.4"), "raw IP must render");
    assert!(
        !html.contains(r#"border: 1px solid var(--acc-good, #2c5f2d); color: var(--acc-good, #2c5f2d); margin-left: 2px;" title="Country"#),
        "no country chip when geo_country is None — currently no such substring"
    );
}

#[tokio::test]
async fn track_1_4_subscription_access_omits_ja_chips_when_null() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_user(&User {
        id: UserId("bender".into()),
        uuid: "be0".into(),
        sub_token: Some("betok".into()),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.log_sub_access(&UserId("bender".into()), "1.2.3.4", None, 200, 0)
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/bender/activity").await;
    assert!(
        !html.contains("JA3 ") && !html.contains("JA4 "),
        "JA chips must not render when columns are NULL"
    );
}

#[tokio::test]
async fn pr_user_traffic_by_server_renders_per_server_rows() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 3_000_000,
                download_bytes: 9_000_000,
                active_connections: 2,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0/traffic").await;
    assert!(
        html.contains("Live VPN stats"),
        "live-stats eyebrow missing"
    );
    assert!(html.contains("peak conns"), "peak-conns column missing");
    assert!(html.contains("total"), "total column missing (R2)");
    assert!(html.contains("s0"), "per-server row for s0 missing");
    assert!(
        html.contains("11.4 MiB"),
        "total column must humanize up+down (3 MB + 9 MB)"
    );
}

#[tokio::test]
async fn pr_user_quota_renders_progress_and_projection_with_limit() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .set_user_traffic_limit(&UserId("u0".into()), Some(5_368_709_120), Some(80))
        .await
        .unwrap();
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 500_000_000,
                download_bytes: 500_000_000,
                active_connections: 1,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(
        html.contains("Traffic limit"),
        "traffic-limit eyebrow missing"
    );
    assert!(
        html.contains("5 GiB") || html.contains("5.0 GiB"),
        "progress bar must show the configured cap"
    );
    assert!(
        html.contains("projected"),
        "month-end projection line missing when a cap is set"
    );
    assert!(
        html.contains("by month-end"),
        "projection copy contract drifted"
    );
}

#[tokio::test]
async fn pr_user_quota_no_limit_shows_form_no_projection() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/users/u0").await;
    assert!(
        html.contains("Traffic limit"),
        "traffic-limit eyebrow missing"
    );
    assert!(
        html.contains(r#"name="limit_gib""#),
        "limit form must still render with no cap"
    );
    assert!(
        !html.contains("by month-end"),
        "projection must not render when no cap is set"
    );
}

#[tokio::test]
async fn pr_user_live_stats_folds_in_user_scoped_window_picker() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 1_000_000,
                download_bytes: 2_000_000,
                active_connections: 1,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0/traffic").await;
    assert!(
        html.contains("/admin/users/u0/traffic?vpn_window=7d"),
        "window picker must offer a 7d link scoped to this user"
    );
    assert!(
        html.contains("/admin/users/u0/traffic?vpn_window=30d"),
        "window picker must offer a 30d link scoped to this user"
    );
    assert!(
        html.contains("traffic trend · "),
        "folded sparkline trend heading missing"
    );
}

#[tokio::test]
async fn pr_user_ua_section_carries_geo_and_last_seen_footer() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .log_sub_access_rich(
            &UserId("u0".into()),
            "192.0.2.10",
            Some("Hiddify/Android/2.5.0"),
            200,
            100,
            None,
            None,
            None,
            Some("US"),
            Some("AS111 Alpha"),
            None,
            None,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(
        html.contains("UA fingerprint"),
        "UA section must render with /sub history"
    );
    assert!(
        html.contains("countries · 30d"),
        "UA geo footer (countries) missing"
    );
    assert!(html.contains("ASNs · 30d"), "UA geo footer (ASNs) missing");
    assert!(html.contains("last seen "), "UA last-seen footer missing");
}

#[tokio::test]
async fn v2_user_activity_renders_tiles_and_geo_log() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .log_sub_access(
            &UserId("u0".into()),
            "5.5.5.5",
            Some("Hiddify/2.5 android"),
            200,
            500,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/u0/activity").await;
    assert!(html.contains("sharing verdict"), "verdict tile missing");
    assert!(
        html.contains("client IPs · 30d") && html.contains("sub fetches · 30d"),
        "count tiles missing"
    );
    assert!(
        html.contains(
            "includes proxy-masked and VPN-egress fetches the «client IPs» tile excludes"
        ) || html.contains(
            "включая proxy-masked и VPN-egress обращения, которые плитка «клиентских IP» исключает"
        ),
        "log scope caption missing"
    );
    assert!(
        html.contains("Sub-access log · GeoIP-resolved"),
        "geo log eyebrow missing"
    );
    assert!(html.contains("5.5.5.5"), "fetch row IP missing");
    assert!(html.contains("Hiddify/2.5 android"), "fetch row UA missing");
}

#[tokio::test]
async fn v2_user_activity_log_pagination_and_csv() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    for i in 0..30 {
        s.inv
            .log_sub_access(
                &UserId("u0".into()),
                &format!("5.5.5.{i}"),
                Some("Hiddify"),
                200,
                100,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(s.clone()), "/admin/users/u0/activity").await;
    assert!(
        html.contains("showing ") && html.contains(" of "),
        "log must show the «showing N of M» counter"
    );
    let link = html
        .split_once(r#"href="/admin/users/u0/activity?log_page=1""#)
        .unwrap()
        .1
        .split_once("</a>")
        .unwrap()
        .0;
    let content = link.split_once('>').unwrap().1;
    assert_eq!(
        content.split_once("<svg ").unwrap().0.trim(),
        "older",
        "page 1 of 2 must offer the exact older label"
    );
    assert!(
        content.contains(r#"<use href="/admin/assets/icons.svg#arrow-right""#),
        "older-page link must carry its own arrow icon"
    );
    assert!(
        html.contains("/admin/users/u0/access.csv"),
        "log must offer a CSV export link"
    );
    let resp = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/users/u0/access.csv")
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
    assert!(ct.contains("text/csv"), "CSV must be text/csv, got {ct}");
    let cc = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        cc, "no-store",
        "Cache-Control must be no-store for access CSV export, got {cc:?}"
    );
    let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let csv = std::str::from_utf8(&body).unwrap();
    assert!(
        csv.starts_with("ts,ip,country,asn,user_agent,status,is_vpn_egress"),
        "CSV header drifted"
    );
    assert_eq!(csv.lines().count(), 31, "header + 30 data rows");
}
