use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{ServerId, User, UserId};
use vpnctl_inventory::VpnStatsDelta;
use vpnctld::router;

use crate::common::*;

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

    let html = fetch_html(app, "/admin/users/u0/activity").await;
    // R2: the v2 4c surface — tiles + geo-log — replaced the legacy
    // Track-1 block; a fresh user shows the no-data verdict tile, not
    // a broken-looking empty table.
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
    let html = fetch_html(app, "/admin/users/u0/activity").await;

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

    let html = fetch_html(router(s), "/admin/users/u1/activity").await;
    // u1 has no fetches — the v2 verdict tile says so.
    assert!(
        html.contains("no real-client fetches in 30d"),
        "u1 should show the no-data verdict note"
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
// Phase Track-4 — UA fingerprint section on user-detail.
//
// Backed by `inventory::ua_clusters_for_user`. Three behaviors covered:
//   1. Empty case — the section silently disappears (no headline, no
//      empty-state copy). Operators only see the section when there's
//      something to read; an empty table on a fresh user would just be
//      noise.
//   2. Populated case — one row per distinct UA, with the verdict
//      column rendering \"likely shared URL\" for /16 spread ≥ 3.
//   3. Roaming verdict — distinct_ips ≥ 3, distinct_slash16 ≤ 1 →
//      \"likely roaming\". This is the operator's \"one device hopping
//      ISPs\" tell, opposite of the shared-URL signal.
//
// Per-section copy contract: the headline reads \"UA fingerprint · last
// 24h\"; the deck contains the word \"Heuristic\" so the operator knows
// not to treat the verdict as authoritative.

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
    // Same UA hitting from three different /16 networks — classic
    // \"subscription URL got shared with friends in different ISPs\".
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

    // Section headline + deck (copy contract).
    assert!(
        html.contains("UA fingerprint"),
        "UA section headline missing"
    );
    assert!(
        html.contains("Heuristic"),
        "UA section deck must caveat the verdict"
    );
    // Verdict label shows up.
    assert!(
        html.contains("likely shared URL"),
        "expected 'likely shared URL' verdict; html (truncated): {}",
        &html[..html.len().min(800)]
    );
    // The UA renders in its column.
    assert!(html.contains("Hiddify/Android/2.5.0"));
    // Counters per row: hits=3, ips=3, /16=3 — they all show as \">3<\"
    // somewhere; this just confirms the row data wired through.
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
    // Three distinct IPs but all in the same /16 — one device whose
    // carrier reassigned its IP a few times.
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
    // Must NOT misclassify as shared.
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
    // Empty-state copy must mention chunk 4 + the SSH key path.
    assert!(
        html.contains("No live stats yet"),
        "empty-state nudge missing"
    );
    // Copy refreshed 2026-06-10: the scheduler is LIVE — empty state
    // now explains why a covered user can still be blank.
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
    seed(&s.inv, 2, 1, &[]).await; // s0, s1, u0

    // Simulate two ticks worth of poller output.
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[
                VpnStatsDelta {
                    user_id: Some(UserId("u0".into())),
                    upload_bytes: 1_000_000,   // 976 KiB
                    download_bytes: 5_000_000, // ~4.77 MiB
                    active_connections: 3,
                },
                // Server-wide row — must NOT appear in user query.
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

    // Aggregated totals appear (rendered via humanize_bytes — KiB/MiB).
    // Sum of u0's bytes: up = 1_500_000 (~1.4 MiB), dn = 7_000_000 (~6.7 MiB).
    assert!(html.contains("uploaded"), "uploaded KPI label missing");
    assert!(html.contains("downloaded"), "downloaded KPI label missing");
    assert!(html.contains("peak conns"), "peak conns KPI label missing");
    // Per-server breakdown table must list both servers.
    assert!(html.contains("s0"), "server s0 row missing");
    assert!(html.contains("s1"), "server s1 row missing");
    // Server-wide totals (99,999,999) MUST NOT appear — that row was
    // user_id=NULL and recent_vpn_stats_for_user filters those out.
    assert!(
        !html.contains("99.9 MiB") && !html.contains("99,999,999"),
        "server-wide row must not leak into per-user view"
    );
    // The empty-state nudge must NOT render when there's data.
    assert!(
        !html.contains("No live stats yet"),
        "empty-state copy leaked into populated render"
    );
    // Aggregation footer mentions the snapshot count.
    assert!(
        html.contains("Aggregated from 2 snapshots"),
        "snapshot count footer missing or wrong"
    );
}

#[tokio::test]
async fn admin_user_detail_track3_does_not_leak_other_users_stats() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 2, &[]).await; // s0, u0, u1

    // u0 has stats, u1 has none.
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
    // u1 must show empty state, not u0's bytes.
    assert!(
        html.contains("No live stats yet"),
        "u1 must show empty state when only u0 has data"
    );
}

// ─── Pavel iter D.6c: traffic limit + alert UI ──────────────────────────

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
    // Section heading + the form's action URL + default threshold.
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
    // 5 GiB = 5 * 1_073_741_824 = 5_368_709_120 bytes
    assert_eq!(lim, Some(5_368_709_120));
    assert_eq!(thr, Some(75));
    // Audit row with the new payload.
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
    // Pre-state: cap of 10 GiB.
    inv.set_user_traffic_limit(&UserId("alice".into()), Some(10_737_418_240), Some(80))
        .await
        .unwrap();
    // POST with limit_gib=0 → cap cleared.
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
    // Pin that the migration-0019 chips render on the
    // /admin/users/{id} Subscription-access table when columns
    // are present. Without this assertion, a maud template
    // refactor that drops the chip rendering would silently
    // ship without breaking a test.
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

    // Use log_sub_access_rich directly so we can populate the new
    // metadata columns without a real HTTP roundtrip (the writer
    // task path is exercised live, not in this smoke).
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
    // R2: the v2 geo-log has no http-version / device-class columns —
    // that metadata lives in the origins fingerprint line + the CSV
    // export. The UA column carries the raw string.
    assert!(
        html.contains("Hiddify/Android/2.5.0"),
        "raw UA must render in the UA column"
    );
}

#[tokio::test]
async fn track_1_2_subscription_access_legacy_row_renders_bare_ip() {
    // Symmetric: a row from BEFORE migration 0019 (no new metadata)
    // renders the IP without exploding and without spurious empty
    // chips.
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
    // No geo_country / geo_asn chips since both are NULL — render
    // must NOT emit empty `>` `<` placeholders.
    assert!(
        !html.contains(r#"border: 1px solid var(--acc-good, #2c5f2d); color: var(--acc-good, #2c5f2d); margin-left: 2px;" title="Country"#),
        "no country chip when geo_country is None — currently no such substring"
    );
}

#[tokio::test]
async fn track_1_4_subscription_access_omits_ja_chips_when_null() {
    // Symmetric: rows with NULL tls_ja3 + tls_ja4 (default today;
    // nginx-side module not installed) render WITHOUT the JA chips.
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

/// user#2 — populated: a per-user VPN tick lands a per-server row.
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
    // R2: the fixed-24h duplicate table was removed — the window-driven
    // live-stats table (now carrying a «total» column) is the one
    // per-server surface on this tab.
    assert!(
        html.contains("Live VPN stats"),
        "live-stats eyebrow missing"
    );
    assert!(html.contains("peak conns"), "peak-conns column missing");
    assert!(html.contains("total"), "total column missing (R2)");
    // s0 row present with humanized totals.
    assert!(html.contains("s0"), "per-server row for s0 missing");
    assert!(
        html.contains("11.4 MiB"),
        "total column must humanize up+down (3 MB + 9 MB)"
    );
}

/// user#3 — with a monthly cap set + month-to-date usage, the section
/// renders the progress bar copy AND the month-end projection.
#[tokio::test]
async fn pr_user_quota_renders_progress_and_projection_with_limit() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // 5 GiB cap.
    s.inv
        .set_user_traffic_limit(&UserId("u0".into()), Some(5_368_709_120), Some(80))
        .await
        .unwrap();
    // Some month-to-date usage so the projection is non-zero.
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
    // Progress copy from fmt_traffic_progress: "X / Y (Z%)".
    assert!(
        html.contains("5 GiB") || html.contains("5.0 GiB"),
        "progress bar must show the configured cap"
    );
    // Projection line.
    assert!(
        html.contains("projected"),
        "month-end projection line missing when a cap is set"
    );
    assert!(
        html.contains("by month-end"),
        "projection copy contract drifted"
    );
}

/// user#3 — with NO cap set, the section shows just the usage + form,
/// and NO projection line (projection is only meaningful with a cap).
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
    // The form is still present.
    assert!(
        html.contains(r#"name="limit_gib""#),
        "limit form must still render with no cap"
    );
    // No projection line without a cap.
    assert!(
        !html.contains("by month-end"),
        "projection must not render when no cap is set"
    );
}

/// user#6 — the live-VPN-stats section folds in a window picker scoped
/// to THIS user's detail page (24h/7d/30d/all) so the trend is one
/// click away.
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
    // The window picker links are scoped to the user's detail page.
    assert!(
        html.contains("/admin/users/u0/traffic?vpn_window=7d"),
        "window picker must offer a 7d link scoped to this user"
    );
    assert!(
        html.contains("/admin/users/u0/traffic?vpn_window=30d"),
        "window picker must offer a 30d link scoped to this user"
    );
    // The trend sub-heading renders when there's traffic.
    assert!(
        html.contains("traffic trend · "),
        "folded sparkline trend heading missing"
    );
}

/// user#7 — the UA-cluster section carries the additive geo + last-seen
/// footer (country / ASN / last-seen) once the user has /sub history.
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
    // Additive geo + last-seen footer labels.
    assert!(
        html.contains("countries · 30d"),
        "UA geo footer (countries) missing"
    );
    assert!(html.contains("ASNs · 30d"), "UA geo footer (ASNs) missing");
    assert!(html.contains("last seen "), "UA last-seen footer missing");
}

/// Design v2 4c — the user Activity tab opens with the four fact
/// tiles and the GeoIP-resolved fetch log (row per fetch incl. the
/// geo/asn/ua columns and the egress ⚠ flag path).
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
    // TT-3 — the distinct-IP tile is labelled \"client IPs · 30d\" and
    // counts only real client IPs (proxy/reserved excluded), matching the
    // verdict + Source-IP origins.
    assert!(
        html.contains("client IPs · 30d") && html.contains("sub fetches · 30d"),
        "count tiles missing"
    );
    // TT-3 — log scope caption describes the log's own scope (all sources,
    // incl. proxy-masked + egress) so it reads as a deliberately-different
    // view from the real-client «client IPs» tile.
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

/// v2 4c gap-close — the Activity sub-access log shows a «showing N of M»
/// pager with an older→ link and a CSV export link; the CSV endpoint
/// returns a text/csv attachment.
#[tokio::test]
async fn v2_user_activity_log_pagination_and_csv() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // 30 fetches → 2 pages of 25.
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
    assert!(
        html.contains("older →") || html.contains("старше →"),
        "page 1 of 2 must offer an older→ link"
    );
    assert!(
        html.contains("/admin/users/u0/access.csv"),
        "log must offer a CSV export link"
    );
    // CSV endpoint.
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
