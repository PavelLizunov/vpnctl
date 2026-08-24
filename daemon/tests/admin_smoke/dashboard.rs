use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctld::router;

use super::common::*;

/// Empty inventory must render the dashboard with all four metric tiles
/// at zero (or "live" for the daemon tile) and the empty-state copy for
/// recent activity. Each integer is anchored to its tile, so swapping
/// tile order in a refactor doesn't fool the test.
#[tokio::test]
async fn admin_dashboard_renders_zero_state_on_empty_db() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/").await;

    assert!(html.contains(r#"class="ed-sumbar""#), "summary bar missing");
    assert_summary_stat(&html, "0", "servers");
    assert_summary_stat(&html, "0", "users");
    assert_summary_stat(&html, "0", "protocols");
    // Daemon 'live' status lives in the summary bar's right slot.
    assert!(
        html.contains(r#"class="ed-sumbar__live""#) && html.contains("<em>live</em>"),
        "summary bar must show the daemon 'live' status"
    );
    // Dashboard 1b quiet contract: no servers → no fleet table, no
    // alerts → no health feed, no flagged users → no likely-shared
    // panel. The overview two-column wrapper still renders (empty).
    assert!(
        !html.contains("fleet-at-a-glance"),
        "empty inventory must not render the fleet table"
    );
    assert!(
        html.contains(r#"class="ed-dash-cols""#),
        "overview panel row missing"
    );
}

/// Dashboard counters must reflect what's actually in the inventory:
/// 3 servers, 2 users, 4 grants → exact integers anchored to their tiles
/// plus an "across 4 grants" subtitle.
#[tokio::test]
async fn admin_dashboard_counts_match_seeded_inventory() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // 4 grants among 2 users / 3 servers (u0 -> s0,s1; u1 -> s1,s2)
    seed(&s.inv, 3, 2, &[(0, 0), (0, 1), (1, 1), (1, 2)]).await;

    let app = router(s);
    let html = fetch_html(app, "/admin/").await;

    assert_summary_stat(&html, "3", "servers");
    assert_summary_stat(&html, "2", "users");
    // distinct enabled_protocols is 1 (every seeded server gets
    // vless+reality) — and the label declines: «1 protocol», not the
    // old always-plural «1 protocols» (i18n::noun_for, polish pass).
    assert_summary_stat(&html, "1", "protocol");
    assert!(
        html.contains("<b>4</b> grants"),
        "grants subtitle missing or wrong (expected 4 grants, plural)"
    );
}

/// Pluralisation guard for the dashboard "across N grants" subtitle:
/// 1 grant must read "1 grant" (singular), >1 must read "N grants".
#[tokio::test]
async fn admin_dashboard_pluralises_grants_subtitle() {
    // 1 grant — singular.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("<b>1</b> grant"),
        "singular form 'grant' expected for 1 grant"
    );
    assert!(
        !html.contains("<b>1</b> grants"),
        "must not pluralise when grant count is 1"
    );

    // 2 grants — plural.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0), (0, 1)]).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("<b>2</b> grants"),
        "plural form 'grants' expected for 2 grants"
    );
}

#[tokio::test]
async fn phase4b_dashboard_renders_vpn_activity_tile_with_per_server_breakdown() {
    // Two servers; one has a sample, one doesn't. Dashboard tile
    // must render with the per-server breakdown table; quiet server
    // still appears with zeros.
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    use vpnctl_inventory::VpnStatsDelta;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    for (id, addr) in [("busy", "203.0.113.1"), ("quiet", "203.0.113.2")] {
        s.inv
            .add_server(&Server {
                id: ServerId(id.into()),
                address: addr.into(),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels: vec![KernelId("sing-box".into())],
                enabled_protocols: Vec::new(),
                trusted_host_fingerprint: None,
                hoster: "generic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            })
            .await
            .unwrap();
    }
    s.inv
        .add_user(&User {
            id: UserId("u1".into()),
            uuid: "u10".into(),
            sub_token: None,
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // Record server-wide tick on `busy` (user_id = None).
    s.inv
        .record_vpn_stats(
            &ServerId("busy".into()),
            &[VpnStatsDelta {
                user_id: None,
                upload_bytes: 12_345,
                download_bytes: 54_321,
                active_connections: 7,
            }],
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/activity").await;
    // Heading uses the active window label (default 24h, post-
    // 2026-05-23 global window picker). «VPN activity · 24h»
    // — same tile, just generic-windowed.
    assert!(
        html.contains("VPN activity · 24h"),
        "dashboard must surface the new VPN-activity tile; got: {}",
        &html[..200.min(html.len())]
    );
    assert!(html.contains("NM-11"), "tile must surface NM-11 explainer");
    // Pin the busy server's `<td>7</td>` row specifically so an
    // unrelated «7» in a sibling tile (page counter, server total
    // etc.) can't satisfy this assertion. Review-agent Phase 4b #7.
    // PR-Dash: the fleet-at-a-glance table (above this tile) ALSO links
    // /admin/servers/busy with a «conns now» cell sourced from the live
    // snapshot cache (empty in this test → «—»), so scope the search to
    // the VPN-activity section to keep hitting the active_now=7 row.
    let activity_pos = html
        .find("VPN activity · 24h")
        .expect("VPN activity tile must render");
    let activity_html = &html[activity_pos..];
    let busy_anchor = "href=\"/admin/servers/busy\"";
    let busy_pos = activity_pos
        + activity_html
            .find(busy_anchor)
            .expect("busy server link must render in the VPN-activity breakdown");
    let busy_row = &html[busy_pos..busy_pos.saturating_add(400)];
    assert!(
        busy_row.contains(">7<"),
        "busy server's active-now cell must be 7, got row: …{busy_row}…"
    );
    // Per-server breakdown links to each server-detail page.
    assert!(
        html.contains(busy_anchor) && html.contains("href=\"/admin/servers/quiet\""),
        "both servers must appear in the per-server breakdown"
    );
}

#[tokio::test]
async fn phase4b_dashboard_vpn_activity_tile_shows_empty_state_when_no_polls() {
    // No samples anywhere — the tile must render the empty-state
    // copy pointing at the Servers list, NOT crash or hide.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // No servers at all → list is empty.
    let html = fetch_html(router(s), "/admin/activity").await;
    assert!(
        html.contains("VPN activity · 24h"),
        "tile must always render"
    );
    assert!(
        html.contains("No clash-api samples yet"),
        "empty-state copy must mention «No clash-api samples yet»"
    );
}

// ── Phase H+ — dashboard FLEET uptime tile ──────────────────────────
//
// Companion to `server_detail_uptime_*` tests above. The dashboard
// tile aggregates probe-weighted across all servers. Empty fleet =
// section omitted; populated fleet = 3 chips with
// `data-fleet-uptime-pct` attribute.

#[tokio::test]
async fn dashboard_fleet_uptime_section_omitted_when_no_servers_polled() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Add a server but write ZERO node_health rows. The aggregator
    // must see «no decidable data anywhere» and suppress the section.
    st.inv
        .add_server(&Server {
            id: ServerId("fresh".into()),
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
                .uri("/admin/activity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("id=\"fleet-uptime\""),
        "fleet-uptime section must NOT render when no server has decidable probes"
    );
    assert!(
        !html.contains("Fleet uptime"),
        "fleet-uptime eyebrow must NOT render when section is suppressed"
    );
}

#[tokio::test]
async fn dashboard_fleet_uptime_section_renders_with_probe_data() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Two servers: alpha all-up (4 rows), bravo also all-up (3 rows).
    // Aggregate = (4+3) up / (4+3) decidable = 100% in every window.
    for (sid_s, n_rows) in [("alpha", 4), ("bravo", 3)] {
        let sid = ServerId(sid_s.into());
        st.inv
            .add_server(&Server {
                id: sid.clone(),
                address: format!("203.0.113.{}", if sid_s == "alpha" { 1 } else { 2 }),
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
        for _ in 0..n_rows {
            st.inv
                .record_node_health(
                    &sid,
                    Some(true),
                    Some(true),
                    Some(1024),
                    Some(10240),
                    Some(500),
                    Some(1024),
                    Some(50),
                    Some("[\"tcp/443\"]"),
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
    }
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/activity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // Section anchor + eyebrow present.
    assert!(
        html.contains("id=\"fleet-uptime\""),
        "fleet-uptime section anchor must render"
    );
    assert!(
        html.contains("Fleet uptime · sing-box services"),
        "fleet-uptime EN eyebrow must render"
    );
    // 3 chips × 100% via the stable scrape attribute (not inline
    // text — admin page has many unrelated «100%» substrings).
    let pct_attr_count = html.matches("data-fleet-uptime-pct=\"100\"").count();
    assert_eq!(
        pct_attr_count, 3,
        "all three fleet-uptime chips must carry data-fleet-uptime-pct=\"100\" \
         (found {pct_attr_count})"
    );
    // Polled / total ratio chip footer must read «2/2 polled»
    // (both seeded servers contributed probes).
    assert!(
        html.contains("2/2"),
        "chip footer must show «2/2 polled» when both seeded servers contributed"
    );
}

#[tokio::test]
async fn dashboard_fleet_uptime_excludes_unpolled_server_from_polled_ratio() {
    // Mixed fleet: one server polled, one fresh. Aggregator should
    // EXCLUDE the fresh one from the «polled» count (numerator)
    // but INCLUDE it in the total-servers count (denominator) →
    // footer reads «1/2 polled». Pins the «fresh server doesn't
    // poison the average» guarantee from the doc-comment.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    for sid_s in ["polled", "fresh"] {
        st.inv
            .add_server(&Server {
                id: ServerId(sid_s.into()),
                address: format!("203.0.113.{}", if sid_s == "polled" { 11 } else { 12 }),
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
    }
    // Only «polled» gets probes.
    let polled = ServerId("polled".into());
    for _ in 0..5 {
        st.inv
            .record_node_health(
                &polled,
                Some(true),
                Some(true),
                Some(1024),
                Some(10240),
                Some(500),
                Some(1024),
                Some(50),
                Some("[\"tcp/443\"]"),
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
                .uri("/admin/activity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("id=\"fleet-uptime\""),
        "fleet-uptime section must render when at least one server is polled"
    );
    assert!(
        html.contains("1/2"),
        "chip footer must show «1/2 polled» (one polled, one fresh)"
    );
    // The polled server is 100% → all 3 chips must read 100.
    let pct_attr_count = html.matches("data-fleet-uptime-pct=\"100\"").count();
    assert_eq!(
        pct_attr_count, 3,
        "all three chips must carry data-fleet-uptime-pct=\"100\" \
         when the only polled server is 100% up"
    );
}

// ── A2 — idle-users panel on dashboard ──────────────────────────────
//
// Lists users idle 30+ days OR never-seen. Renders only when there's
// at least one idle user (quiet dashboard for a healthy fleet).

#[tokio::test]
async fn dashboard_idle_users_panel_omitted_when_no_users() {
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
        !html.contains("id=\"idle-users\""),
        "idle-users panel must be omitted on an empty inventory"
    );
}

// ── B1.user dashboard surface — «N paused» sub-line ─────────────────
//
// Disabled-count surfaces in the Users tile sub-line so paused users
// don't fall off the operator's radar. Quiet dashboard contract:
// rendered ONLY when at least one user is disabled.

#[tokio::test]
async fn dashboard_users_tile_omits_paused_subline_when_zero() {
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
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains("paused") && !html.contains("на паузе"),
        "no users disabled → «paused» sub-line must be hidden"
    );
}

#[tokio::test]
async fn dashboard_users_tile_renders_paused_subline_when_nonzero() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Two disabled users + one normal to verify the count is exact.
    st.inv
        .add_user(&User {
            id: UserId("p1".into()),
            uuid: "00000000-0000-0000-0000-000000000071".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: true,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("p2".into()),
            uuid: "00000000-0000-0000-0000-000000000072".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: true,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("active".into()),
            uuid: "00000000-0000-0000-0000-000000000073".into(),
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
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("paused") || html.contains("на паузе"),
        "paused sub-line must render when disabled count > 0"
    );
    assert!(
        html.contains(">2<"),
        "exact disabled count (2) must appear in the rendered <b>; html sample: {}",
        if html.len() > 600 { &html[..600] } else { html }
    );
}

/// dash#1 — fleet-at-a-glance renders one row per server with the
/// section eyebrow + the seeded sing-box version cell.
#[tokio::test]
async fn dashboard_fleet_table_renders_row_per_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/").await;

    assert!(
        html.contains(r#"id="fleet-at-a-glance""#),
        "fleet section anchor missing"
    );
    // Dashboard 1b: the fleet renders as a dense .ed-grid table.
    assert!(
        html.contains(r#"<table class="ed-grid""#),
        "fleet must render as a dense ed-grid table"
    );
    // Both seeded servers appear as drill-in links.
    assert!(
        html.contains("/admin/servers/s0") && html.contains("/admin/servers/s1"),
        "every seeded server must get a row link"
    );
    // The seeded sing-box version shows in s0's version cell.
    assert!(html.contains("1.13.12"), "s0 sing-box version cell missing");
    // Disk% (20) stays a plain cell; mem% (75) crosses the 70% watermark
    // and must render as a warm heat cell with the ⚠ marker.
    assert!(html.contains("20%"), "s0 disk% cell missing");
    assert!(
        html.contains(r#"class="num warn""#) && html.contains("75% ⚠"),
        "s0 mem% above 70 must render the heat cell + ⚠"
    );
}

/// Dashboard 1b — a node whose sing-box version differs from the fleet
/// majority gets the warm «≠» drift marker in its version cell.
#[tokio::test]
async fn dashboard_fleet_table_marks_version_drift() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 3, 0, &[]).await;
    // s0 + s1 on the majority version, s2 drifted ahead.
    for (sid, ver) in [("s0", "1.13.12"), ("s1", "1.13.12"), ("s2", "1.13.14")] {
        s.inv
            .record_node_health(
                &ServerId(sid.into()),
                Some(true),
                Some(true),
                Some(1024),
                Some(20480),
                Some(6144),
                Some(8192),
                Some(50),
                None,
                None,
                Some(&format!(r#"{{"sing-box":"{ver}"}}"#)),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("1.13.14 ≠"),
        "minority version must carry the ≠ drift marker"
    );
    assert!(
        !html.contains("1.13.12 ≠"),
        "majority version must NOT be flagged"
    );
}

/// dash#1 — empty fleet renders no at-a-glance table at all (the metrics
/// deck + servers page already carry the "add a server" CTA).
#[tokio::test]
async fn dashboard_fleet_table_hidden_when_no_servers() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/").await;
    assert!(
        !html.contains(r#"id="fleet-at-a-glance""#),
        "fleet table must stay hidden on an empty fleet"
    );
}

/// dash#2 — real-traffic totals render the ↑↓ + vs-prior tiles beside
/// the chart, inside the #vpn-traffic block.
#[tokio::test]
async fn dashboard_fleet_traffic_totals_render_beside_chart() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/activity").await;
    // The vs-prior delta tile label is distinctive to dash#2.
    assert!(
        html.contains("vs prior"),
        "dash#2 'vs prior' delta tile missing"
    );
    // The upload/download window tiles use the ↑/↓ glyphs.
    assert!(
        html.contains("↑ upload") && html.contains("↓ download"),
        "dash#2 ↑↓ window tiles missing"
    );
}

/// Issue 2 (Activity) — the fleet traffic totals beside the chart must
/// sum ALL rows (attributed + remainder), not only user_id IS NULL.
/// 900 attributed + 100 remainder = 1000 total.
#[tokio::test]
async fn activity_fleet_totals_sum_attributed_and_remainder() {
    use vpnctl_inventory::VpnStatsDelta;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[
                VpnStatsDelta {
                    user_id: Some(UserId("u0".into())),
                    upload_bytes: 400,
                    download_bytes: 500,
                    active_connections: 1,
                },
                VpnStatsDelta {
                    user_id: None,
                    upload_bytes: 40,
                    download_bytes: 60,
                    active_connections: 1,
                },
            ],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/activity").await;
    assert!(
        html.contains("1000 B"),
        "activity fleet totals must sum attributed (900) + remainder (100) = 1000 B"
    );
}

/// Issue 2 — the fleet table "traffic 24h" column must sum EVERY row
/// (per-user attributed + server-wide remainder). Since the NM-11
/// attribution fix the server-wide row holds only the unattributed
/// remainder, so summing it alone undercounts by the attributed share.
/// 900 attributed + 100 remainder must read as 1000, matching the
/// server-detail / activity rollup (`server_live_activity`).
#[tokio::test]
async fn dashboard_traffic_24h_sums_attributed_and_remainder() {
    use vpnctl_inventory::VpnStatsDelta;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // s0, u0 granted
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[
                // 900 bytes attributed to u0 (400 up + 500 down).
                VpnStatsDelta {
                    user_id: Some(UserId("u0".into())),
                    upload_bytes: 400,
                    download_bytes: 500,
                    active_connections: 1,
                },
                // 100 bytes unattributed remainder (server-wide row).
                VpnStatsDelta {
                    user_id: None,
                    upload_bytes: 40,
                    download_bytes: 60,
                    active_connections: 1,
                },
            ],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/").await;
    // 900 + 100 = 1000 → "1000 B". Pre-fix this column summed only the
    // user_id IS NULL remainder and rendered "100 B".
    assert!(
        html.contains("1000 B"),
        "traffic 24h must sum attributed (900) + remainder (100) = 1000 B"
    );
}

/// Issue 5 — the multi-window (24h / 7d / 30d / all) traffic picker lives
/// on the Activity tab after the dashboard split; Overview must surface a
/// clear, bilingual pointer to it so the traffic history stays
/// discoverable from the landing glance (a link, not a duplicated chart).
#[tokio::test]
async fn dashboard_overview_surfaces_traffic_history_link() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/").await;
    // Bilingual label wording (EN copy on the default locale).
    assert!(
        html.contains("Traffic history · 1 / 7 / 30 days"),
        "overview must label the traffic-history pointer with 1/7/30-day wording"
    );
    // …and it must actually link through to the Activity tab.
    assert!(
        html.contains("/admin/activity#vpn-traffic"),
        "the traffic-history pointer must link to the Activity tab"
    );
}

/// dash#3 — kernel rollup shows the fleet floor version + on-target
/// state when every reporting node is at the floor.
#[tokio::test]
async fn dashboard_kernel_rollup_shows_version() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/activity").await;
    assert!(
        html.contains("Kernel rollup"),
        "kernel-rollup eyebrow missing"
    );
    assert!(
        html.contains(r#"id="kernel-rollup""#),
        "kernel-rollup section anchor missing"
    );
    // Single node at 1.13.12 → "sing-box 1/1 @ 1.13.12 ✓ on target".
    assert!(
        html.contains("1.13.12"),
        "kernel-rollup floor version missing"
    );
    assert!(
        html.contains("on target"),
        "kernel-rollup on-target verdict missing when all nodes at floor"
    );
}

/// dash#3 — quiet empty-state when no node has reported a version.
#[tokio::test]
async fn dashboard_kernel_rollup_empty_state_when_no_versions() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Server exists but NO node_health row with kernel versions.
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/activity").await;
    assert!(
        html.contains("No on-node version data yet"),
        "kernel-rollup must show the quiet no-data line"
    );
}

/// dash#4 — alerts breakdown renders severity counts + the section
/// when there's at least one unacked alert.
#[tokio::test]
async fn dashboard_health_feed_renders_alert_row() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(html.contains("Health feed"), "health-feed eyebrow missing");
    // Eyebrow carries the unacked total (1 seeded).
    assert!(
        html.contains("open 1"),
        "health-feed eyebrow must show the unacked total"
    );
    // The seeded critical alert renders as a feed row: ✖ mark + kind +
    // the server target linked.
    assert!(html.contains("✖"), "critical alert must show the ✖ mark");
    assert!(
        html.contains("disk_pressure"),
        "feed row must name the alert kind"
    );
    assert!(
        html.contains("full feed →") || html.contains("весь поток →"),
        "feed must link to /admin/alerts"
    );
}

/// Dashboard 1b — quiet contract: no health feed when zero unacked alerts.
#[tokio::test]
async fn dashboard_health_feed_empty_when_none() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // no alerts seeded
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        !html.contains("Health feed"),
        "health feed must stay hidden with zero unacked alerts"
    );
}

/// dash#5 — abuse summary lists the likely-shared user with an ASN count
/// and a drill-in link.
#[tokio::test]
async fn dashboard_abuse_summary_lists_shared_user() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("Likely-shared subscriptions"),
        "abuse-summary eyebrow missing"
    );
    assert!(
        html.contains("/admin/users/u0"),
        "abuse-summary must link the flagged user to their detail page"
    );
    // Sharing v2: the dominant reason is TypicalConcurrentNets(3) (seeded above),
    // rendered as "3 networks at once" — fetch-side ASN diversity no longer
    // scores or shows here.
    assert!(
        html.contains("3 networks at once"),
        "abuse-summary must show the concurrency reason"
    );
}

/// dash#5 — hidden when no sub crosses the ASN threshold.
#[tokio::test]
async fn dashboard_abuse_summary_hidden_when_no_sharing() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // no sub_access rows
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        !html.contains("Likely-shared subscriptions"),
        "abuse-summary must stay hidden when nothing is shared"
    );
}

/// The sharing-risk card must link to the VPN source-IP evidence that
/// actually feeds the score, not to unrelated subscription-fetch origins.
#[tokio::test]
async fn dashboard_abuse_summary_links_to_source_ip_evidence() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let app = router(s);
    let html = fetch_html(app.clone(), "/admin/").await;
    assert!(
        html.contains("/admin/users/u0/activity#source-ips"),
        "abuse-summary user link must anchor to the VPN source-IP evidence"
    );
    let detail = fetch_html(app, "/admin/users/u0/activity").await;
    assert!(
        detail.contains(r#"id="source-ips""#),
        "the link target must exist on the user activity page"
    );
}

/// The compact dashboard card shows six rows, then links to the dedicated
/// filtered review page instead of appending an unstyled list in-place.
#[tokio::test]
async fn dashboard_abuse_summary_more_flagged_links_to_full_page() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 7, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    for i in 1..7 {
        s.inv
            .record_user_ip_concurrency(&[(UserId(format!("u{i}")), 3)])
            .await
            .unwrap();
    }

    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains(r#"href="/admin/sharing""#) && html.contains("+1 more flagged"),
        "overflow must link to the full sharing-risk page: {html}"
    );
    assert!(
        !html.contains("<details"),
        "dashboard must not append the old native disclosure list"
    );
}

/// abuse-origins — the deleted-user blank-row bug. Seeding a NULL-user
/// (since-deleted) sub_access pattern that crosses the ASN threshold must
/// NOT surface a nameless row in the dashboard abuse card (the
/// `user_id IS NOT NULL` fix in `likely_shared_summary`).
#[tokio::test]
async fn dashboard_abuse_summary_omits_deleted_user_blank_row() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    // Seed a high-ASN pattern for a soon-to-be-deleted user.
    s.inv
        .add_user(&User {
            id: UserId("ghost".into()),
            uuid: "00000000-0000-0000-0000-deadbeefdead".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    for (ip, asn, cc) in [
        ("203.0.113.40", "AS4444", "US"),
        ("198.51.100.50", "AS5555", "DE"),
        ("192.0.2.60", "AS6666", "FR"),
    ] {
        s.inv
            .log_sub_access_rich(
                &UserId("ghost".into()),
                ip,
                Some("curl/8.0"),
                200,
                1024,
                None,
                None,
                None,
                Some(cc),
                Some(asn),
                None,
                None,
            )
            .await
            .unwrap();
    }
    // Remove the user — the inventory pool runs with foreign_keys ON, so
    // the `ON DELETE SET NULL` (migration 0004) NULLs user_id on every
    // one of ghost's sub_access_log rows while keeping the forensic rows.
    s.inv.remove_user(&UserId("ghost".into())).await.unwrap();

    let html = fetch_html(router(s), "/admin/").await;
    // No nameless link to the user index (the blank-row symptom).
    assert!(
        !html.contains(r#"href="/admin/users/#source-ips""#)
            && !html.contains(r#"href="/admin/users/""#),
        "abuse card must not render a blank-name (deleted-user) link"
    );
    // And specifically the deleted user's id must not appear in a link.
    assert!(
        !html.contains("/admin/users/ghost"),
        "a deleted user must not be flagged in the abuse card"
    );
    // With ONLY deleted-user rows, the whole card stays hidden.
    assert!(
        !html.contains("Likely-shared subscriptions"),
        "abuse card must stay hidden when the only high-ASN pattern is a deleted user"
    );
}

// ════════════════════════════════════════════════════════════════════
//  ui-audit follow-up — dashboard split into sub-route tabs. The KPI
//  metrics + today-digest + fleet table
//  stay as CHROME (every tab — the glance is never hidden); the two tabs
//  split only the deeper drill-downs. Bare /admin/ == overview.
// ════════════════════════════════════════════════════════════════════

/// Each tab route → 200, renders the `.ed-tabs` bar, keeps the KPI glance
/// (fleet table) as chrome on BOTH tabs, marks the right tab active,
/// shows a section unique to that tab, and does NOT leak the other tab's.
#[tokio::test]
async fn dashboard_tabs_render_gate_and_mark_active() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let app = router(s);
    let cases = [
        (
            "/admin/overview",
            "overview",
            "Health feed",
            "Fleet traffic",
        ),
        (
            "/admin/activity",
            "activity",
            "Fleet traffic",
            "Health feed",
        ),
        (
            "/admin/sharing",
            "sharing",
            "Sharing-risk review",
            "Health feed",
        ),
    ];
    for (path, slug, present, absent) in cases {
        let html = fetch_html(app.clone(), path).await;
        assert!(
            html.contains(r#"class="ed-tabs""#),
            "{path}: tab bar (.ed-tabs) missing"
        );
        // KPI glance stays chrome — the fleet table renders on BOTH tabs.
        assert!(
            html.contains(r#"id="fleet-at-a-glance""#),
            "{path}: KPI glance (fleet table) must stay as chrome on every tab"
        );
        let active = format!(r#"ed-tab--on" href="/admin/{slug}""#);
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

/// Bare `/admin/` renders the overview tab directly.
#[tokio::test]
async fn dashboard_bare_url_renders_overview_tab() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains(r#"ed-tab--on" href="/admin/overview""#),
        "bare URL must mark the overview tab active"
    );
    assert!(
        html.contains("Health feed"),
        "bare URL must render the overview tab's sections"
    );
    assert!(
        !html.contains("Fleet traffic"),
        "bare URL (overview) must not render the activity tab"
    );
}

/// Copy-contract — pin the dashboard tab labels in both locales.
#[tokio::test]
async fn dashboard_tab_labels_copy_contract() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[]).await;
    let app = router(s);
    let en = fetch_html(app.clone(), "/admin/").await;
    for label in [">Overview</a>", ">Activity</a>", ">Sharing risk</a>"] {
        assert!(en.contains(label), "EN tab label drifted: {label:?}");
    }
    let ru = fetch_html_with_cookie(app, "/admin/", "vpnctl_lang=ru").await;
    for label in [">Обзор</a>", ">Активность</a>", ">Риск расшаривания</a>"]
    {
        assert!(ru.contains(label), "RU tab label drifted: {label:?}");
    }
}

/// Copy-contract — pin every new PR-Dash eyebrow/headline (EN) so a
/// future copy edit has to update this test in lockstep. Mirrors
/// `admin_frontend_section_headlines_match_voice`.
#[tokio::test]
async fn dashboard_info_cards_headlines_match_voice() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    // ui-audit follow-up — dash#2/#3 (traffic totals + kernel rollup)
    // moved to the activity tab; the rest stay on the overview/chrome.
    let app = router(s);
    let overview = fetch_html(app.clone(), "/admin/").await;
    let activity = fetch_html(app, "/admin/activity").await;
    for (html, needle) in [
        (&overview, ">Fleet <span"),                // 1b fleet (chrome)
        (&activity, "vs prior"),                    // dash#2 (activity)
        (&activity, "Kernel rollup · sing-box"),    // dash#3 (activity)
        (&overview, "Health feed"),                 // 1b feed (overview)
        (&overview, "Likely-shared subscriptions"), // 1b panel (overview)
    ] {
        assert!(
            html.contains(needle),
            "dashboard headline drifted — missing: {needle:?}"
        );
    }
}

/// Copy-contract (RU) — pin the Russian arm of each new card so a
/// half-translation can't ship. Extends the i18n RU walker's intent.
#[tokio::test]
async fn dashboard_info_cards_headlines_ru() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let app = router(s);
    let overview = fetch_html_with_cookie(app.clone(), "/admin/", "vpnctl_lang=ru").await;
    let activity = fetch_html_with_cookie(app, "/admin/activity", "vpnctl_lang=ru").await;
    for (html, needle) in [
        (&overview, ">Флот <span"),                    // 1b fleet (chrome)
        (&activity, "против пред."),                   // dash#2 (activity)
        (&activity, "Версии ядер · sing-box"),         // dash#3 (activity)
        (&overview, "Поток здоровья"),                 // 1b feed (overview)
        (&overview, "Похоже на расшаренные подписки"), // 1b panel (overview)
    ] {
        assert!(
            html.contains(needle),
            "dashboard RU headline drifted — missing: {needle:?}"
        );
    }
}

#[tokio::test]
async fn kernel_quality_release_renders_dashboard_ranking_and_detail() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    for minute in 1..=12 {
        s.inv
            .record_service_quality_sample(&release_quality_sample("s0", minute, true))
            .await
            .unwrap();
        s.inv
            .record_service_quality_sample(&release_quality_sample("s1", minute, false))
            .await
            .unwrap();
    }

    let dashboard = fetch_html(router(s.clone()), "/admin/").await;
    let ranking = &dashboard[dashboard.find(r#"id="fleet-quality-ranking""#).unwrap()..];
    assert!(ranking.contains("Fleet quality ranking · service path"));
    assert!(ranking.contains("100/100"));
    assert!(ranking.contains("0/100"));
    assert!(
        ranking.find(r#"data-quality-server="s0""#).unwrap()
            < ranking.find(r#"data-quality-server="s1""#).unwrap()
    );

    let detail = fetch_html(router(s), "/admin/servers/s0").await;
    assert!(detail.contains(r#"id="server-quality""#));
    assert!(detail.contains("Quality · service path"));
    assert!(detail.contains("vpnctld control host"));
}
