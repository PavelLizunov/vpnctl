use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctld::router;

use super::common::*;

#[tokio::test]
async fn admin_dashboard_renders_zero_state_on_empty_db() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/").await;

    assert!(html.contains(r#"class="ed-sumbar""#), "summary bar missing");
    assert_summary_stat(&html, "0", "servers");
    assert_summary_stat(&html, "0", "users");
    assert_summary_stat(&html, "0", "protocols");
    assert!(
        html.contains(r#"class="ed-sumbar__live""#) && html.contains("<em>live</em>"),
        "summary bar must show the daemon 'live' status"
    );
    assert!(
        !html.contains("fleet-at-a-glance"),
        "empty inventory must not render the fleet table"
    );
    assert!(
        html.contains(r#"class="ed-dash-cols""#),
        "overview panel row missing"
    );
}

#[tokio::test]
async fn admin_dashboard_counts_match_seeded_inventory() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 3, 2, &[(0, 0), (0, 1), (1, 1), (1, 2)]).await;

    let app = router(s);
    let html = fetch_html(app, "/admin/").await;

    assert_summary_stat(&html, "3", "servers");
    assert_summary_stat(&html, "2", "users");
    assert_summary_stat(&html, "1", "protocol");
    assert!(
        html.contains("<b>4</b> grants"),
        "grants subtitle missing or wrong (expected 4 grants, plural)"
    );
}

#[tokio::test]
async fn admin_dashboard_pluralises_grants_subtitle() {
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
    assert!(
        html.contains("VPN activity · 24h"),
        "dashboard must surface the new VPN-activity tile; got: {}",
        &html[..200.min(html.len())]
    );
    assert!(html.contains("NM-11"), "tile must surface NM-11 explainer");
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
    assert!(
        html.contains(busy_anchor) && html.contains("href=\"/admin/servers/quiet\""),
        "both servers must appear in the per-server breakdown"
    );
}

#[tokio::test]
async fn phase4b_dashboard_vpn_activity_tile_shows_empty_state_when_no_polls() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
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

#[tokio::test]
async fn dashboard_fleet_uptime_section_omitted_when_no_servers_polled() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
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
    assert!(
        html.contains("id=\"fleet-uptime\""),
        "fleet-uptime section anchor must render"
    );
    assert!(
        html.contains("Fleet uptime · sing-box services"),
        "fleet-uptime EN eyebrow must render"
    );
    let pct_attr_count = html.matches("data-fleet-uptime-pct=\"100\"").count();
    assert_eq!(
        pct_attr_count, 3,
        "all three fleet-uptime chips must carry data-fleet-uptime-pct=\"100\" \
         (found {pct_attr_count})"
    );
    assert!(
        html.contains("2/2"),
        "chip footer must show «2/2 polled» when both seeded servers contributed"
    );
}

#[tokio::test]
async fn dashboard_fleet_uptime_excludes_unpolled_server_from_polled_ratio() {
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
    let pct_attr_count = html.matches("data-fleet-uptime-pct=\"100\"").count();
    assert_eq!(
        pct_attr_count, 3,
        "all three chips must carry data-fleet-uptime-pct=\"100\" \
         when the only polled server is 100% up"
    );
}

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
    assert!(
        html.contains(r#"<table class="ed-grid""#),
        "fleet must render as a dense ed-grid table"
    );
    assert!(
        html.contains("/admin/servers/s0") && html.contains("/admin/servers/s1"),
        "every seeded server must get a row link"
    );
    assert!(html.contains("1.13.12"), "s0 sing-box version cell missing");
    let fleet = html
        .split_once(r#"id="fleet-at-a-glance""#)
        .unwrap()
        .1
        .split_once("</table>")
        .unwrap()
        .0;
    let row = fleet
        .split("<tr>")
        .find(|row| row.contains(r#"href="/admin/servers/s0""#))
        .unwrap()
        .split_once("</tr>")
        .unwrap()
        .0;
    assert!(
        row.contains(r#"<td class="num">20%</td>"#),
        "s0 disk% cell must stay plain"
    );
    let mem = row
        .split_once(r#"<td class="num warn">75%"#)
        .unwrap()
        .1
        .split_once("</td>")
        .unwrap()
        .0;
    assert!(
        mem.contains(r#"aria-label="High usage""#)
            && mem.contains(r#"<use href="/admin/assets/icons.svg#triangle-alert""#),
        "s0 mem% above 70 must render the heat cell and high-usage warning icon"
    );
}

#[tokio::test]
async fn dashboard_fleet_table_marks_version_drift() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 3, 0, &[]).await;
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
    let fleet = html
        .split_once(r#"id="fleet-at-a-glance""#)
        .unwrap()
        .1
        .split_once("</table>")
        .unwrap()
        .0;
    for (sid, version, drifted) in [
        ("s0", "1.13.12", false),
        ("s1", "1.13.12", false),
        ("s2", "1.13.14", true),
    ] {
        let row = fleet
            .split("<tr>")
            .find(|row| row.contains(&format!(r#"href="/admin/servers/{sid}""#)))
            .unwrap()
            .split_once("</tr>")
            .unwrap()
            .0;
        let value = row
            .split_once(&format!(r#"class="ed-kvers__value" title="{version}">"#))
            .unwrap()
            .1
            .split_once("</td>")
            .unwrap()
            .0;
        assert!(value.starts_with(version), "{sid}: version label drifted");
        assert_eq!(
            value.contains(r#"<use href="/admin/assets/icons.svg#equal-not""#),
            drifted,
            "{sid}: only minority versions must carry the drift icon"
        );
        assert_eq!(
            value.contains(r#"aria-label="Version differs / Версия отличается""#),
            drifted,
            "{sid}: drift status must be accessible"
        );
    }
}

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

#[tokio::test]
async fn dashboard_fleet_traffic_totals_render_beside_chart() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/activity").await;
    assert!(
        html.contains("vs prior"),
        "dash#2 'vs prior' delta tile missing"
    );
    let traffic = html
        .split_once(r#"id="vpn-traffic""#)
        .unwrap()
        .1
        .split_once(r#"id="kernel-rollup""#)
        .unwrap()
        .0;
    for (direction, label) in [("arrow-up", "upload 24h"), ("arrow-down", "download 24h")] {
        assert!(
            traffic
                .split(r#"class="ed-status-tile__k">"#)
                .skip(1)
                .any(|tile| {
                    let heading = tile.split_once("</div>").unwrap().0;
                    heading.contains(&format!(
                        r#"<use href="/admin/assets/icons.svg#{direction}""#
                    )) && heading.split_once("</svg>").map(|(_, text)| text.trim()) == Some(label)
                }),
            "{label}: direction icon and exact window label missing from the same tile"
        );
    }
}

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

#[tokio::test]
async fn dashboard_traffic_24h_sums_attributed_and_remainder() {
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
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("1000 B"),
        "traffic 24h must sum attributed (900) + remainder (100) = 1000 B"
    );
}

#[tokio::test]
async fn dashboard_overview_surfaces_traffic_history_link() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        html.contains("Traffic history · 1 / 7 / 30 days"),
        "overview must label the traffic-history pointer with 1/7/30-day wording"
    );
    assert!(
        html.contains("/admin/activity#vpn-traffic"),
        "the traffic-history pointer must link to the Activity tab"
    );
}

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
    assert!(
        html.contains("1.13.12"),
        "kernel-rollup floor version missing"
    );
    assert!(
        html.contains("on target"),
        "kernel-rollup on-target verdict missing when all nodes at floor"
    );
}

#[tokio::test]
async fn dashboard_kernel_rollup_empty_state_when_no_versions() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/activity").await;
    assert!(
        html.contains("No on-node version data yet"),
        "kernel-rollup must show the quiet no-data line"
    );
}

#[tokio::test]
async fn dashboard_health_feed_renders_alert_row() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(html.contains("Health feed"), "health-feed eyebrow missing");
    assert!(
        html.contains("open 1"),
        "health-feed eyebrow must show the unacked total"
    );
    let feed = html
        .split_once("Health feed · open 1</div>")
        .unwrap()
        .1
        .split_once(r#"<table class="ed-feed""#)
        .unwrap()
        .1
        .split_once("</table>")
        .unwrap()
        .0;
    let row = feed
        .split("<tr>")
        .find(|row| row.contains(">disk_pressure</td>"))
        .unwrap()
        .split_once("</tr>")
        .unwrap()
        .0;
    assert!(
        row.contains(r#"<use href="/admin/assets/icons.svg#circle-x""#)
            && row.contains(r#"aria-label="Critical""#),
        "critical feed row must show the accessible critical icon"
    );
    assert!(
        row.contains(r#"href="/admin/servers/s0""#),
        "feed row must link the affected server"
    );
    let link = html
        .split("<a ")
        .skip(1)
        .find(|link| {
            link.split_once("</a>")
                .unwrap()
                .0
                .contains("</svg>full feed")
        })
        .unwrap()
        .split_once("</a>")
        .unwrap()
        .0;
    assert!(
        link.contains(r#"href="/admin/alerts""#)
            && link.contains(r#"<use href="/admin/assets/icons.svg#arrow-right""#),
        "full feed control must carry its own arrow and alerts destination"
    );
    assert_eq!(link.split_once("</svg>").unwrap().1.trim(), "full feed");
}

#[tokio::test]
async fn dashboard_health_feed_empty_when_none() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        !html.contains("Health feed"),
        "health feed must stay hidden with zero unacked alerts"
    );
}

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
    assert!(
        html.contains("3 networks at once"),
        "abuse-summary must show the concurrency reason"
    );
}

#[tokio::test]
async fn dashboard_abuse_summary_hidden_when_no_sharing() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        !html.contains("Likely-shared subscriptions"),
        "abuse-summary must stay hidden when nothing is shared"
    );
}

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

#[tokio::test]
async fn dashboard_abuse_summary_omits_deleted_user_blank_row() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
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
    s.inv.remove_user(&UserId("ghost".into())).await.unwrap();

    let html = fetch_html(router(s), "/admin/").await;
    assert!(
        !html.contains(r#"href="/admin/users/#source-ips""#)
            && !html.contains(r#"href="/admin/users/""#),
        "abuse card must not render a blank-name (deleted-user) link"
    );
    assert!(
        !html.contains("/admin/users/ghost"),
        "a deleted user must not be flagged in the abuse card"
    );
    assert!(
        !html.contains("Likely-shared subscriptions"),
        "abuse card must stay hidden when the only high-ASN pattern is a deleted user"
    );
}

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

#[tokio::test]
async fn dashboard_tab_labels_copy_contract() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[]).await;
    let app = router(s);
    let en = fetch_html(app.clone(), "/admin/").await;
    let ru = fetch_html_with_cookie(app, "/admin/", "vpnctl_lang=ru").await;
    for (slug, icon, en_label, ru_label) in [
        ("overview", "layout-dashboard", "Overview", "Обзор"),
        ("activity", "activity", "Activity", "Активность"),
        ("sharing", "shield", "Sharing risk", "Риск расшаривания"),
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
                .split_once(&format!(r#"href="/admin/{slug}""#))
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
async fn dashboard_info_cards_headlines_match_voice() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    seed_dashboard_signals(&s.inv).await;
    let app = router(s);
    let overview = fetch_html(app.clone(), "/admin/").await;
    let activity = fetch_html(app, "/admin/activity").await;
    for (html, needle) in [
        (&overview, ">Fleet <span"),
        (&activity, "vs prior"),
        (&activity, "Kernel rollup · sing-box"),
        (&overview, "Health feed"),
        (&overview, "Likely-shared subscriptions"),
    ] {
        assert!(
            html.contains(needle),
            "dashboard headline drifted — missing: {needle:?}"
        );
    }
}

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
        (&overview, ">Флот <span"),
        (&activity, "против пред."),
        (&activity, "Версии ядер · sing-box"),
        (&overview, "Поток здоровья"),
        (&overview, "Похоже на расшаренные подписки"),
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
    for (id, healthy) in [("s0", true), ("s1", false)] {
        s.inv
            .audit("test", "server.deploy", Some(id), None)
            .await
            .unwrap();
        let target = ["192.0.2.1:443".parse().unwrap()];
        let control = ["192.0.2.1:22".parse().unwrap()];
        for minute in 1..=12 {
            let mut sample = release_quality_sample(id, minute, healthy);
            sample.ts = chrono::Utc::now();
            s.inv
                .record_service_quality_sample_for_targets(&sample, &target, &control)
                .await
                .unwrap();
        }
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
