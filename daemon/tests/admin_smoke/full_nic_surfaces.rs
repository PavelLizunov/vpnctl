use super::common::*;
use tempfile::TempDir;
use vpnctl_core::ServerId;
use vpnctl_inventory::{ServerTrafficLimit, VpnStatsDelta};
use vpnctld::router;

#[tokio::test]
async fn full_nic_totals_match_main_activity_and_server_without_coefficients_or_attribution() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(dir.path().join("inv.db")),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE servers SET usage_coefficient=7")
        .execute(&pool)
        .await
        .unwrap();
    let sid = ServerId("s0".into());
    seed_nic_traffic(&s.inv, &sid, 3 << 30, 2 << 30).await;
    seed_nic_traffic(&s.inv, &ServerId("s1".into()), 7 << 30, 0).await;
    s.inv
        .record_vpn_stats(
            &sid,
            &[VpnStatsDelta {
                user_id: None,
                upload_bytes: 100,
                download_bytes: 200,
                active_connections: 99,
            }],
        )
        .await
        .unwrap();
    s.inv
        .set_server_traffic_limit(
            &sid,
            Some(&ServerTrafficLimit {
                limit_bytes: 10 << 30,
                direction: "tx".into(),
                reset_day: 1,
                warning_pct: 80,
            }),
            "spec",
        )
        .await
        .unwrap();
    let app = router(s);
    for path in [
        "/admin/",
        "/admin/overview",
        "/admin/activity",
        "/admin/sharing",
    ] {
        let html = fetch_html(app.clone(), path).await;
        let fleet = html
            .split_once("id=\"fleet-at-a-glance\"")
            .unwrap()
            .1
            .split_once("</section>")
            .unwrap()
            .0;
        assert!(
            fleet.contains("5.0 GiB") && fleet.contains("7.0 GiB"),
            "{path}"
        );
        assert!(
            !fleet.contains("35.0 GiB") && !fleet.contains("300 B"),
            "{path}"
        );
        assert!(fleet.contains("partial coverage"));
    }
    let activity = fetch_html(app.clone(), "/admin/activity").await;
    let nic = activity.split_once("data-source=\"nic\"").unwrap().1;
    assert!(nic.contains("12.0 GiB"));
    assert!(nic.contains("Full NIC traffic chart"));
    let server = fetch_html(app, "/admin/servers/s0/activity").await;
    let chart = server.split_once("id=\"server-traffic\"").unwrap().1;
    assert!(chart.contains("5.0 GiB") && !chart.contains("35.0 GiB"));
    assert!(
        server.contains("Observed: 5.0 GiB"),
        "monthly headline must remain full RX+TX even when quota charges TX only"
    );
    assert!(server.contains("Chargeable usage: 2.0 GiB"));
}

#[tokio::test]
async fn measured_zero_and_missing_nodes_are_distinct_on_main_and_activity() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    seed_nic_traffic(&s.inv, &ServerId("s0".into()), 0, 0).await;
    let app = router(s);
    let main = fetch_html(app.clone(), "/admin/").await;
    assert!(main.contains("0 B"));
    let activity = fetch_html(app, "/admin/activity").await;
    let nic = activity.split_once("data-source=\"nic\"").unwrap().1;
    assert!(nic.contains("Measured nodes: 1 / 2"));
    assert!(nic.contains("0 B") && nic.contains("unavailable") && nic.contains("partial coverage"));
    assert!(nic.contains("/admin/servers/s1/activity"));
    assert!(
        !nic.contains("No NIC observations."),
        "measured zero has observations"
    );
}

#[tokio::test]
async fn each_history_window_uses_its_own_full_nic_deltas_including_retained_history() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(dir.path().join("inv.db")),
    )
    .await
    .unwrap();
    let now = chrono::Utc::now();
    for (n, hours, rx) in [
        (0, 35 * 24, 100),
        (1, 10 * 24, 200),
        (2, 6 * 24, 500),
        (3, 12, 900),
        (4, 0, 1200),
    ] {
        sqlx::query("INSERT INTO node_health(sample_id,server_id,ts,nic_iface,nic_rx_bytes,nic_tx_bytes) VALUES(?1,'s0',?2,'eth0',?3,0)")
            .bind(format!("nic-{n}")).bind((now-chrono::Duration::hours(hours)).to_rfc3339()).bind(rx).execute(&pool).await.unwrap();
    }
    let app = router(s);
    for (slug, amount) in [
        ("24h", "300 B"),
        ("7d", "700 B"),
        ("30d", "1000 B"),
        ("all", "1.1 KiB"),
    ] {
        for base in ["/admin/activity", "/admin/servers/s0/activity"] {
            let html = fetch_html(app.clone(), &format!("{base}?vpn_window={slug}")).await;
            let nic = html.split_once("data-source=\"nic\"").unwrap().1;
            assert!(nic.contains(amount), "{base} {slug}: expected {amount}");
            assert!(nic.contains("Full NIC traffic chart") && nic.contains("partial coverage"));
        }
    }
}
