use tempfile::TempDir;
use vpnctl_inventory::SqliteInventory;
use vpnctld::router;

use super::common::{
    fetch_html, fetch_html_with_cookie, release_quality_sample, seed, seed_dashboard_signals, state,
};

async fn rounds(inv: &SqliteInventory, server: &str, observations: &[(i64, u32)]) {
    for &(seconds_ago, successes) in observations {
        let mut sample = release_quality_sample(server, 0, false);
        sample.ts = chrono::Utc::now() - chrono::Duration::seconds(seconds_ago);
        sample.successes = successes;
        sample.available_targets = u32::from(successes == 3);
        sample.vantage = "fixture <network>".into();
        inv.record_service_path(&sample, "fixture-current-path", 630)
            .await
            .unwrap();
    }
}

fn summary(html: &str) -> &str {
    html.split_once("id=\"fleet-current-path\"")
        .unwrap()
        .1
        .split_once("</section>")
        .unwrap()
        .0
}

fn assert_count(section: &str, status: &str, count: usize) {
    let item = section
        .split_once(&format!("data-path-count=\"{status}\""))
        .unwrap()
        .1
        .split_once("</span>")
        .unwrap()
        .0;
    assert!(item.contains(&format!("<b>{count}</b>")), "{item}");
}

#[tokio::test]
async fn current_availability_precedes_fleet_and_links_problems_in_priority_order() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 6, 1, &[(0, 0)]).await;
    rounds(&s.inv, "s0", &[(60, 0), (30, 0)]).await;
    rounds(&s.inv, "s1", &[(30, 1)]).await;
    rounds(&s.inv, "s2", &[(90, 0), (60, 0), (30, 3)]).await;
    rounds(&s.inv, "s3", &[(30, 3)]).await;
    rounds(&s.inv, "s4", &[(3600, 3)]).await;
    seed_dashboard_signals(&s.inv).await;
    let app = router(s);
    for path in [
        "/admin/",
        "/admin/overview",
        "/admin/activity",
        "/admin/sharing",
    ] {
        let html = fetch_html(app.clone(), path).await;
        assert!(html.find("fleet-current-path").unwrap() < html.find("fleet-at-a-glance").unwrap());
        let panel = summary(&html);
        for (status, count) in [
            ("unreachable", 1),
            ("degraded", 1),
            ("recovering", 1),
            ("unknown", 2),
            ("available", 1),
        ] {
            assert_count(panel, status, count);
        }
        for pair in [0, 1, 2, 4, 5].windows(2) {
            assert!(
                panel
                    .find(&format!("data-path-server=\"s{}\"", pair[0]))
                    .unwrap()
                    < panel
                        .find(&format!("data-path-server=\"s{}\"", pair[1]))
                        .unwrap()
            );
        }
        assert!(!panel.contains("data-path-server=\"s3\""));
        assert!(panel.contains("/admin/servers/s0/status#current-path-availability"));
        assert!(panel.contains("fixture &lt;network&gt;") && !panel.contains("fixture <network>"));
        assert!(panel.contains("TCP results show port reachability"));
        assert!(panel.contains("UDP-only servers show results from external VPN client tests"));
        let fleet = html.split_once("id=\"fleet-at-a-glance\"").unwrap().1;
        let row = fleet
            .split("<tr>")
            .find(|row| row.contains("href=\"/admin/servers/s0\""))
            .unwrap()
            .split_once("</tr>")
            .unwrap()
            .0;
        assert!(row.contains(">up</span>") && row.contains("data-path-status=\"unreachable\""));
        assert!(row.contains("TCP unreachable") && row.contains("fixture &lt;network&gt;"));
    }
}

#[tokio::test]
async fn failed_path_reads_show_unknown_in_summary_and_fleet_without_green_claims() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    rounds(&s.inv, "s0", &[(30, 3)]).await;
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(dir.path().join("inv.db")),
    )
    .await
    .unwrap();
    sqlx::query("DROP TABLE service_path_states")
        .execute(&pool)
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/").await;
    let panel = summary(&html);
    assert_count(panel, "unknown", 1);
    assert_count(panel, "available", 0);
    assert!(panel.contains("Unknown / stale"));
    let fleet = html
        .split_once("id=\"fleet-at-a-glance\"")
        .unwrap()
        .1
        .split_once("</section>")
        .unwrap()
        .0;
    assert!(fleet.contains("data-path-status=\"unknown\""));
    assert!(!fleet.contains("data-path-status=\"available\""));
}

#[tokio::test]
async fn main_dashboard_empty_state_and_russian_scope_are_pinned() {
    let dir = TempDir::new().unwrap();
    let html = fetch_html(router(state(&dir).await), "/admin/").await;
    let panel = summary(&html);
    assert!(panel.contains("Availability now"));
    assert!(panel.contains("No servers to monitor."));
    assert!(panel.contains("href=\"/admin/servers/new\"") && panel.contains("Add server"));
    let ru_dir = TempDir::new().unwrap();
    let s = state(&ru_dir).await;
    let html = fetch_html_with_cookie(router(s), "/admin/", "vpnctl_lang=ru").await;
    let panel = summary(&html);
    assert!(panel.contains("Доступность сейчас"));
    assert!(panel.contains("Два неудачных раунда подтверждают отказ"));
    assert!(panel.contains(
        "Для серверов только с UDP-протоколами показаны результаты внешних подключений к VPN"
    ));
}

#[tokio::test]
async fn dashboard_rendering_does_not_change_detector_or_audit_history() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    rounds(&s.inv, "s0", &[(60, 0), (30, 0)]).await;
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(dir.path().join("inv.db")),
    )
    .await
    .unwrap();
    let before: String = sqlx::query_scalar("SELECT json_array((SELECT state_json FROM service_path_states), (SELECT incident_json FROM service_path_incidents), (SELECT COUNT(*) FROM audit_log), (SELECT COUNT(*) FROM admin_alerts))").fetch_one(&pool).await.unwrap();
    let app = router(s);
    for path in ["/admin/", "/admin/overview", "/admin/"] {
        let html = fetch_html(app.clone(), path).await;
        assert_count(summary(&html), "unreachable", 1);
    }
    let after: String = sqlx::query_scalar("SELECT json_array((SELECT state_json FROM service_path_states), (SELECT incident_json FROM service_path_incidents), (SELECT COUNT(*) FROM audit_log), (SELECT COUNT(*) FROM admin_alerts))").fetch_one(&pool).await.unwrap();
    assert_eq!(before, after);
}
