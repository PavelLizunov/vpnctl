use tempfile::TempDir;
use vpnctl_core::ServerId;
use vpnctld::router;

use crate::common::{fetch_html, seed, state};

fn section<'a>(html: &'a str, id: &str) -> &'a str {
    let marker = format!("id=\"{id}\"");
    let start = html.find(&marker).unwrap_or_else(|| panic!("missing {id}"));
    let start = html[..start].rfind("<section").expect("section opening");
    let end = html[start..].find("</section>").expect("section closing");
    &html[start..start + end]
}

#[tokio::test]
async fn deployment_fragment_is_the_same_single_status_panel() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    s.inv
        .audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    let app = router(s);

    let full = fetch_html(app.clone(), "/admin/servers/s0").await;
    let panel = section(&full, "deployment-status");
    assert!(panel.contains(r#"data-deploy-state="applied""#), "{panel}");
    assert!(panel.contains(r#"data-deploy-server="s0""#), "{panel}");
    assert!(
        panel.contains(r#"data-deploy-status-url="/admin/servers/s0?deploy_status=1""#),
        "{panel}"
    );
    assert!(panel.contains("data-deploy-generation"), "{panel}");
    assert!(panel.contains("data-deploy-stage-phase"), "{panel}");
    assert!(
        panel.contains("last success"),
        "the panel must show when the audit last confirmed application: {panel}"
    );
    assert!(
        panel.contains("not a VPN connectivity test"),
        "applied configuration must not become a connectivity claim: {panel}"
    );

    let fragment = fetch_html(app, "/admin/servers/s0?deploy_status=1").await;
    assert!(
        fragment.trim_start().starts_with("<section"),
        "status polling must return only the panel, not a full page: {fragment}"
    );
    assert!(!fragment.contains("<html"), "{fragment}");
    let fragment_panel = section(&fragment, "deployment-status");
    for needle in [
        r#"data-deploy-state="applied""#,
        r#"data-deploy-server="s0""#,
        r#"data-deploy-status-url="/admin/servers/s0?deploy_status=1""#,
        "data-deploy-generation",
        "last success",
    ] {
        assert!(
            fragment_panel.contains(needle),
            "fragment panel lost {needle}: {fragment_panel}"
        );
    }
}

#[tokio::test]
async fn deployment_panel_reports_running_operation_without_claiming_applied() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let mut server = s
        .inv
        .get_server(&ServerId("s0".into()))
        .await
        .unwrap()
        .unwrap();
    server.id = ServerId("panel-running".into());
    s.inv.add_server(&server).await.unwrap();
    s.inv
        .audit("admin", "server.deploy", Some(&server.id.0), None)
        .await
        .unwrap();
    let _guard = vpnctld::wizard_bootstrap::DeployGuard::try_acquire(&server.id.0)
        .expect("hold the operation lock to simulate another tab's deploy");

    let app = router(s);
    let html = fetch_html(app, &format!("/admin/servers/{}", server.id.0)).await;
    let panel = section(&html, "deployment-status");
    assert!(panel.contains(r#"data-deploy-state="running""#), "{panel}");
    assert!(
        panel.contains(r#"data-deploy-can-start="false""#),
        "{panel}"
    );
    assert!(
        panel.contains("another node operation is in progress"),
        "a held operation lock must be reported as running, not applied: {panel}"
    );
    assert!(
        !panel.contains(r#"data-deploy-state="applied""#),
        "running must not be conflated with applied: {panel}"
    );
}

#[tokio::test]
async fn deployment_panel_keeps_saved_changes_distinct_from_success() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);

    let html = fetch_html(app, "/admin/servers/s0").await;
    let panel = section(&html, "deployment-status");
    assert!(panel.contains(r#"data-deploy-state="pending""#), "{panel}");
    assert!(
        panel.contains("Older config may still be active"),
        "pending saved changes must explain the active-config risk: {panel}"
    );
    assert!(
        !panel.contains(r#"data-deploy-state="applied""#),
        "saved changes must not be reported as applied without a successful audit: {panel}"
    );
    assert!(
        panel.contains(r#"data-deploy-pending="pending""#),
        "the saved-configuration row must stay pending independently of the operation state: {panel}"
    );
}

#[tokio::test]
async fn neighbouring_node_failure_does_not_leak_into_this_panel() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let mut neighbour = s
        .inv
        .get_server(&ServerId("s0".into()))
        .await
        .unwrap()
        .unwrap();
    neighbour.id = ServerId("s0-neighbour".into());
    s.inv.add_server(&neighbour).await.unwrap();
    s.inv
        .audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    s.inv
        .audit(
            "admin",
            "server.deploy.failed",
            Some("s0-neighbour"),
            Some(&serde_json::json!({
                "ssh_errors": ["neighbour-only failure"],
            })),
        )
        .await
        .unwrap();
    let app = router(s);

    let html = fetch_html(app, "/admin/servers/s0").await;
    let panel = section(&html, "deployment-status");
    assert!(panel.contains(r#"data-deploy-state="applied""#), "{panel}");
    assert!(
        !panel.contains("neighbour-only failure"),
        "another node's failure must not leak into this server: {panel}"
    );
}

#[tokio::test]
async fn stale_failure_cannot_mask_a_later_successful_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    s.inv
        .audit(
            "admin",
            "server.deploy.failed",
            Some("s0"),
            Some(&serde_json::json!({
                "ssh_errors": ["synthetic previous failure"],
            })),
        )
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    s.inv
        .audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    let app = router(s);

    let html = fetch_html(app, "/admin/servers/s0").await;
    let panel = section(&html, "deployment-status");
    assert!(panel.contains(r#"data-deploy-state="applied""#), "{panel}");
    assert!(
        !panel.contains("synthetic previous failure"),
        "an older failure must not surface as the current error: {panel}"
    );
    assert!(
        !panel.contains(r#"data-deploy-state="failed""#),
        "a stale failure must not mask a later success: {panel}"
    );
}
