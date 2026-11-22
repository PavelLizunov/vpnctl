//! Independent HTTP contract tests for the server deployment status fragment.
//!
//! Contract under test:
//! `GET /admin/servers/{sid}?deploy_status=1` returns an HTML fragment for only
//! that node (no page shell, no scripts) exposing `#deployment-status` with
//! `data-deploy-state` and, when relevant, `data-deploy-error`. Reopening the
//! fragment after many newer deploy audit rows on a similarly named node must
//! still report that node's own latest state. A later successful deploy makes
//! the state applied when nothing else is pending. An unknown node is 404.
//!
//! Fixtures use the existing audited deploy actions and payload shape:
//! `server.deploy.failed` with `{"ssh_errors": [...]}` and `server.deploy`.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::ServerId;
use vpnctl_inventory::SqliteInventory;
use vpnctld::router;

use crate::common::{fetch_html, seed, state};

const DEPLOYED: &str = "server.deploy";
const DEPLOY_FAILED: &str = "server.deploy.failed";

/// Extract the `#deployment-status` section from a full page or a fragment.
///
/// The contract fixes the id, not the tag that carries it, so walk back to the
/// enclosing `<section>` like the existing readiness tests do.
fn panel(html: &str) -> &str {
    let marker = "id=\"deployment-status\"";
    let at = html
        .find(marker)
        .unwrap_or_else(|| panic!("missing #{marker}: {html}"));
    let start = html[..at].rfind("<section").expect("panel section opening");
    let end = html[start..]
        .find("</section>")
        .expect("panel section closing");
    &html[start..start + end]
}

async fn record_failure(inv: &SqliteInventory, server: &str, marker: &str) {
    inv.audit(
        "spec",
        DEPLOY_FAILED,
        Some(server),
        Some(&serde_json::json!({ "ssh_errors": [marker] })),
    )
    .await
    .unwrap();
}

async fn record_success(inv: &SqliteInventory, server: &str) {
    inv.audit("spec", DEPLOYED, Some(server), None)
        .await
        .unwrap();
}

fn assert_no_page_shell(fragment: &str) {
    let lower = fragment.to_ascii_lowercase();
    for shell in ["<!doctype", "<html", "<head>", "<head ", "<body", "<script"] {
        assert!(
            !lower.contains(shell),
            "deploy status fragment must not contain {shell}: {fragment}"
        );
    }
}

#[tokio::test]
async fn fragment_carries_only_the_requested_nodes_panel_without_page_shell() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    record_failure(&s.inv, "s0", "qol-fragment-s0-failure").await;
    record_failure(&s.inv, "s1", "qol-fragment-s1-failure").await;

    let fragment = fetch_html(router(s), "/admin/servers/s0?deploy_status=1").await;

    assert!(
        fragment.trim_start().starts_with("<section"),
        "status polling must return a panel fragment, not a page: {fragment}"
    );
    assert_no_page_shell(&fragment);

    let panel = panel(&fragment);
    assert!(panel.contains(r#"id="deployment-status""#));
    assert!(panel.contains(r#"data-deploy-server="s0""#));
    assert!(
        panel.contains(r#"data-deploy-state="failed""#),
        "s0's latest audited deploy failure must render: {panel}"
    );
    assert!(
        panel.contains("qol-fragment-s0-failure"),
        "the failed node's recorded error must be shown: {panel}"
    );
    assert!(
        !panel.contains("qol-fragment-s1-failure"),
        "another node's failure leaked into s0's panel: {panel}"
    );
    assert!(
        !panel.contains(r#"data-deploy-server="s1""#),
        "the fragment must not render another node: {panel}"
    );
}

#[tokio::test]
async fn reopening_keeps_failure_after_many_newer_deploys_on_a_similar_node() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;

    // A similarly named node makes a bare prefix / unfiltered "latest rows"
    // query select the wrong history.
    let mut shadow = s
        .inv
        .get_server(&ServerId("s0".into()))
        .await
        .unwrap()
        .unwrap();
    shadow.id = ServerId("s0-shadow".into());
    shadow.address = "10.0.0.99".into();
    s.inv.add_server(&shadow).await.unwrap();

    record_failure(&s.inv, "s0", "qol-original-failure").await;
    let app = router(s.clone());
    let first = fetch_html(app.clone(), "/admin/servers/s0?deploy_status=1").await;
    assert!(
        panel(&first).contains(r#"data-deploy-state="failed""#),
        "initial open must show s0's failure"
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    // 21 newer deploy rows on the similar node: one failure plus 20 later
    // successes, so the similar node itself ends applied while a 20-row global
    // window would lose s0's older failure.
    record_failure(&s.inv, "s0-shadow", "qol-shadow-failure").await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    for _ in 0..20 {
        record_success(&s.inv, "s0-shadow").await;
    }

    let reopened = fetch_html(app.clone(), "/admin/servers/s0?deploy_status=1").await;
    let reopened_panel = panel(&reopened);
    assert!(
        reopened_panel.contains(r#"data-deploy-state="failed""#),
        "21 newer deploys on a similar node must not hide s0's failure: {reopened_panel}"
    );
    assert!(
        reopened_panel.contains("qol-original-failure"),
        "reopening must still surface s0's own recorded error: {reopened_panel}"
    );
    assert!(
        !reopened_panel.contains("qol-shadow-failure"),
        "the similar node's failure leaked into s0's panel: {reopened_panel}"
    );
    assert!(
        !reopened_panel.contains(r#"data-deploy-state="applied""#),
        "another node's success must not turn s0 into applied: {reopened_panel}"
    );
    assert!(
        !reopened_panel.contains(r#"data-deploy-server="s0-shadow""#),
        "the s0 fragment must stay scoped to s0: {reopened_panel}"
    );

    let shadow_fragment = fetch_html(app, "/admin/servers/s0-shadow?deploy_status=1").await;
    let shadow_panel = panel(&shadow_fragment);
    assert!(
        shadow_panel.contains(r#"data-deploy-state="applied""#),
        "the similar node's own 21 deploy audits must be visible as applied: {shadow_panel}"
    );
    assert!(
        !shadow_panel.contains("qol-original-failure"),
        "s0's failure leaked into the similar node's panel: {shadow_panel}"
    );
    assert!(
        !shadow_panel.contains("qol-shadow-failure"),
        "the similar node's older failure must be cleared by its later successes: {shadow_panel}"
    );
}

#[tokio::test]
async fn later_success_makes_the_fragment_applied_when_nothing_is_pending() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    record_failure(&s.inv, "s0", "qol-stale-failure").await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    record_success(&s.inv, "s0").await;

    let fragment = fetch_html(router(s), "/admin/servers/s0?deploy_status=1").await;
    let panel = panel(&fragment);

    assert!(
        panel.contains(r#"data-deploy-state="applied""#),
        "a later successful deploy must become applied: {panel}"
    );
    assert!(
        !panel.contains(r#"data-deploy-state="failed""#),
        "the older failure must not mask the later success: {panel}"
    );
    assert!(
        !panel.contains("qol-stale-failure"),
        "the older failure's error text must be gone: {panel}"
    );
}

#[tokio::test]
async fn missing_node_fragment_is_a_404() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;

    let status = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/servers/missing-node?deploy_status=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();

    assert_eq!(status, StatusCode::NOT_FOUND);
}
