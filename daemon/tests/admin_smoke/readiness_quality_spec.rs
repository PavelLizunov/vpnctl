//! Independent black-box regressions from deploy-readiness-quality.md and the
//! approved public UI/API contract; implementation source was not consulted.

use std::net::SocketAddr;

use tempfile::TempDir;
use vpnctl_core::{ProtocolId, ServerId};
use vpnctl_inventory::{AssuranceStage, AssuranceState, ProtocolAssuranceSample};
use vpnctld::router;

use crate::common::{fetch_html, fetch_html_with_cookie, release_quality_sample, seed, state};

// These section IDs are the public semantic contract, not whole-page snapshots.
fn section<'a>(html: &'a str, id: &str) -> &'a str {
    let marker = format!("id=\"{id}\"");
    let start = html.find(&marker).unwrap_or_else(|| panic!("missing {id}"));
    let start = html[..start].rfind("<section").expect("section opening");
    let end = html[start..].find("</section>").expect("section closing");
    &html[start..start + end]
}

fn assert_unknown(text: &str) {
    let text = text.to_lowercase();
    assert!(
        text.contains("unknown")
            || text.contains("not measured")
            || text.contains("no measurements"),
        "missing explicit unknown/not-measured state: {text}"
    );
}

fn fail_pending_queries(dir: &TempDir) {
    // Existing smoke suites use Python's sqlite3 for disposable DB fault
    // injection. This approved fault affects only this test's own inventory.
    let status = std::process::Command::new("python3")
        .args([
            "-c",
            "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DROP TABLE audit_log'); c.commit(); c.close()",
        ])
        .arg(dir.path().join("inv.db"))
        .status()
        .unwrap();
    assert!(
        status.success(),
        "temporary inventory fault injection failed"
    );
}

#[tokio::test]
async fn failed_deployment_query_is_unknown_on_every_server_tab() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .audit("spec", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    fail_pending_queries(&dir);
    assert!(
        s.inv
            .server_pending_deploy(&ServerId("s0".into()))
            .await
            .is_err()
    );
    let app = router(s);
    for tab in ["status", "activity", "protocols", "grants", "setup"] {
        let html = fetch_html(app.clone(), &format!("/admin/servers/s0/{tab}")).await;
        let deployment = section(&html, "deployment-status");
        assert!(
            deployment.contains("data-deploy-state=\"unknown\""),
            "{tab}: {deployment}"
        );
        assert_unknown(deployment);
        assert!(!deployment.contains("data-deploy-state=\"applied\""));
    }
}

#[tokio::test]
async fn failed_grant_deployment_query_never_claims_on_node_or_all_applied() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .audit("spec", "user.grant", Some("u0"), None)
        .await
        .unwrap();
    s.inv
        .audit("spec", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    fail_pending_queries(&dir);
    let app = router(s);
    for path in ["/admin/users/u0/access", "/admin/servers/s0/grants"] {
        let html = fetch_html(app.clone(), path).await;
        let status = if path == "/admin/users/u0/access" {
            html.split("<tr")
                .find(|row| row.contains("/admin/users/u0/grants/s0/revoke"))
                .expect("granted server row")
                .split_once("</tr>")
                .expect("grant row closing")
                .0
        } else {
            section(&html, "deployment-status")
        };
        assert_unknown(status);
        for claim in [">on node<", "all applied", "deployed config covers"] {
            assert!(
                !status.to_lowercase().contains(claim),
                "{path}: failed query must not claim {claim}"
            );
        }
    }
}

#[tokio::test]
async fn unprovisioned_server_with_failure_history_has_unknown_quality() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    for minute in 1..=12 {
        s.inv
            .record_service_quality_sample(&release_quality_sample("s0", minute, false))
            .await
            .unwrap();
    }
    let html = fetch_html(router(s.clone()), "/admin/servers/s0").await;
    let quality = section(&html, "server-quality");
    assert_unknown(quality);
    assert!(
        !quality.contains("0/100"),
        "unprovisioned is not a measured failing service"
    );
    assert!(
        !quality.contains("100/100"),
        "unprovisioned is not a measured healthy service"
    );
    assert_eq!(
        s.inv
            .service_quality_samples_for_server(&ServerId("s0".into()), 24)
            .await
            .unwrap()
            .len(),
        12,
        "rendering unknown must not delete historical evidence"
    );
}

#[tokio::test]
async fn applied_configuration_without_external_evidence_is_explicitly_not_checked() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    s.inv
        .audit("spec", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    let app = router(s);
    for (cookie, unchecked) in [
        ("vpnctl_lang=en", "not checked"),
        ("vpnctl_lang=ru", "не проверено"),
    ] {
        let html = fetch_html_with_cookie(app.clone(), "/admin/servers/s0", cookie).await;
        let deployment = section(&html, "deployment-status");
        assert!(deployment.contains("data-deploy-state=\"applied\""));
        let external = section(&html, "external-readiness").to_lowercase();
        assert!(
            external.contains(unchecked),
            "missing external-evidence warning: {external}"
        );
    }
}

#[tokio::test]
async fn applied_config_does_not_override_blocked_external_assurance() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    s.inv
        .audit("spec", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    s.inv
        .record_protocol_assurance_sample(&ProtocolAssuranceSample {
            ts: chrono::Utc::now(),
            server_id: ServerId("s0".into()),
            protocol_id: ProtocolId("vless+reality".into()),
            client_kind: "external-runner".into(),
            stage: AssuranceStage::Handshake,
            state: AssuranceState::Blocked,
            latency_ms: None,
            failure_code: Some("connection_refused".into()),
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0").await;
    assert!(section(&html, "deployment-status").contains("data-deploy-state=\"applied\""));
    let external = section(&html, "external-readiness").to_lowercase();
    assert!(
        external.contains("blocked")
            || external.contains("failed")
            || external.contains("not verified"),
        "blocked external evidence must not become success: {external}"
    );
    assert!(
        !external.contains(">verified<"),
        "blocked handshake is not verified VPN readiness"
    );
}

#[tokio::test]
async fn measured_tcp_failure_label_is_not_packet_loss_and_has_context() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    s.inv
        .audit("spec", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    let targets = [SocketAddr::from(([192, 0, 2, 10], 443))];
    let controls = [SocketAddr::from(([192, 0, 2, 10], 22))];
    for _ in 0..12 {
        let mut sample = release_quality_sample("s0", 0, false);
        sample.vantage = "spec-test control vantage".into();
        s.inv
            .record_service_quality_sample_for_targets(&sample, &targets, &controls)
            .await
            .unwrap();
    }
    let app = router(s);
    for (cookie, label) in [
        ("vpnctl_lang=en", "TCP connection failures"),
        ("vpnctl_lang=ru", "Неудачные TCP-подключения"),
    ] {
        let html = fetch_html_with_cookie(app.clone(), "/admin/servers/s0", cookie).await;
        let quality = section(&html, "server-quality");
        assert!(
            quality.contains(label),
            "TCP metric label missing: {quality}"
        );
        assert!(
            quality.contains("spec-test control vantage"),
            "measurement vantage must be visible"
        );
        let lower = quality.to_lowercase();
        assert!(
            !lower.contains("packet loss"),
            "TCP connect failures are not packet loss"
        );
        assert!(
            !lower.contains("потери пакетов"),
            "TCP failures must not be labeled packet loss in RU"
        );
        assert!(
            lower.contains("24h")
                || lower.contains("24 h")
                || lower.contains("24ч")
                || lower.contains("24 ч"),
            "quality must identify its rolling window: {quality}"
        );
        assert!(
            lower.contains("checked")
                || lower.contains("check time")
                || lower.contains("провер")
                || lower.contains("замер"),
            "quality must identify the check time: {quality}"
        );
    }
}
