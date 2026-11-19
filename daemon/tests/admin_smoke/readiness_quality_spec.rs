use std::net::SocketAddr;

use tempfile::TempDir;
use vpnctl_core::{ProtocolId, ServerId};
use vpnctl_inventory::{AssuranceStage, AssuranceState, ProtocolAssuranceSample};
use vpnctld::router;

use crate::common::{fetch_html, fetch_html_with_cookie, release_quality_sample, seed, state};

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

async fn udp_node(inv: &vpnctl_inventory::SqliteInventory) -> ServerId {
    seed(inv, 1, 0, &[]).await;
    let server = ServerId("s0".into());
    inv.remove_server_protocol(&server, &ProtocolId("vless+reality".into()))
        .await
        .unwrap();
    for protocol in ["amneziawg2", "hysteria2"] {
        inv.add_server_protocol(&server, &ProtocolId(protocol.into()))
            .await
            .unwrap();
    }
    server
}

fn assurance(
    server: &ServerId,
    protocol: &str,
    ts: chrono::DateTime<chrono::Utc>,
    stage: AssuranceStage,
    state: AssuranceState,
) -> ProtocolAssuranceSample {
    ProtocolAssuranceSample {
        ts,
        server_id: server.clone(),
        protocol_id: ProtocolId(protocol.into()),
        client_kind: "external-runner".into(),
        stage,
        state,
        latency_ms: None,
        failure_code: None,
    }
}

#[tokio::test]
async fn udp_availability_reports_partial_verified_coverage_on_each_admin_surface() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let server = udp_node(&s.inv).await;
    let now = chrono::Utc::now();
    for (protocol, stage, state) in [
        (
            "amneziawg2",
            AssuranceStage::Transfer,
            AssuranceState::Verified,
        ),
        (
            "hysteria2",
            AssuranceStage::ExternalPath,
            AssuranceState::Unknown,
        ),
    ] {
        s.inv
            .record_protocol_assurance_sample(&assurance(&server, protocol, now, stage, state))
            .await
            .unwrap();
    }

    let app = router(s.clone());
    for path in ["/admin/servers/s0/status", "/admin/servers", "/admin/"] {
        let page = fetch_html_with_cookie(app.clone(), path, "vpnctl_lang=en").await;
        assert!(
            page.contains(r#"data-path-status="udp_verified""#),
            "{path}"
        );
        assert!(page.contains("UDP VPN verified"), "{path}");
        assert!(page.contains("1/2 verified"), "{path}");
        assert!(!page.contains("2/2 verified"), "{path}");
    }
    let page =
        fetch_html_with_cookie(app.clone(), "/admin/servers/s0/status", "vpnctl_lang=ru").await;
    let current = section(&page, "current-path-availability");
    assert!(current.contains("VPN по UDP проверен"));
    assert!(current.contains("Проверено 1 из 2"));
    assert!(current.contains(r##"href="#protocol-assurance""##));
    assert!(!current.contains("Нет свежих данных"));
    let dashboard = fetch_html(app.clone(), "/admin/").await;
    assert!(section(&dashboard, "fleet-current-path").contains(r#"data-path-server="s0""#));

    s.inv
        .record_protocol_assurance_sample(&assurance(
            &server,
            "hysteria2",
            now,
            AssuranceStage::Transfer,
            AssuranceState::Verified,
        ))
        .await
        .unwrap();
    let dashboard = fetch_html(app, "/admin/").await;
    let summary = section(&dashboard, "fleet-current-path");
    assert!(summary.contains(r#"data-path-count="udp_verified""#));
    assert!(!summary.contains(r#"data-path-server="s0""#));
}

#[tokio::test]
async fn udp_availability_requires_fresh_transfer_and_reports_alongside_tcp_for_mixed_nodes() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let server = udp_node(&s.inv).await;
    let now = chrono::Utc::now();
    let app = router(s.clone());
    let path = "/admin/servers/s0/status";
    let no_samples = fetch_html(app.clone(), path).await;
    let current = section(&no_samples, "current-path-availability");
    assert!(current.contains(r#"data-path-status="udp_unknown""#));
    assert!(current.contains(r##"href="#external-readiness""##));

    for sample in [
        assurance(
            &server,
            "amneziawg2",
            now - chrono::TimeDelta::days(1),
            AssuranceStage::Transfer,
            AssuranceState::Verified,
        ),
        assurance(
            &server,
            "hysteria2",
            now + chrono::TimeDelta::hours(1),
            AssuranceStage::Transfer,
            AssuranceState::Verified,
        ),
        assurance(
            &server,
            "vless+reality",
            now,
            AssuranceStage::Transfer,
            AssuranceState::Verified,
        ),
        assurance(
            &server,
            "amneziawg2",
            now,
            AssuranceStage::Listener,
            AssuranceState::Verified,
        ),
    ] {
        s.inv
            .record_protocol_assurance_sample(&sample)
            .await
            .unwrap();
        let page = fetch_html(app.clone(), path).await;
        let current = section(&page, "current-path-availability");
        assert!(current.contains(r#"data-path-status="udp_unknown""#));
        assert!(!current.contains(r#"data-path-status="udp_verified""#));
    }

    s.inv
        .record_protocol_assurance_sample(&assurance(
            &server,
            "amneziawg2",
            now,
            AssuranceStage::Handshake,
            AssuranceState::Blocked,
        ))
        .await
        .unwrap();
    let page = fetch_html(app.clone(), path).await;
    let current = section(&page, "current-path-availability");
    assert!(current.contains(r#"data-path-status="udp_failed""#));
    assert!(current.contains("1 failed"));

    s.inv
        .add_server_protocol(&server, &ProtocolId("vless+reality".into()))
        .await
        .unwrap();
    let page = fetch_html(app.clone(), path).await;
    let current = section(&page, "current-path-availability");
    assert!(current.contains(r#"data-path-status="unknown""#));
    assert!(current.contains(r#"data-path-status="udp_failed""#));
    assert!(current.contains("TCP VPN ports"));

    s.inv
        .record_protocol_assurance_sample(&assurance(
            &server,
            "hysteria2",
            now,
            AssuranceStage::Transfer,
            AssuranceState::Verified,
        ))
        .await
        .unwrap();
    s.inv
        .add_server_protocol(&server, &ProtocolId("shadowsocks-2022".into()))
        .await
        .unwrap();
    s.inv
        .record_protocol_assurance_sample(&assurance(
            &server,
            "shadowsocks-2022",
            now,
            AssuranceStage::Transfer,
            AssuranceState::Verified,
        ))
        .await
        .unwrap();
    for seconds_ago in [60, 30] {
        let mut sample = release_quality_sample(&server.0, 0, false);
        sample.ts = now - chrono::TimeDelta::seconds(seconds_ago);
        sample.successes = 0;
        sample.available_targets = 0;
        sample.vantage = "fixture mixed origin".into();
        s.inv
            .record_service_path(&sample, "mixed-availability", 630)
            .await
            .unwrap();
    }

    let dashboard = fetch_html(app.clone(), "/admin/").await;
    let summary = section(&dashboard, "fleet-current-path");
    for status in ["unreachable", "udp_verified"] {
        let count = summary
            .split_once(&format!(r#"data-path-count="{status}""#))
            .unwrap()
            .1
            .split_once("</span>")
            .unwrap()
            .0;
        assert!(count.contains("<b>1</b>"), "{status}: {count}");
    }
    assert_eq!(summary.matches(r#"data-path-server="s0""#).count(), 1);
    for (path, section_id) in [
        ("/admin/", Some("fleet-at-a-glance")),
        ("/admin/servers", None),
        (path, Some("current-path-availability")),
    ] {
        let page = fetch_html(app.clone(), path).await;
        let area = section_id.map_or(page.as_str(), |id| section(&page, id));
        assert!(area.contains(r#"data-path-status="unreachable""#), "{path}");
        assert!(area.contains("fixture mixed origin"), "{path}");
        assert!(
            area.contains(r#"data-path-status="udp_verified""#),
            "{path}"
        );
        assert!(area.contains("1/2 verified"), "{path}");
        assert!(area.contains("1 failed"), "{path}");
        assert!(!area.contains("1 unverified"), "{path}");
        assert!(!area.contains("2/2 verified"), "{path}");
    }
}
