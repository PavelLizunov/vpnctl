use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality};
use vpnctld::AppState;

pub(crate) async fn state(dir: &TempDir) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::AmneziaWg::new()))
        .unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::Hysteria2::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::Shadowsocks2022::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::WireGuard::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::AmneziaWg2::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::AmneziaWg3::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::AnyTls::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::Trojan::new()))
        .unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::Caddy::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::Naive::new()))
        .unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::Xray::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::VlessWs::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::VlessXhttp::new()))
        .unwrap();
    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

pub(crate) async fn seed(
    inv: &SqliteInventory,
    n_servers: usize,
    n_users: usize,
    grant_pairs: &[(usize, usize)],
) {
    for i in 0..n_servers {
        let id = ServerId(format!("s{i}"));
        inv.add_server(&Server {
            id,
            address: format!("10.0.0.{i}"),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    }
    for i in 0..n_users {
        let id = UserId(format!("u{i}"));
        inv.add_user(&User {
            id,
            uuid: format!("00000000-0000-0000-0000-{i:012}"),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    }
    for (u, s) in grant_pairs {
        inv.grant(&UserId(format!("u{u}")), &ServerId(format!("s{s}")))
            .await
            .unwrap();
    }
}

pub(crate) async fn fetch_html(app: axum::Router, path: &str) -> String {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200 from {path}, got {:?}",
        resp.status()
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub(crate) async fn fetch_html_with_cookie(app: axum::Router, path: &str, cookie: &str) -> String {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(path)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200 from {path}, got {:?}",
        resp.status()
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

pub(crate) fn assert_summary_stat(html: &str, value: &str, label: &str) {
    let needle = format!("<b>{value}</b> {label}");
    assert!(
        html.contains(&needle),
        "summary stat '{value} {label}' not found (looked for {needle:?})"
    );
}

pub(crate) const TEST_NINITUX_DEVICE_ID: &str = "a92b915032b48a2ed45ef72f4171e5f4";

pub(crate) fn mk_user(id: &str, disabled: bool) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("uuid-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled,
    }
}

pub(crate) const SAME_ORIGIN_HOST: &str = "test.example";

pub(crate) fn add_same_origin(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.header("host", SAME_ORIGIN_HOST)
        .header("origin", format!("http://{SAME_ORIGIN_HOST}"))
}

pub(crate) fn naive_server(id: &str) -> vpnctl_core::Server {
    vpnctl_core::Server {
        id: vpnctl_core::ServerId(id.into()),
        address: "203.0.113.5".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("caddy".into())],
        enabled_protocols: vec![vpnctl_core::ProtocolId("naive".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

pub(crate) async fn body_of(
    app: axum::Router,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: Option<&str>,
) -> String {
    let mut req = Request::builder().method(method).uri(path);
    req = add_same_origin(req);
    if let Some(ct) = content_type {
        req = req.header("content-type", ct);
    }
    let body = match body {
        Some(s) => Body::from(s.to_string()),
        None => Body::empty(),
    };
    let resp = app.oneshot(req.body(body).unwrap()).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).expect("response body must be utf-8")
}

pub(crate) async fn enqueue_one_and_drain(
    s: &vpnctld::AppState,
    user_id: &str,
    ip: &str,
    device_class: Option<&str>,
) {
    let (tx, mut writer) = vpnctld::access_log::spawn_writer(s.inv.clone());
    assert!(vpnctld::access_log::try_enqueue(
        &tx,
        vpnctld::access_log::AccessLogRecord {
            user_id: vpnctl_core::UserId(user_id.to_string()),
            ip: ip.to_string(),
            ua: device_class.map(str::to_owned),
            status: 200,
            bytes: 0,
            accept_language: None,
            http_version: Some("HTTP/1.1".to_string()),
            device_class: device_class.map(str::to_owned),
            geo_country: None,
            geo_asn: None,
            tls_ja3: None,
            tls_ja4: None,
        },
    ));
    drop(tx);
    match tokio::time::timeout(std::time::Duration::from_secs(10), &mut writer).await {
        Ok(result) => result.expect("access-log writer must finish without panic"),
        Err(_) => {
            writer.abort();
            let _ = writer.await;
            panic!("access-log writer did not drain within 10 seconds");
        }
    }
}

pub(crate) async fn seed_dashboard_signals(inv: &SqliteInventory) {
    inv.record_node_health(
        &ServerId("s0".into()),
        Some(true),
        Some(true),
        Some(4096),
        Some(20480),
        Some(2048),
        Some(8192),
        Some(120),
        Some(r#"["tcp/443","udp/8443"]"#),
        Some(1_048_576),
        Some(r#"{"sing-box":"1.13.12","caddy":"2.8.4"}"#),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();

    inv.insert_alert(
        "disk_pressure",
        Some(&ServerId("s0".into())),
        "critical",
        "disk above 90% on s0",
        None,
    )
    .await
    .unwrap();

    inv.audit("admin", "user.create", Some("u0"), None)
        .await
        .unwrap();

    for (ip, asn, cc) in [
        ("203.0.113.10", "AS1111", "US"),
        ("198.51.100.20", "AS2222", "DE"),
        ("192.0.2.30", "AS3333", "RU"),
    ] {
        inv.log_sub_access_rich(
            &UserId("u0".into()),
            ip,
            Some("curl/8.0"),
            200,
            1024,
            None,
            Some("HTTP/2"),
            None,
            Some(cc),
            Some(asn),
            None,
            None,
        )
        .await
        .unwrap();
    }

    inv.record_user_ip_concurrency(&[(UserId("u0".into()), 3)])
        .await
        .unwrap();
}

pub(crate) fn pr_user_conn(src_ip: &str, src_port: &str) -> vpnctld::clash_api::Connection {
    vpnctld::clash_api::Connection {
        id: format!("c-{src_ip}-{src_port}"),
        upload: 10,
        download: 20,
        start: "2026-06-14T18:00:00Z".into(),
        metadata: vpnctld::clash_api::ConnectionMeta {
            network: "tcp".into(),
            destination_ip: "1.2.3.4".into(),
            destination_port: "443".into(),
            source_ip: src_ip.into(),
            source_port: src_port.into(),
            host: String::new(),
            user: None,
        },
    }
}

pub(crate) async fn wait_for_autodeploy_rows(
    inv: &SqliteInventory,
    n: usize,
) -> Vec<vpnctl_inventory::AuditEntry> {
    for _ in 0..200 {
        let rows: Vec<_> = inv
            .recent_audit(200)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.action == "user.autodeploy" || e.action == "server.autodeploy")
            .collect();
        if rows.len() >= n {
            return rows;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {n} autodeploy audit row(s)");
}

pub(crate) async fn count_autodeploy_rows(inv: &SqliteInventory) -> usize {
    inv.recent_audit(200)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.action == "user.autodeploy" || e.action == "server.autodeploy")
        .count()
}

pub(crate) fn reality_naive_server(id: &str) -> vpnctl_core::Server {
    vpnctl_core::Server {
        id: vpnctl_core::ServerId(id.into()),
        address: "203.0.113.9".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![
            vpnctl_core::KernelId("caddy".into()),
            vpnctl_core::KernelId("sing-box".into()),
        ],
        enabled_protocols: vec![
            vpnctl_core::ProtocolId("naive".into()),
            vpnctl_core::ProtocolId("vless+reality".into()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

pub(crate) fn release_quality_sample(
    server_id: &str,
    minute: i64,
    available: bool,
) -> vpnctl_inventory::ServiceQualitySample {
    vpnctl_inventory::ServiceQualitySample {
        ts: chrono::Utc::now() - chrono::Duration::minutes(minute),
        server_id: ServerId(server_id.into()),
        vantage: "vpnctld control host".into(),
        target_count: 1,
        available_targets: u32::from(available),
        attempts: 3,
        successes: if available { 3 } else { 0 },
        tcp_rtt_ms: if available { vec![20, 21, 22] } else { vec![] },
        control_attempts: 3,
        control_successes: 3,
        control_rtt_ms: vec![5, 6, 7],
        icmp_attempts: None,
        icmp_successes: None,
        icmp_rtt_ms: None,
    }
}
