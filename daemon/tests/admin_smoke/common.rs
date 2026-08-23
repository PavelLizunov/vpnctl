//! Shared test fixtures and helpers for admin smoke tests.

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
use vpnctld::{AppState, router};

pub(crate) async fn state(dir: &TempDir) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    // Mirror the full production registry so tests that introspect
    // the registry (e.g. server-detail enabled-protocols section)
    // see the same set the live daemon does. Previously only 2
    // protocols were registered here, which made admin_smoke
    // tests for the protocols section fail silently — they'd
    // pass on assertions involving vless/tuic and skip everything
    // else without the test owner noticing.
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::AmneziaWg::new()))
        .unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::WgTurn::new()))
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
    reg.register_protocol(Box::new(vpnctl_protocols::AnyTls::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::Trojan::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::WgTurn::new()))
        .unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::Caddy::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::Naive::new()))
        .unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::DnsTunnel::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::DnsTunnel::new()))
        .unwrap();
    // Lockstep with `app.rs::build_registry` (PR #139 round-2 review):
    // xray kernel + vless-ws/vless+xhttp protocols were missing here, so
    // any future admin-level test touching those protocols (e.g. the
    // reality↔vless-ws front-port collision) would run against a vacuum.
    reg.register_kernel(Box::new(vpnctl_kernels::Xray::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::VlessWs::new()))
        .unwrap();
    reg.register_protocol(Box::new(vpnctl_protocols::VlessXhttp::new()))
        .unwrap();
    // Wire the access-log writer the same way `build()` does. Drop the
    // JoinHandle — for tests that don't introspect the writer, the
    // task lives until the AppState clones drop, which happens at end
    // of test. Tests that DO need to assert writer behavior (e.g.
    // back-pressure spec) call `vpnctld::make_app_state_for_tests`
    // directly to keep the handle.
    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

// ────────────────────────────────────────────────────────────────────────
//  Phase B — dashboard + servers list
// ────────────────────────────────────────────────────────────────────────

/// Seed the inventory with `n_servers` servers and `n_users` users; if
/// `grant_pairs` are given, add those user×server grants too. Lives here
/// instead of in a #[cfg(test)] mod because integration tests can't share
/// helpers across files via cfg.
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

/// Variant of `fetch_html` that ships a Cookie header — used by the
/// wizard step-2 tests where the page is session-gated.
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

/// Assert the dashboard summary bar (densification pass) shows
/// `<b>value</b> label` (e.g. `<b>3</b> servers`), anchoring each count to
/// its own unit label so a reorder of the bar can't pass by coincidence.
pub(crate) fn assert_summary_stat(html: &str, value: &str, label: &str) {
    let needle = format!("<b>{value}</b> {label}");
    assert!(
        html.contains(&needle),
        "summary stat '{value} {label}' not found (looked for {needle:?})"
    );
}

/// Seed a dns-tunnel server (with the share-link secrets) granted to one
/// user; return the inventory ready for a user-detail render.
pub(crate) async fn seed_dns_tunnel_server(
    inv: &SqliteInventory,
    server_id: &str,
    granted_user: &str,
) {
    let sid = ServerId(server_id.into());
    inv.add_server(&Server {
        id: sid.clone(),
        address: "203.0.113.9".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("dns-tunnel".into())],
        enabled_protocols: vec![ProtocolId("dns-tunnel".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(&sid, "dns-tunnel:domain", "t.example.com")
        .await
        .unwrap();
    inv.set_server_secret(&sid, "dns-tunnel:fingerprint", "47:1E:87:8F:3E:48:C8:1C")
        .await
        .unwrap();
    inv.grant(&UserId(granted_user.into()), &sid).await.unwrap();
}

// ────────────────────────────────────────────────────────────────────────
//  Phase 3+ ninitux-compat URL rendering (post-Phase-5 cutover, 2026-05-19)
//
//  Pinned behaviour:
//    1. User with `vpn_router_device_id` pinned → admin UI renders
//       `https://ninitux.com/api/v1/app/config/<device_id>` as the
//       PRIMARY subscription URL. The QR encodes that exact URL.
//       The legacy `/sub/<token>` URL is demoted inside a <details>
//       collapsible labelled "LAN-only fallback".
//    2. User WITHOUT a device_id → admin UI falls back to the
//       legacy `/sub/<token>` URL as primary (pre-Phase-3 behaviour
//       preserved) AND the empty-state copy quotes the literal CLI
//       command to pin a device_id (per CLAUDE.md "Every empty
//       state must quote a literal CLI command").
//    3. Users-list deck mentions the `ninitux.com` host so the
//       operator sees the production URL shape at-a-glance.
//
//  Caught 2026-05-19 by visual review of /admin/users/tester-1: the
//  QR encoded the LAN URL `http://192.168.0.236:18402/sub/<token>`
//  which doesn't work for any client outside the LAN — operators
//  showing the QR to a real user would silently fail.
// ────────────────────────────────────────────────────────────────────────

pub(crate) const TEST_NINITUX_DEVICE_ID: &str = "a92b915032b48a2ed45ef72f4171e5f4";

// ────────────────────────────────────────────────────────────────────────
//  Boosty subscription bridge (/admin/boosty)
// ────────────────────────────────────────────────────────────────────────

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

/// Default same-origin host used by every test that POSTs to /admin
/// without explicitly testing CSRF behaviour. Using a single constant
/// here means a future schema change (e.g. switching to a vhost-aware
/// router) only touches one place.
pub(crate) const SAME_ORIGIN_HOST: &str = "test.example";

/// Inject the Host + Origin headers that the CSRF middleware expects
/// (`handlers::csrf::require_same_origin` rejects state-mutating requests
/// whose Origin does not match Host). Tests that explicitly verify the
/// CSRF rejection path do not call this helper.
pub(crate) fn add_same_origin(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.header("host", SAME_ORIGIN_HOST)
        .header("origin", format!("http://{SAME_ORIGIN_HOST}"))
}

// ── Phase 3: naive (Caddy) per-server config UI ──────────────────────────

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

/// Helper for the copy-contract tests — exercises the router and
/// returns the response body as a UTF-8 String. Sets same-origin
/// headers on every method so the CSRF middleware passes mutating
/// requests through (GET passes regardless).
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

// ─── sub_access.suspicious_local_ip alert spec (Pavel 2026-05-21) ───
//
// «если видим 127.0.0.1 или любой из 192.168/10/172.16-31 (метка
// LAN) и 169.254.* то это инцидент, который требует разбирательства».
// The writer task fires an admin_alert per (user_id) bucket when a
// LAN/loopback/link-local IP is paired with a UA that's NOT on the
// allowlist (only `phase6-monitor (canary)` today).

/// Helper: send one record through the writer + wait for it to drain
/// + return the inventory handle for assertions.
pub(crate) async fn enqueue_one_and_drain(
    s: &vpnctld::AppState,
    user_id: &str,
    ip: &str,
    device_class: Option<&str>,
) {
    let _ = vpnctld::access_log::try_enqueue(
        &s.access_log_tx,
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
    );
    // Writer is async; small sleep + drain is the same pattern the
    // existing `sub_access_writer_persists_one_hit` test uses.
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
}

// ════════════════════════════════════════════════════════════════════
//  PR-Dash — informativeness cards (fleet-at-a-glance, real traffic,
//  kernel rollup, alerts breakdown, abuse summary, today digest).
//
//  The base `seed()` helper deliberately writes ZERO audit rows (several
//  existing tests pin that contract — see `grants_via_real_handlers_
//  mark_server_pending_deploy`). So rather than disturb it, the dashboard
//  cards get their own opt-in signal seeder layered on top: a node_health
//  row carrying `kernel_versions_json`, an admin_alert of a known
//  (kind, severity), an audit row dated today, and a high-ASN sub_access
//  pattern for a user. Each new test calls `seed()` then this.
// ════════════════════════════════════════════════════════════════════

/// Layer the dashboard-card signals onto an already-seeded inventory.
/// Assumes `s0`/`u0` exist (call after `seed(.., n>=1, m>=1, ..)`).
pub(crate) async fn seed_dashboard_signals(inv: &SqliteInventory) {
    // dash#1 + dash#3 — node_health with on-node kernel versions, disk
    // + mem so the at-a-glance row has real cells (not all «—»). s0 is
    // the fleet-max sing-box version (1.13.12 = the floor/target).
    inv.record_node_health(
        &ServerId("s0".into()),
        Some(true),  // sing_box_active = up
        Some(true),  // fail2ban_active
        Some(4096),  // disk_used_mib
        Some(20480), // disk_total_mib  → 20% used
        Some(2048),  // mem_available_mib
        Some(8192),  // mem_total_mib   → 75% used
        Some(120),   // load_1min_x100
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

    // dash#4 — one admin_alert of a known (kind, severity) so the
    // breakdown card has something to render.
    inv.insert_alert(
        "disk_pressure",
        Some(&ServerId("s0".into())),
        "critical",
        "disk above 90% on s0",
        None,
    )
    .await
    .unwrap();

    // dash#6 — an audit row dated today (the `audit()` helper stamps
    // `ts` with `now`, which is >= today's local-midnight UTC). A
    // `user.create` action buckets into `users_added`.
    inv.audit("admin", "user.create", Some("u0"), None)
        .await
        .unwrap();

    // dash#5 — high-ASN sub_access pattern: u0's subscription fetched
    // from 3 distinct ASNs (≥ LIKELY_SHARED_MIN_ASNS=3) → "likely
    // shared". `is_vpn_egress` defaults to 0 so these are real fetches.
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

    // sharing v2 — flag u0 via the DOMINANT signal: typical peak of 3
    // concurrent networks (`TypicalConcurrentNets(3)` = 45 pts ≥ 35). The old
    // 3-ASN fetch-diversity above no longer scores (dropped in v2), so the
    // abuse-summary card only renders once a real-simultaneity signal lands.
    inv.record_user_ip_concurrency(&[(UserId("u0".into()), 3)])
        .await
        .unwrap();
}

// ════════════════════════════════════════════════════════════════════
//  PR-User — informativeness cards on the user-detail page.
//  DOM + empty-state per card + copy-contract (EN + RU).
// ════════════════════════════════════════════════════════════════════

/// Build a clash-api connection with a controllable source IP/port —
/// the attribution key the online badge reads.
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

// ────────────────────────────────────────────────────────────────────────
//  Auto-deploy on grant / revoke (HANDOFF 2026-07-08 §4.1 / §6.2)
//
//  A grant only used to write inv.db: the sub URI appeared instantly but
//  the UUID never reached the node's vless users[] — REALITY handshake
//  succeeds, VLESS-auth rejects, the client is forwarded to the cover
//  dest → «connects but no internet». Every grant/revoke handler must now
//  dispatch the same background redeploy delete/disable already use.
//
//  In the test environment the deploy key is absent, so the spawn skips
//  the SSH pipeline and records a FAILED `user.autodeploy` audit row
//  (ok=false) instead of stamping a fake `server.deploy` baseline. That
//  row — its trigger + servers payload — is the observable contract that
//  the redeploy was dispatched for exactly the affected server set.
// ────────────────────────────────────────────────────────────────────────

/// Poll the audit log until at least `n` autodeploy rows exist
/// (`user.autodeploy` for user-scoped triggers, `server.autodeploy`
/// for server-side bulk — the spawn is a background task racing the
/// test). Returns newest-first per `recent_audit` ordering.
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

/// Count autodeploy rows right now (for no-op negative checks).
pub(crate) async fn count_autodeploy_rows(inv: &SqliteInventory) -> usize {
    inv.recent_audit(200)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.action == "user.autodeploy" || e.action == "server.autodeploy")
        .count()
}

// ── reality-config: per-server VLESS+REALITY listen port (PR #139) ──────
//
// The cdn topology (naive/caddy on 443 + reality moved off it via
// `vless.listen_port`) made the port load-bearing for firewall, guard
// and drift — so the admin form gets the same save-time gate the naive
// and vless-ws forms have, pinned here end-to-end.

pub(crate) fn reality_naive_server(id: &str) -> vpnctl_core::Server {
    // naive (caddy, tcp/443) + vless+reality (sing-box) on ONE node —
    // exactly the combination the save-time guard exists for.
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
