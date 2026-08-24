use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::VpnStatsDelta;
use vpnctld::clash_api::{Connection, ConnectionMeta, Snapshot};
use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn admin_server_detail_highlights_drift_between_declared_and_observed() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Server declares vless+reality + tuic-v5 in inventory
    s.inv
        .add_server(&Server {
            id: ServerId("driftnode".into()),
            address: "10.0.0.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    // But the probe sees vless (tcp/443) AND an EXTRA hysteria2 (udp/8444),
    // and NO tuic (no udp/8443). Two drifts: missing tuic, extra hy2.
    s.inv
        .record_node_health(
            &ServerId("driftnode".into()),
            Some(true),
            Some(true),
            Some(1000),
            Some(10000),
            Some(500),
            Some(1000),
            Some(10),
            Some(r#"["tcp/22","tcp/443","udp/8444"]"#),
            Some(1000),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers/driftnode/protocols").await;
    // v2 3c grid: the silent tuic port renders the warm flag + the
    // declared-but-NOT-listening line names it.
    assert!(
        html.contains("✗ silent") || html.contains("✗ молчит"),
        "silent declared port must carry the ✗ flag; got: {}",
        &html[..html.len().min(400)]
    );
    assert!(
        html.contains("declared but NOT listening"),
        "missing-port warning line must render"
    );
    assert!(
        html.contains("udp/8443"),
        "missing tuic udp/8443 must be listed"
    );
    // The extra hysteria2 socket lands in the grouped undeclared table
    // (unclassified group names raw ports).
    assert!(
        html.contains("Listening but undeclared"),
        "undeclared group table must render"
    );
    assert!(
        html.contains("udp/8444"),
        "extra hysteria2 udp/8444 must be listed in a group"
    );
    // SSH port 22 must NOT be flagged as "extra" (always-listening).
    let undeclared = html.split("Listening but undeclared").nth(1).unwrap_or("");
    assert!(
        !undeclared.contains("tcp/22"),
        "ssh port must be excluded from the undeclared groups"
    );
}

#[tokio::test]
async fn phase4b_server_detail_renders_live_activity_section_when_no_samples() {
    // Pavel: even before the poller has sampled, the section must
    // render (with empty-state «active now: 0», «last poll: never»)
    // so the page structure is predictable. NM-11 caveat copy
    // present.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("emptynode".into()),
            address: "192.0.2.99".into(),
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

    let html = fetch_html(router(s), "/admin/servers/emptynode/activity").await;
    assert!(
        html.contains("Live activity · last 24h"),
        "server-detail must surface the Phase 4b live-activity section eyebrow"
    );
    assert!(
        html.contains("NM-11"),
        "section must mention NM-11 upstream caveat so the operator knows why per-user is zero"
    );
    assert!(
        html.contains("active now") && html.contains("upload 24h") && html.contains("download 24h"),
        "all 4 tile labels must render"
    );
    assert!(
        html.contains("last poll: ") && html.contains("never"),
        "empty-state must read «last poll: never»"
    );
}

#[tokio::test]
async fn phase4c_server_detail_renders_empty_state_when_no_snapshot() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("emptynode".into()),
            address: "192.0.2.99".into(),
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
    let html = fetch_html(router(s), "/admin/servers/emptynode/activity").await;
    assert!(
        html.contains("Live connections"),
        "server-detail must surface the Phase 4c section eyebrow even without data"
    );
    assert!(
        html.contains("No clash-api snapshot for this server yet"),
        "empty-state copy must explain the 5-minute poller cadence"
    );
}

#[tokio::test]
async fn phase4c_server_detail_renders_top_destinations_and_sources_from_snapshot() {
    // Manually inject a snapshot into the cache so we don't need a
    // real clash-api running. Pin: top destinations + top sources +
    // network breakdown tiles + correlation column header.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("active".into()),
            address: "203.0.113.10".into(),
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
    s.inv
        .add_user(&User {
            id: UserId("brat".into()),
            uuid: "br0".into(),
            sub_token: Some("brtok".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // brat fetched subscription from 9.9.9.9 → correlation
    // should surface that user_id when 9.9.9.9 appears as
    // sourceIP in the live snapshot.
    s.inv
        .log_sub_access(&UserId("brat".into()), "9.9.9.9", None, 200, 100)
        .await
        .unwrap();

    let snap = Snapshot {
        upload_total: 5000,
        download_total: 10000,
        connections: vec![
            Connection {
                id: "c1".into(),
                upload: 1000,
                download: 5000,
                start: "2026-05-21T18:00:00Z".into(),
                metadata: ConnectionMeta {
                    network: "tcp".into(),
                    destination_ip: "172.217.16.142".into(),
                    destination_port: "443".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "55555".into(),
                    host: "youtube.com".into(),
                    user: None,
                },
            },
            Connection {
                id: "c2".into(),
                upload: 100,
                download: 200,
                start: "2026-05-21T18:00:01Z".into(),
                metadata: ConnectionMeta {
                    network: "udp".into(),
                    destination_ip: "1.1.1.1".into(),
                    destination_port: "53".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "55556".into(),
                    host: String::new(),
                    user: None,
                },
            },
        ],
    };
    s.snapshot_cache.store(ServerId("active".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/active/activity").await;
    assert!(html.contains("Live connections"));
    // Top destinations must include youtube.com (preferred over IP).
    assert!(
        html.contains("youtube.com:443"),
        "top destinations must render host:port preferring DNS name"
    );
    // Top sources must include the real client IP.
    assert!(
        html.contains("9.9.9.9"),
        "top sources must render the real source IP"
    );
    // Correlation should resolve `9.9.9.9` → `brat`.
    assert!(
        html.contains("href=\"/admin/users/brat\""),
        "source-IP-to-user correlation must surface brat as the likely owner of 9.9.9.9"
    );
    // Network breakdown tiles (TCP 1 / UDP 1).
    assert!(html.contains(">tcp<") || html.contains("tcp"));
    assert!(html.contains("udp"));
    // NM-11 caveat copy
    assert!(
        html.contains("NM-11"),
        "section must surface NM-11 explainer"
    );
}

#[tokio::test]
async fn phase4d_server_detail_log_attribution_wins_over_sub_access_correlation() {
    // Setup: clash snapshot has source IP 31.135.234.102 with no
    // sub_access row (so Phase 4c correlation returns nothing).
    // Phase 4d attribution map says 31.135.234.102 → main-brat.
    // The «top sources» row must surface main-brat (exact match,
    // tagged «log») not «—».
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("phase4d-srv".into()),
            address: "203.0.113.50".into(),
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
    s.inv
        .add_user(&User {
            id: UserId("main-brat".into()),
            uuid: "mb0".into(),
            sub_token: None,
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // NO sub_access_log row — so Phase 4c fallback would NOT
    // find a match. Only Phase 4d log attribution can.

    let snap = Snapshot {
        upload_total: 1000,
        download_total: 5000,
        connections: vec![Connection {
            id: "c1".into(),
            upload: 1000,
            download: 5000,
            start: "2026-05-21T19:00:00Z".into(),
            metadata: ConnectionMeta {
                network: "tcp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: "31.135.234.102".into(),
                source_port: "2810".into(),
                host: String::new(),
                user: Some("main-brat".into()),
            },
        }],
    };
    s.snapshot_cache.store(ServerId("phase4d-srv".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/phase4d-srv/activity").await;
    // Exact match link to main-brat — now sourced from metadata.user
    // (the patched sing-box clash-api), not the removed log-scrape map.
    assert!(
        html.contains("href=\"/admin/users/main-brat\""),
        "metadata.user attribution must link the source IP to main-brat"
    );
}

#[tokio::test]
async fn phase4d_server_detail_falls_back_to_sub_access_when_no_log_attribution() {
    // Symmetric case — log attribution empty, sub_access has a
    // match → falls back, tagged «sub».
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("phase4d-fb".into()),
            address: "203.0.113.51".into(),
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
    s.inv
        .add_user(&User {
            id: UserId("falluser".into()),
            uuid: "fb0".into(),
            sub_token: Some("fbtok".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    // sub_access_log entry — Phase 4c sub_access correlation
    // hit for 5.5.5.5.
    s.inv
        .log_sub_access(&UserId("falluser".into()), "5.5.5.5", None, 200, 100)
        .await
        .unwrap();

    let snap = Snapshot {
        upload_total: 100,
        download_total: 200,
        connections: vec![Connection {
            id: "c1".into(),
            upload: 100,
            download: 200,
            start: "2026-05-21T19:00:00Z".into(),
            metadata: ConnectionMeta {
                network: "tcp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: "5.5.5.5".into(),
                source_port: "55555".into(),
                host: String::new(),
                user: None,
            },
        }],
    };
    // EMPTY attribution map — Phase 4d had nothing for this IP.
    s.snapshot_cache.store(ServerId("phase4d-fb".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/phase4d-fb/activity").await;
    // Must link to falluser via sub_access fallback.
    assert!(
        html.contains("href=\"/admin/users/falluser\""),
        "sub_access fallback must link the source IP to falluser when log attribution is empty"
    );
    // Tagged «sub» (not «log»).
    assert!(
        html.contains(">sub<"),
        "tag «sub» must indicate fallback-via-sub_access"
    );
    assert!(
        !html.contains(">log<"),
        "no «log» tag when log attribution map is empty"
    );
}

#[tokio::test]
async fn phase4d_server_detail_renders_dash_when_neither_log_nor_sub_has_attribution() {
    // Pin the «both layers empty» path: no log attribution, no
    // sub_access correlation hits → the «likely user» cell must
    // render «—» with NO `<a href="/admin/users/...">` link.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("phase4d-none".into()),
            address: "203.0.113.52".into(),
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
    // NO users added → users_for_source_ips returns no matches
    // for any IP, and we pass an empty attribution map.

    let snap = Snapshot {
        upload_total: 100,
        download_total: 100,
        connections: vec![Connection {
            id: "c1".into(),
            upload: 100,
            download: 100,
            start: "2026-05-21T19:00:00Z".into(),
            metadata: ConnectionMeta {
                network: "tcp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: "203.0.113.99".into(),
                source_port: "55555".into(),
                host: String::new(),
                user: None,
            },
        }],
    };
    s.snapshot_cache
        .store(ServerId("phase4d-none".into()), snap);

    let html = fetch_html(router(s), "/admin/servers/phase4d-none/activity").await;
    // Source IP must render in the top-sources row.
    assert!(
        html.contains("203.0.113.99"),
        "the unattributed source IP must still render in the table"
    );
    // NO link to any user-detail for this orphan IP. We use a
    // targeted check: extract the slice around the source IP cell
    // and assert it doesn't carry a user-detail link.
    let pos = html.find("203.0.113.99").expect("source IP must render");
    // The cell + the next ~400 chars cover the «likely user» cell.
    let window = &html[pos..pos.saturating_add(800)];
    assert!(
        !window.contains("href=\"/admin/users/"),
        "orphan source IP must NOT link to any user-detail; window: …{window}…"
    );
    // The «—» glyph appears as the cell content.
    assert!(
        window.contains("—"),
        "«likely user» cell must render «—» for orphan IP, got window: …{window}…"
    );
}

#[tokio::test]
async fn server_detail_renders_traffic_gap_section() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let sid = ServerId("gaptest".into());
    st.inv
        .add_server(&Server {
            id: sid.clone(),
            address: "203.0.113.9".into(),
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
    // Two NIC readings → rx Δ5 GB, tx 0 → nic_total ≈ 5 GB.
    for rx in [1_000_000_000u64, 6_000_000_000u64] {
        st.inv
            .record_node_health(
                &sid,
                Some(true),
                Some(true),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some("ens18"),
                Some(rx),
                Some(0),
                None,
            )
            .await
            .unwrap();
    }
    // Clash attributes ~1 GB → the gap is ~4 GB of unseen traffic.
    st.inv
        .record_vpn_stats(
            &sid,
            &[VpnStatsDelta {
                user_id: None,
                upload_bytes: 1_000_000_000,
                download_bytes: 0,
                active_connections: 0,
            }],
        )
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/gaptest/activity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // Section + the three tiles render (NIC ground-truth vs attributed vs gap).
    assert!(html.contains("Traffic accounting"), "gap section eyebrow");
    assert!(html.contains("NIC total"), "NIC total tile");
    assert!(html.contains("GAP (unattributed)"), "gap tile");
    assert!(html.contains("ens18"), "interface name shown");
    // With 2 samples it must NOT show the empty-state.
    assert!(
        !html.contains("No NIC ground-truth yet"),
        "should render real numbers, not the empty-state"
    );
}

/// server#1 — DEFAULT page load (no ?drift=live) renders the
/// «check live drift →» link and does NOT attempt any SSH. We can't
/// directly assert «no SSH» from the integration boundary, but the
/// node address is bogus (10.0.0.0) and the page MUST still return 200
/// fast — a default load that tried SSH would block on ConnectTimeout.
#[tokio::test]
async fn server_detail_drift_detail_default_shows_check_link_no_ssh() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // server s0
    let html = fetch_html(router(s), "/admin/servers/s0/protocols").await;
    assert!(
        html.contains("Drift detail · on-node UUIDs"),
        "drift-detail eyebrow missing on default load"
    );
    assert!(
        html.contains("check live drift →"),
        "default load must offer the [check live drift] link"
    );
    assert!(
        html.contains("?drift=live#drift-detail"),
        "the link must arm the ?drift=live opt-in"
    );
    // No live-read result copy on the default path.
    assert!(
        !html.contains("orphan uuids on node"),
        "default load must NOT render live-read results"
    );
}

/// server#1 — ?drift=live against an unreachable node (bogus address)
/// renders the POLICY-SAFE empty-state and NEVER 500s. The empty-state
/// copy must NOT instruct the operator to «ssh» the box.
#[tokio::test]
async fn server_detail_drift_live_failure_renders_policy_safe_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Address 192.0.2.1 is TEST-NET-1 (RFC 5737) — guaranteed
    // unroutable, so the live read fails fast under the ≤6s timeout.
    s.inv
        .add_server(&Server {
            id: ServerId("blackhole".into()),
            address: "192.0.2.1".into(),
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
    let html = fetch_html(router(s), "/admin/servers/blackhole/protocols?drift=live").await;
    // 200 (fetch_html asserts) + the policy-safe empty-state.
    assert!(
        html.contains("Couldn't read the live config"),
        "armed live-read failure must render the policy-safe empty-state"
    );
    assert!(
        html.contains("node unreachable or deploy key"),
        "empty-state must name the real cause (unreachable / deploy key)"
    );
    // Operator-action-policy: the DRIFT-DETAIL card's empty-state must
    // NEVER tell the operator to ssh the box. Scope the check to that
    // section (the page-wide Deploy button legitimately mentions an
    // automated «SSH into the node» it performs for the operator — a
    // different, allowed string).
    let drift_section = html
        .split("Drift detail · on-node UUIDs")
        .nth(1)
        .unwrap_or("")
        .split("Server traffic · ")
        .next()
        .unwrap_or("");
    let lower = drift_section.to_lowercase();
    assert!(
        !lower.contains("ssh to the box")
            && !lower.contains("ssh into")
            && !lower.contains("run ssh"),
        "policy violation: drift-detail empty-state must not instruct an SSH session"
    );
}

/// server#3 — top-users card carries the NM-11 empty-state when no
/// per-user traffic is attributed (the prod reality).
#[tokio::test]
async fn server_detail_top_users_renders_nm11_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("Top users · last 24h"),
        "top-users eyebrow missing"
    );
    assert!(
        html.contains("NM-11"),
        "empty top-users card must carry the NM-11 explainer"
    );
}

/// server#3 — when per-user rows DO exist they render with a drill-in
/// link to the user-detail page (and the NM-11 empty-state is gone).
#[tokio::test]
async fn server_detail_top_users_lists_users_with_links_when_present() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // s0, u0 granted
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: Some(UserId("u0".into())),
                upload_bytes: 3_000_000,
                download_bytes: 7_000_000,
                active_connections: 2,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains(r#"href="/admin/users/u0""#),
        "top-users row must link to the user-detail page"
    );
    // Section present; the NM-11 empty-state must NOT show with data.
    let top_section = html.split("Top users · last 24h").nth(1).unwrap_or("");
    let next_section = top_section.split("TCP / UDP split").next().unwrap_or("");
    assert!(
        !next_section.contains("NM-11"),
        "NM-11 empty-state must not render once per-user rows exist"
    );
}

/// server#4 — per-server traffic sparkline renders with the window
/// picker scoped to /admin/servers/{id} and the ↑↓ totals tiles.
#[tokio::test]
async fn server_detail_traffic_section_renders_sparkline_and_window_picker() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .record_vpn_stats(
            &ServerId("s0".into()),
            &[VpnStatsDelta {
                user_id: None, // server-wide row
                upload_bytes: 10_000_000,
                download_bytes: 40_000_000,
                active_connections: 12,
            }],
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("Server traffic · "),
        "server-traffic eyebrow missing"
    );
    assert!(
        html.contains("↑ upload") && html.contains("↓ download"),
        "server-traffic ↑↓ totals tiles missing"
    );
    // Window picker links scoped to THIS server.
    assert!(
        html.contains("/admin/servers/s0/activity?vpn_window=7d"),
        "window picker must be scoped to /admin/servers/s0"
    );
    // An <svg> sparkline rendered for the populated window.
    let traffic = html.split("Server traffic · ").nth(1).unwrap_or("");
    assert!(
        traffic.contains("<svg"),
        "populated window must render the sparkline svg"
    );
}

/// server#4 — empty window renders the no-traffic empty-state, not a
/// broken/blank chart.
#[tokio::test]
async fn server_detail_traffic_section_empty_state_when_no_stats() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // no vpn stats recorded
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("No traffic recorded in this window yet"),
        "empty traffic window must render the empty-state copy"
    );
}

/// server#5 — TCP/UDP split renders from the live snapshot with the
/// «no per-protocol tag» caption + tiles.
#[tokio::test]
async fn server_detail_network_split_renders_from_snapshot() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let snap = Snapshot {
        upload_total: 300,
        download_total: 600,
        connections: vec![
            Connection {
                id: "c1".into(),
                upload: 100,
                download: 200,
                start: "2026-05-21T18:00:00Z".into(),
                metadata: ConnectionMeta {
                    network: "tcp".into(),
                    destination_ip: "1.1.1.1".into(),
                    destination_port: "443".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "5000".into(),
                    host: String::new(),
                    user: None,
                },
            },
            Connection {
                id: "c2".into(),
                upload: 50,
                download: 100,
                start: "2026-05-21T18:00:01Z".into(),
                metadata: ConnectionMeta {
                    network: "udp".into(),
                    destination_ip: "1.1.1.1".into(),
                    destination_port: "53".into(),
                    source_ip: "9.9.9.9".into(),
                    source_port: "5001".into(),
                    host: String::new(),
                    user: None,
                },
            },
        ],
    };
    s.snapshot_cache.store(ServerId("s0".into()), snap);
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("TCP / UDP split"),
        "network-split eyebrow missing"
    );
    assert!(
        html.contains("clash-api carries no per-protocol tag"),
        "network-split must carry the per-protocol caveat caption"
    );
}

/// server#5 — empty-state when no snapshot exists for the server.
#[tokio::test]
async fn server_detail_network_split_empty_state_when_no_snapshot() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // no snapshot cached
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("TCP / UDP split"),
        "network-split eyebrow must render even with no snapshot"
    );
    assert!(
        html.contains("No clash-api snapshot for this server yet"),
        "network-split must render an empty-state when no snapshot"
    );
}

/// server#7 — server-scoped audit timeline renders rows that reference
/// this server (deploy/grant/etc), reusing the .ed-time component.
#[tokio::test]
async fn server_detail_audit_timeline_renders_server_scoped_rows() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    // An audit row targeting this server.
    s.inv
        .audit("admin", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("Audit timeline · this server"),
        "server-audit eyebrow missing"
    );
    assert!(
        html.contains("server.deploy"),
        "server-scoped audit row must list the deploy action"
    );
    assert!(
        html.contains("ed-time-row"),
        "audit timeline must reuse the .ed-time editorial component"
    );
}

/// server#7 — empty-state when no audit row references the server.
#[tokio::test]
async fn server_detail_audit_timeline_empty_state() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // seed writes no audit rows
    let html = fetch_html(router(s), "/admin/servers/s0/activity").await;
    assert!(
        html.contains("No audit rows reference this server yet"),
        "server-audit must render an empty-state with no rows"
    );
}
