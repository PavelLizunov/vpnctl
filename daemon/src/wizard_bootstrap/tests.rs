#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use super::*;
use vpnctl_core::{KernelId, ProtocolId, RenderCtx, Server, ServerId};

#[test]
fn derive_server_id_keeps_ipv4_unchanged() {
    assert_eq!(derive_server_id("198.51.100.42"), "198.51.100.42");
}

#[test]
fn derive_server_id_replaces_ipv6_colons() {
    assert_eq!(derive_server_id("2001:db8::1"), "2001-db8--1");
}

#[test]
fn derive_server_id_filters_non_alphabet_chars() {
    // Whitespace and semicolons (shouldn't reach here — the
    // wizard validates upfront — but defensive) get stripped.
    assert_eq!(derive_server_id("foo bar; rm -rf"), "foobarrm-rf");
}

/// `BootstrapPlan` is the contract between handler and engine —
/// the test confirms we can build one without any axum types in
/// scope (which would couple the engine to the HTTP surface).
#[test]
fn bootstrap_plan_constructible_outside_handler() {
    let plan = BootstrapPlan {
        server_id: "vps-test".into(),
        address: "203.0.113.7".into(),
        ssh_user: "debian".into(),
        ssh_port: 22,
        root_password: "redacted".into(),
        deploy_key_path: PathBuf::from("/tmp/k"),
        known_hosts_path: PathBuf::from("/tmp/kh"),
    };
    assert_eq!(plan.server_id, "vps-test");
    assert_eq!(plan.ssh_port, 22);
}

#[test]
fn redact_password_replaces_substring_with_placeholder() {
    let stderr = "permission denied: password 'hunter2' rejected";
    assert_eq!(
        redact_password(stderr, "hunter2"),
        "permission denied: password '<redacted>' rejected"
    );
}

#[test]
fn redact_password_passthrough_when_password_absent() {
    let stderr = "ssh: connect to host 198.51.100.1: connection refused";
    assert_eq!(
        redact_password(stderr, "secret"),
        "ssh: connect to host 198.51.100.1: connection refused"
    );
}

#[test]
fn redact_password_handles_empty_password_safely() {
    // Empty password would otherwise match every char position
    // (`str::replace("", "<redacted>")` would explode). Guard
    // returns trimmed stderr unchanged.
    let stderr = "  hello world  ";
    assert_eq!(redact_password(stderr, ""), "hello world");
}

#[test]
fn find_available_server_id_returns_base_when_free() {
    let existing = std::collections::HashSet::new();
    assert_eq!(
        find_available_server_id(&existing, "198.51.100.1").unwrap(),
        "198.51.100.1"
    );
}

#[test]
fn find_available_server_id_suffixes_2_on_first_collision() {
    let mut existing = std::collections::HashSet::new();
    existing.insert("198.51.100.1".into());
    assert_eq!(
        find_available_server_id(&existing, "198.51.100.1").unwrap(),
        "198.51.100.1-2"
    );
}

#[test]
fn find_available_server_id_walks_through_taken_suffixes() {
    let mut existing = std::collections::HashSet::new();
    existing.insert("a".into());
    existing.insert("a-2".into());
    existing.insert("a-3".into());
    existing.insert("a-4".into());
    assert_eq!(find_available_server_id(&existing, "a").unwrap(), "a-5");
}

/// `bootstrap_server_secrets` is the single source of truth for
/// server-side per-protocol secret minting (shared between the
/// wizard and `server_deploy`). Spec it against an in-memory
/// inventory: mint once → 3 vless keys + 1 hy2 password (3 mint
/// labels: REALITY keypair + short_id + hy2 obfs); mint again → no
/// churn (idempotent).
#[tokio::test]
async fn bootstrap_secrets_mints_then_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = vpnctl_inventory::SqliteInventory::open(&db).await.unwrap();
    let registry = crate::app::build_registry().unwrap();
    let server = Server {
        id: ServerId("test-server".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("hysteria2".into()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server).await.unwrap();

    let (secrets1, minted1) = bootstrap_server_secrets(&inv, &server, &registry)
        .await
        .unwrap();
    assert!(secrets1.contains_key("vless.private_key"));
    assert!(secrets1.contains_key("vless.public_key"));
    assert!(secrets1.contains_key("vless.short_id"));
    assert!(secrets1.contains_key("hysteria2.obfs.password"));
    assert!(!secrets1.contains_key("wireguard.server_public_key"));
    // REALITY keypair + REALITY short_id + hy2 obfs = 3 spec labels.
    assert_eq!(minted1.len(), 3, "expected 3 mint labels, got {minted1:?}");

    // Second call — nothing new to mint.
    let (secrets2, minted2) = bootstrap_server_secrets(&inv, &server, &registry)
        .await
        .unwrap();
    assert_eq!(secrets1, secrets2);
    assert!(
        minted2.is_empty(),
        "second call must mint nothing; got {minted2:?}"
    );
}

/// REGRESSION GUARD for the `kg` deploy bug (2026-05-30): a server
/// enabling EVERY sing-box protocol (the quick-add default set)
/// must, after `bootstrap_server_secrets`, have minted every secret
/// each enabled protocol's `server_inbound` requires — i.e. NO
/// protocol renders `MissingSecret`. Before the
/// `Protocol::server_secret_specs()` refactor this failed on
/// `shadowsocks-2022` (`ss2022.psk` was never minted), which broke
/// the whole node deploy at render time.
#[tokio::test]
async fn bootstrap_mints_every_secret_each_enabled_protocol_needs_to_render() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = vpnctl_inventory::SqliteInventory::open(&db).await.unwrap();
    let registry = crate::app::build_registry().unwrap();

    // Every sing-box-rendered protocol.
    let sing_box = registry.kernel(&KernelId("sing-box".into())).unwrap();
    let enabled = sing_box.supported_protocols();
    let server = Server {
        id: ServerId("all-protos".into()),
        address: "203.0.113.9".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: enabled.clone(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server).await.unwrap();

    let (secrets, _minted) = bootstrap_server_secrets(&inv, &server, &registry)
        .await
        .unwrap();

    // The contract: every enabled protocol renders its server
    // inbound WITHOUT a MissingSecret after bootstrap.
    let ctx = RenderCtx::new(&server, &secrets);
    for pid in &enabled {
        let proto = registry.protocol(pid).unwrap();
        if let Err(vpnctl_core::CoreError::MissingSecret { key, .. }) =
            proto.server_inbound(&ctx, &[])
        {
            panic!("protocol {pid:?} still missing secret `{key}` after bootstrap — kg-class bug");
        }
    }

    // Stronger contract, independent of how each protocol READS its
    // secret: every key a protocol DECLARES via server_secret_specs()
    // must actually be minted. Catches a future protocol that forgets
    // its spec even when its server_inbound reads via or_default()
    // (which never raises MissingSecret, so the render loop above
    // would pass it vacuously).
    for pid in &enabled {
        let proto = registry.protocol(pid).unwrap();
        for spec in proto.server_secret_specs() {
            use vpnctl_core::ServerSecretSpec as S;
            let keys: Vec<&'static str> = match spec {
                S::Password { key, .. } | S::Base64Key { key, .. } | S::ShortId { key } => {
                    vec![key]
                }
                S::X25519Keypair {
                    private_key,
                    public_key,
                }
                | S::WireguardKeypair {
                    private_key,
                    public_key,
                } => vec![private_key, public_key],
            };
            for k in keys {
                assert!(
                    secrets.contains_key(k),
                    "{pid:?} declares secret `{k}` but bootstrap didn't mint it"
                );
            }
        }
    }

    // Pin the specific regression: ss2022.psk minted AND in the
    // sing-box-compatible encoding (standard base64 of a 16-byte
    // aes-128 key = 24 chars, padded, NOT url-safe). A url-safe /
    // unpadded PSK would be rejected by sing-box's StdEncoding and
    // crash the node config.
    let psk = secrets
        .get("ss2022.psk")
        .expect("ss2022.psk must be minted for a server with shadowsocks-2022 enabled");
    assert_eq!(
        psk.len(),
        24,
        "aes-128 PSK = 24-char padded base64, got {psk:?}"
    );
    assert!(psk.ends_with("=="), "standard base64 of 16 bytes ends '=='");
    assert!(
        !psk.contains('-') && !psk.contains('_'),
        "PSK must be STANDARD base64 (sing-box StdEncoding), not url-safe"
    );
}

#[test]
fn find_available_server_id_errors_when_1000_taken() {
    // Pathological — operator has registered 'a', 'a-2', …,
    // 'a-1000'. Refusing avoids an infinite loop on a corrupt
    // inventory. The error message points the operator at the
    // recovery path.
    let mut existing = std::collections::HashSet::new();
    existing.insert("a".into());
    for n in 2u32..=1000u32 {
        existing.insert(format!("a-{n}"));
    }
    assert!(find_available_server_id(&existing, "a").is_err());
}

/// JSON shape pinned — the SSE handler serialises events to JSON
/// in each Event's `data:` payload, and the browser parses them
/// with a `tag: "kind"` discriminator. If we ever rename `kind`
/// the front-end breaks silently — this test surfaces the rename.
#[test]
fn bootstrap_event_serialises_with_kind_tag() {
    let step = BootstrapEvent::Step {
        phase: "probe",
        message: "ssh root@…".into(),
    };
    let json = serde_json::to_string(&step).unwrap();
    assert!(json.contains("\"kind\":\"step\""), "got: {json}");
    assert!(json.contains("\"phase\":\"probe\""), "got: {json}");

    let ok = BootstrapEvent::Ok {
        server_id: "vps-1".into(),
        redirect: "/admin/servers/vps-1".into(),
    };
    let json_ok = serde_json::to_string(&ok).unwrap();
    assert!(json_ok.contains("\"kind\":\"ok\""), "got: {json_ok}");
    assert!(json_ok.contains("\"redirect\""), "got: {json_ok}");

    let err = BootstrapEvent::Error {
        phase: "probe",
        message: "permission denied".into(),
    };
    let json_err = serde_json::to_string(&err).unwrap();
    assert!(json_err.contains("\"kind\":\"error\""), "got: {json_err}");
}

#[test]
fn deploy_audit_action_reserves_baseline_for_applied_success() {
    assert_eq!(deploy_audit_action(&[], 1, None, false), "server.deploy");
    assert_eq!(
        deploy_audit_action(&[], 0, Some("deploy key absent"), false),
        "server.deploy.skipped"
    );
    assert_eq!(
        deploy_audit_action(&[], 0, None, false),
        "server.deploy.skipped"
    );
    assert_eq!(
        deploy_audit_action(&["sing-box failed".into()], 1, None, false),
        "server.deploy.failed"
    );
    assert_eq!(
        deploy_audit_action(&[], 1, None, true),
        "server.deploy.stale"
    );
}

// ─── per-server deploy concurrency gate (DeployGuard) ────────────
// Each test uses UNIQUE server-ids: the in-flight set is a
// process-wide static shared across the parallel test runner.

#[test]
fn deploy_guard_blocks_second_acquire_of_same_server() {
    let g1 = DeployGuard::try_acquire("gate-same-server");
    assert!(g1.is_some(), "first acquire must succeed");
    assert!(
        DeployGuard::try_acquire("gate-same-server").is_none(),
        "a second concurrent acquire of the same server must be refused"
    );
    drop(g1);
    assert!(
        DeployGuard::try_acquire("gate-same-server").is_some(),
        "must re-acquire after the holder drops (RAII release)"
    );
}

#[test]
fn deploy_guard_allows_distinct_servers_concurrently() {
    let a = DeployGuard::try_acquire("gate-distinct-a");
    let b = DeployGuard::try_acquire("gate-distinct-b");
    assert!(
        a.is_some() && b.is_some(),
        "per-server lock must let unrelated nodes deploy in parallel"
    );
}

#[tokio::test]
async fn run_redeploy_reports_already_running_when_locked() {
    use tokio_stream::StreamExt;
    let dir = tempfile::tempdir().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let registry = Arc::new(crate::app::build_registry().unwrap());
    let server = Server {
        id: ServerId("gate-run-redeploy".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server).await.unwrap();
    inv.add_server_protocol(&server.id, &ProtocolId("amneziawg2".into()))
        .await
        .unwrap();
    // Hold the permit so run_redeploy must stop before refreshing the stored
    // server or bootstrapping its newly enabled protocol.
    let _held = DeployGuard::try_acquire("gate-run-redeploy").expect("hold permit");
    let mut stream = Box::pin(run_redeploy(
        server.clone(),
        inv.clone(),
        registry,
        PathBuf::from("/nonexistent/key"),
    ));
    match stream.next().await {
        Some(BootstrapEvent::Error { message, .. }) => assert!(
            message.contains("already running"),
            "expected already-running error, got: {message}"
        ),
        other => panic!("expected one Error event, got {other:?}"),
    }
    assert!(
        stream.next().await.is_none(),
        "stream must close after the single already-running error"
    );
    assert!(
        inv.list_server_secrets(&server.id)
            .await
            .unwrap()
            .is_empty(),
        "guard rejection must happen before stored-server refresh/bootstrap"
    );
}

fn redeploy_test_server(id: &str, enabled_protocols: Vec<ProtocolId>) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols,
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn declared_secret_keys(registry: &vpnctl_core::Registry, protocol_id: &str) -> Vec<&'static str> {
    use vpnctl_core::ServerSecretSpec as S;

    let keys: Vec<_> = registry
        .protocol(&ProtocolId(protocol_id.into()))
        .unwrap()
        .server_secret_specs()
        .into_iter()
        .flat_map(|spec| match spec {
            S::Password { key, .. } | S::Base64Key { key, .. } | S::ShortId { key } => {
                vec![key]
            }
            S::X25519Keypair {
                private_key,
                public_key,
            }
            | S::WireguardKeypair {
                private_key,
                public_key,
            } => vec![private_key, public_key],
        })
        .collect();
    let namespace = format!("{protocol_id}.");
    assert!(
        !keys.is_empty(),
        "{protocol_id} must declare server secrets"
    );
    assert!(
        keys.iter().all(|key| key.starts_with(&namespace)),
        "{protocol_id} secret keys must be namespaced: {keys:?}"
    );
    keys
}

async fn collect_redeploy_bounded(
    snapshot: Server,
    inv: vpnctl_inventory::SqliteInventory,
    registry: Arc<vpnctl_core::Registry>,
    missing_key: PathBuf,
) -> Vec<BootstrapEvent> {
    use std::time::Duration;
    use tokio_stream::StreamExt;

    let mut stream = Box::pin(run_redeploy(snapshot, inv, registry, missing_key));
    let mut events = Vec::new();
    for _ in 0..32 {
        match tokio::time::timeout(Duration::from_secs(2), stream.next()).await {
            Ok(Some(event)) => events.push(event),
            Ok(None) => return events,
            Err(_) => panic!("redeploy stream did not terminate within the per-event bound"),
        }
    }
    panic!("redeploy stream exceeded the 32-event test bound");
}

fn terminal_error(events: &[BootstrapEvent]) -> &str {
    match events.last() {
        Some(BootstrapEvent::Error { message, .. }) => message,
        other => panic!("expected terminal Error event, got {other:?}"),
    }
}

#[tokio::test]
async fn run_redeploy_refreshes_enabled_awg_protocols_before_secret_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let registry = Arc::new(crate::app::build_registry().unwrap());
    let old = redeploy_test_server("redeploy-refresh-awg-enable", vec![]);
    inv.add_server(&old).await.unwrap();

    for protocol in ["amneziawg2", "amneziawg3"] {
        inv.add_server_protocol(&old.id, &ProtocolId(protocol.into()))
            .await
            .unwrap();
    }
    assert!(
        inv.list_server_secrets(&old.id).await.unwrap().is_empty(),
        "precondition: AWG secrets must be minted by run_redeploy"
    );

    let events = collect_redeploy_bounded(
        old.clone(),
        inv.clone(),
        Arc::clone(&registry),
        dir.path().join("missing-deploy-key"),
    )
    .await;
    assert!(
        terminal_error(&events).contains(DEPLOY_KEY_ABSENT_MSG),
        "nonexistent key must stop before SSH: {events:?}"
    );

    let secrets = inv.list_server_secrets(&old.id).await.unwrap();
    for protocol in ["amneziawg2", "amneziawg3"] {
        for key in declared_secret_keys(&registry, protocol) {
            assert!(
                secrets.contains_key(key),
                "fresh stored {protocol} requires newly minted `{key}`; got {:?}",
                secrets.keys().collect::<Vec<_>>()
            );
        }
    }
    let repeated = collect_redeploy_bounded(
        old.clone(),
        inv.clone(),
        registry,
        dir.path().join("missing-deploy-key"),
    )
    .await;
    assert!(terminal_error(&repeated).contains(DEPLOY_KEY_ABSENT_MSG));
    assert_eq!(
        secrets,
        inv.list_server_secrets(&old.id).await.unwrap(),
        "retry must not rotate either AWG identity or profile"
    );
}

#[tokio::test]
async fn run_redeploy_does_not_mint_secrets_for_protocol_removed_after_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let registry = Arc::new(crate::app::build_registry().unwrap());
    let old = redeploy_test_server(
        "redeploy-refresh-awg-disable",
        vec![
            ProtocolId("amneziawg2".into()),
            ProtocolId("amneziawg3".into()),
        ],
    );
    inv.add_server(&old).await.unwrap();
    inv.remove_server_protocol(&old.id, &ProtocolId("amneziawg3".into()))
        .await
        .unwrap();

    let events = collect_redeploy_bounded(
        old.clone(),
        inv.clone(),
        Arc::clone(&registry),
        dir.path().join("missing-deploy-key"),
    )
    .await;
    assert!(
        terminal_error(&events).contains(DEPLOY_KEY_ABSENT_MSG),
        "nonexistent key must stop before SSH: {events:?}"
    );

    let secrets = inv.list_server_secrets(&old.id).await.unwrap();
    for key in declared_secret_keys(&registry, "amneziawg2") {
        assert!(
            secrets.contains_key(key),
            "enabled AWG2 secret `{key}` missing"
        );
    }
    for key in declared_secret_keys(&registry, "amneziawg3") {
        assert!(
            !secrets.contains_key(key),
            "removed AWG3 protocol must not mint `{key}`"
        );
    }
}

#[tokio::test]
async fn run_redeploy_fails_for_removed_server_without_bootstrapping_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let registry = Arc::new(crate::app::build_registry().unwrap());
    let old = redeploy_test_server(
        "redeploy-refresh-removed-server",
        vec![
            ProtocolId("amneziawg2".into()),
            ProtocolId("amneziawg3".into()),
        ],
    );
    inv.add_server(&old).await.unwrap();
    inv.remove_server(&old.id).await.unwrap();

    let events = collect_redeploy_bounded(
        old.clone(),
        inv.clone(),
        registry,
        dir.path().join("missing-deploy-key"),
    )
    .await;
    let message = terminal_error(&events);
    assert!(
        message.contains("removed")
            || message.contains("no longer exists")
            || message.contains("not found"),
        "removed server must fail as stale inventory, got: {message}"
    );
    assert!(
        !message.contains(DEPLOY_KEY_ABSENT_MSG),
        "server removal must be detected before the missing-key gate"
    );
    assert!(
        inv.list_server_secrets(&old.id).await.unwrap().is_empty(),
        "removed server must not receive bootstrapped secrets"
    );
}

/// Operator-action-policy (CLAUDE.md HARD rule): the verify-key
/// failure copy that renders into the operator's browser must NOT
/// instruct them to `cat … on the node` (or any shell-on-node).
/// Pins the rewritten remediation text.
#[test]
fn verify_key_fail_copy_has_no_cat_on_node() {
    let hint = VERIFY_KEY_FAIL_HINT;
    assert!(
        !hint.contains("cat "),
        "verify-key hint must not tell the operator to cat on the node: {hint}"
    );
    assert!(
        !hint.contains("on the node"),
        "verify-key hint must not reference running things on the node: {hint}"
    );
    // And it points at the compliant product surfaces.
    assert!(
        hint.contains("server page") || hint.contains("wizard"),
        "verify-key hint must point at the wizard / server page: {hint}"
    );
}

// ── deploy_all_terminal — fleet SSE terminal event selection ────

#[test]
fn deploy_all_terminal_ok_when_no_failures() {
    let ev = deploy_all_terminal(&[], "done — deployed all 3 server(s).".into());
    match ev {
        BootstrapEvent::Ok {
            server_id,
            redirect,
        } => {
            assert_eq!(server_id, "all");
            assert_eq!(redirect, "/admin/servers");
        }
        other => panic!("expected Ok terminal, got {other:?}"),
    }
}

#[test]
fn deploy_all_terminal_error_on_partial_failure() {
    let failed = vec!["nl".to_string()];
    let ev = deploy_all_terminal(&failed, "done — 2/3 deployed; failed: nl".into());
    match ev {
        BootstrapEvent::Error { phase, message } => {
            assert_eq!(phase, "done");
            assert!(message.contains("failed: nl"), "message: {message}");
        }
        other => panic!("expected Error terminal, got {other:?}"),
    }
}

#[tokio::test]
async fn run_bootstrap_fails_with_exact_dotted_pubkey_path_when_missing() {
    use tokio_stream::StreamExt;

    let dir = tempfile::tempdir().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let registry = Arc::new(crate::app::build_registry().unwrap());
    let dotted_key = dir.path().join("deploy.id.key");
    let plan = BootstrapPlan {
        server_id: "test-node".into(),
        address: "203.0.113.7".into(),
        ssh_user: "debian".into(),
        ssh_port: 22,
        root_password: "dummy".into(),
        deploy_key_path: dotted_key.clone(),
        known_hosts_path: dir.path().join("known_hosts"),
    };
    let mut stream = Box::pin(run_bootstrap(plan, inv, registry));

    let step = stream.next().await.expect("expected step event");
    match step {
        BootstrapEvent::Step { phase, message } => {
            assert_eq!(phase, "setup");
            assert!(message.contains("loading vpnctld deploy pubkey"));
        }
        other => panic!("expected setup Step event, got {other:?}"),
    }

    let err = stream.next().await.expect("expected error event");
    let expected_pub_path = dir.path().join("deploy.id.key.pub");
    match err {
        BootstrapEvent::Error { phase, message } => {
            assert_eq!(phase, "setup");
            let expected_prefix = format!("can't read {}:", expected_pub_path.display());
            assert!(
                message.starts_with(&expected_prefix),
                "expected message starting with '{expected_prefix}', got: '{message}'"
            );
            assert!(
                message.contains("Re-check daemon's deploy key (see /admin/settings)."),
                "expected remediation hint in '{message}'"
            );
            assert!(
                !message.contains("deploy.id.pub"),
                "dotted path must not be truncated to deploy.id.pub: '{message}'"
            );
        }
        other => panic!("expected setup Error event, got {other:?}"),
    }
}
