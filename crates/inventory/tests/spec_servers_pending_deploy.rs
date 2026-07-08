//! Spec for `SqliteInventory::servers_pending_deploy_for_user` —
//! backs the «⚠ Config not yet deployed to: X, Y» banner on
//! /admin/users/<id>. Written from spec only — impl NOT consulted.
//!
//! Contract: returns the subset of `granted_server_ids` whose latest
//! `server.deploy` audit row is OLDER than the user's latest
//! mutation row (user.add / user.grant / user.set_vpn_router_device_id
//! / user.disable / user.enable). If a server has NO deploy row at all
//! but the user has any mutation, the server is pending.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .expect("open")
}

fn srv(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "203.0.113.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str, n: u32) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("00000000-0000-0000-0000-{n:012}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

#[tokio::test]
async fn empty_granted_list_returns_empty() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let got = inv
        .servers_pending_deploy_for_user(&UserId("anybody".into()), &[])
        .await
        .unwrap();
    assert!(got.is_empty(), "empty input → empty output");
}

#[tokio::test]
async fn user_with_zero_audit_rows_returns_empty() {
    // Legacy import: user exists in `users` but no audit_log entry.
    // We refuse to flag — operator never «changed» the user via the
    // tracked actions, so we can't compare against a deploy ts.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("legacy", 1)).await.unwrap();
    inv.add_server(&srv("alpha")).await.unwrap();
    inv.grant(&UserId("legacy".into()), &ServerId("alpha".into()))
        .await
        .unwrap();
    // `add_user` and `grant` are inventory mutations but don't write
    // audit rows on their own — the audit row is the CALLER's
    // responsibility (CLI / web handler). Here we skip writing one,
    // simulating a legacy user.
    let got = inv
        .servers_pending_deploy_for_user(&UserId("legacy".into()), &[ServerId("alpha".into())])
        .await
        .unwrap();
    assert!(
        got.is_empty(),
        "user with zero audit rows must NOT surface as pending"
    );
}

#[tokio::test]
async fn server_with_no_deploy_row_is_pending_when_user_has_any_mutation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice", 2)).await.unwrap();
    inv.audit("admin", "user.add", Some("alice"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(
            &UserId("alice".into()),
            &[ServerId("never-deployed".into())],
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "no-deploy server must be flagged as pending");
    assert_eq!(got[0].0, "never-deployed");
}

#[tokio::test]
async fn server_deployed_after_user_mutation_is_not_pending() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("bob", 3)).await.unwrap();
    // 1. user mutation first
    inv.audit("admin", "user.add", Some("bob"), None)
        .await
        .unwrap();
    // 2. deploy second — closes the gap.
    inv.audit("admin", "server.deploy", Some("beta"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("bob".into()), &[ServerId("beta".into())])
        .await
        .unwrap();
    assert!(
        got.is_empty(),
        "deploy newer than user mutation → not pending; got: {got:?}"
    );
}

#[tokio::test]
async fn server_deployed_before_user_mutation_is_pending() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("carol", 4)).await.unwrap();
    // 1. deploy first (server-init time).
    inv.audit("admin", "server.deploy", Some("gamma"), None)
        .await
        .unwrap();
    // tiny delay so the next ts is strictly greater
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    // 2. user mutation later — server out-of-date now.
    inv.audit("admin", "user.add", Some("carol"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("carol".into()), &[ServerId("gamma".into())])
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "user.add after deploy → pending");
    assert_eq!(got[0].0, "gamma");
}

#[tokio::test]
async fn mixed_servers_returns_only_the_pending_ones() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("dave", 5)).await.unwrap();
    inv.audit("admin", "server.deploy", Some("old"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "user.add", Some("dave"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "server.deploy", Some("fresh"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(
            &UserId("dave".into()),
            &[
                ServerId("old".into()),
                ServerId("fresh".into()),
                ServerId("nodeploy".into()),
            ],
        )
        .await
        .unwrap();
    let ids: Vec<&str> = got.iter().map(|s| s.0.as_str()).collect();
    assert!(ids.contains(&"old"), "old deploy → pending");
    assert!(ids.contains(&"nodeploy"), "no deploy ever → pending");
    assert!(!ids.contains(&"fresh"), "fresh deploy → NOT pending");
}

#[tokio::test]
async fn enable_disable_count_as_user_mutations() {
    // `user.enable` / `user.disable` flip the sub-render filter
    // (B1.user). They must invalidate the deployed config too.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("eve", 6)).await.unwrap();
    inv.audit("admin", "user.add", Some("eve"), None)
        .await
        .unwrap();
    inv.audit("admin", "server.deploy", Some("srv"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "user.disable", Some("eve"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("eve".into()), &[ServerId("srv".into())])
        .await
        .unwrap();
    assert_eq!(
        got.len(),
        1,
        "user.disable after deploy must mark server pending"
    );
}

#[tokio::test]
async fn server_side_detector_tracks_membership_vs_deploy() {
    // Server-side counterpart (audit 2026-06-10): after a REVOKE the
    // per-user detector can't flag the revoked server (it left the
    // user's granted list) — `server_pending_deploy` keys on the
    // canonical rows' `payload.server` field instead.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    // No membership rows at all → not pending (quiet server).
    assert!(
        !inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap()
    );

    // Grant row, no deploy ever → pending.
    inv.audit(
        "admin",
        "user.grant",
        Some("alice"),
        Some(&serde_json::json!({ "server": "srv", "source": "test" })),
    )
    .await
    .unwrap();
    assert!(
        inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap()
    );

    // Deploy after the grant → cleared.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "server.deploy", Some("srv"), None)
        .await
        .unwrap();
    assert!(
        !inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap()
    );

    // REVOKE after the deploy → pending again (the dangerous case:
    // the node still accepts the revoked UUID).
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "user.revoke",
        Some("alice"),
        Some(&serde_json::json!({ "server": "srv", "source": "test" })),
    )
    .await
    .unwrap();
    assert!(
        inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap()
    );

    // Mutations addressed at a DIFFERENT server must not leak in.
    assert!(
        !inv.server_pending_deploy(&ServerId("other".into()))
            .await
            .unwrap()
    );
}

// ── Only SUCCESSFUL deploys count as a baseline (review 2026-07-08) ────
//
// Every deploy path writes a `server.deploy` row even when it failed or
// was skipped (`ssh_errors` non-empty / `ssh_skip_reason` set). Such a
// row must NOT clear the pending banner: the node's users[] is still
// stale — hiding that is exactly the «connects but no internet» class
// the banner exists to expose.

#[tokio::test]
async fn failed_deploy_row_does_not_clear_user_side_pending() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("frank", 7)).await.unwrap();
    inv.audit("admin", "user.grant", Some("frank"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    // Deploy attempt AFTER the grant, but it failed (ssh_errors set).
    inv.audit(
        "admin",
        "server.deploy",
        Some("srv"),
        Some(&serde_json::json!({
            "ssh_errors": ["sing-box: apply_config failed: node unreachable"],
            "ssh_skip_reason": null,
        })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("frank".into()), &[ServerId("srv".into())])
        .await
        .unwrap();
    assert_eq!(
        got.len(),
        1,
        "a FAILED deploy must not count as a baseline — server stays pending"
    );

    // A later SUCCESSFUL deploy (empty ssh_errors, no skip) clears it.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("srv"),
        Some(&serde_json::json!({
            "ssh_errors": [],
            "ssh_skip_reason": null,
        })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("frank".into()), &[ServerId("srv".into())])
        .await
        .unwrap();
    assert!(got.is_empty(), "successful deploy clears pending");
}

#[tokio::test]
async fn skipped_deploy_row_does_not_clear_user_side_pending() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("grace", 8)).await.unwrap();
    inv.audit("admin", "user.grant", Some("grace"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    // Skip-reason deploy (e.g. deploy key absent) — nothing reached
    // the node.
    inv.audit(
        "admin",
        "server.deploy",
        Some("srv"),
        Some(&serde_json::json!({
            "ssh_errors": [],
            "ssh_skip_reason": "deploy key absent; see /admin/settings",
        })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("grace".into()), &[ServerId("srv".into())])
        .await
        .unwrap();
    assert_eq!(
        got.len(),
        1,
        "a SKIPPED deploy must not count as a baseline — server stays pending"
    );
}

#[tokio::test]
async fn failed_deploy_row_does_not_clear_server_side_pending() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.audit(
        "admin",
        "user.revoke",
        Some("alice"),
        Some(&serde_json::json!({ "server": "srv", "source": "test" })),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    // Auto-deploy after the revoke got refused (e.g. DG-1 guard) —
    // the revoked UUID is still live on the node.
    inv.audit(
        "admin",
        "server.deploy",
        Some("srv"),
        Some(&serde_json::json!({
            "ssh_errors": ["sing-box: apply_config failed: refusing to REMOVE 1 user UUID(s)"],
            "ssh_skip_reason": null,
        })),
    )
    .await
    .unwrap();
    assert!(
        inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap(),
        "failed deploy must leave the server-side pending flag up"
    );

    // Successful deploy clears it.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("srv"),
        Some(&serde_json::json!({ "ssh_errors": [], "ssh_skip_reason": null })),
    )
    .await
    .unwrap();
    assert!(
        !inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn legacy_baseline_rows_without_payload_fields_still_count_as_success() {
    // wizard-bootstrap success rows + pre-2026-07 baselines carry no
    // ssh_errors/ssh_skip_reason fields (or no payload at all) — they
    // were only ever written on success and must keep clearing pending.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("henry", 9)).await.unwrap();
    inv.audit("admin", "user.grant", Some("henry"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    // Payload-less row (test/CLI baseline).
    inv.audit("admin", "server.deploy", Some("srv"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("henry".into()), &[ServerId("srv".into())])
        .await
        .unwrap();
    assert!(
        got.is_empty(),
        "payload-less baseline must count as success"
    );

    // Wizard-bootstrap-shaped row (payload without the ssh_* fields).
    inv.add_user(&user("iris", 10)).await.unwrap();
    inv.audit("admin", "user.grant", Some("iris"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("wiz"),
        Some(&serde_json::json!({ "kernels": ["sing-box"], "via": "wizard-bootstrap" })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("iris".into()), &[ServerId("wiz".into())])
        .await
        .unwrap();
    assert!(
        got.is_empty(),
        "wizard-bootstrap success row must count as a baseline"
    );
}
