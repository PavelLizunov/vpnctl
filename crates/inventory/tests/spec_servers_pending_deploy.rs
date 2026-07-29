//! Spec for `SqliteInventory::servers_pending_deploy_for_user` —
//! backs the «⚠ Config not yet deployed to: X, Y» banner on
//! /admin/users/<id>. Written from spec only — impl NOT consulted.
//!
//! Contract: returns the subset of `granted_server_ids` whose latest
//! `server.deploy` audit row is OLDER than the user's latest
//! mutation row (user.add / user.grant / user.set_vpn_router_device_id
//! / user.disable / user.enable). If a server has NO deploy row at all
//! but the user has any mutation, the server is pending.
//!
//! 2026-07-10 refinement: grant/revoke rows carrying a
//! `payload.server` count only against that server; payload-less rows
//! and server-agnostic mutations count against every granted server.

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

/// 2026-07-10 scoping: a `user.grant` row that NAMES a server via
/// `payload.server` counts only against THAT server. Granting on a new
/// node must not raise a phantom «not deployed» banner on every other
/// node the user already has (post-#92 the affected node auto-deploys;
/// the others didn't change). Payload-less legacy rows keep the old
/// coarse all-servers reading (pinned by the earlier tests, which
/// write no payload).
#[tokio::test]
async fn grant_scoped_by_payload_server_does_not_flag_other_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("brat", 7)).await.unwrap();
    for sid in ["old-node", "new-node"] {
        inv.add_server(&srv(sid)).await.unwrap();
        inv.grant(&UserId("brat".into()), &ServerId(sid.into()))
            .await
            .unwrap();
    }
    // Both nodes deployed successfully…
    for sid in ["old-node", "new-node"] {
        inv.audit(
            "admin",
            "server.deploy",
            Some(sid),
            Some(&serde_json::json!({ "ssh_errors": [], "ssh_skip_reason": null })),
        )
        .await
        .unwrap();
    }
    // tiny delay so the grant ts is strictly greater than the deploys
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    // …then a grant lands that names ONLY new-node.
    inv.audit(
        "admin",
        "user.grant",
        Some("brat"),
        Some(&serde_json::json!({ "server": "new-node", "source": "test" })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(
            &UserId("brat".into()),
            &[ServerId("old-node".into()), ServerId("new-node".into())],
        )
        .await
        .unwrap();
    assert_eq!(
        got,
        vec![ServerId("new-node".into())],
        "only the server named by payload.server may go pending"
    );
}

/// Server-agnostic mutations (disable) still flag every granted server
/// — a disabled user must be excluded from EVERY node's config, so the
/// broad reading is the correct one there.
#[tokio::test]
async fn server_agnostic_mutation_still_flags_all_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("pausa", 8)).await.unwrap();
    for sid in ["n1", "n2"] {
        inv.add_server(&srv(sid)).await.unwrap();
        inv.grant(&UserId("pausa".into()), &ServerId(sid.into()))
            .await
            .unwrap();
        inv.audit(
            "admin",
            "server.deploy",
            Some(sid),
            Some(&serde_json::json!({ "ssh_errors": [], "ssh_skip_reason": null })),
        )
        .await
        .unwrap();
    }
    // tiny delay so the disable ts is strictly greater than the deploys
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "user.disable", Some("pausa"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(
            &UserId("pausa".into()),
            &[ServerId("n1".into()), ServerId("n2".into())],
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 2, "disable must flag every granted server");
}

/// Boosty-bridge flips (`boosty.disable` / `boosty.enable`, actor
/// `boosty-bridge`) are user mutations exactly like `user.disable` — the
/// bridge auto-deploys after a flip, but when that deploy fails (or a
/// CLI-applied flip is never deployed) the banner must catch the gap.
/// Without these actions in the detector's list a bridge flip was
/// INVISIBLE to the pending-deploy safety net.
#[tokio::test]
async fn boosty_bridge_flips_count_as_user_mutations() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("sub", 11)).await.unwrap();
    inv.add_server(&srv("node")).await.unwrap();
    inv.grant(&UserId("sub".into()), &ServerId("node".into()))
        .await
        .unwrap();
    inv.audit(
        "admin",
        "server.deploy",
        Some("node"),
        Some(&serde_json::json!({ "ssh_errors": [], "ssh_skip_reason": null })),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    // Bridge re-enables the user (re-subscribed) → node config is stale.
    inv.audit("boosty-bridge", "boosty.enable", Some("sub"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("sub".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "boosty.enable after deploy → pending");

    // Deploy catches up → cleared.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("node"),
        Some(&serde_json::json!({ "ssh_errors": [], "ssh_skip_reason": null })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("sub".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert!(got.is_empty(), "deploy after the flip clears pending");

    // Bridge disables the user (lapsed) → stale again.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("boosty-bridge", "boosty.disable", Some("sub"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("sub".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "boosty.disable after deploy → pending");
}

// ── WireGuard regen + TUIC mint count as user mutations ────────────

/// `user.wireguard.regen` changes the pubkey on every granted server;
/// the pending-deploy detector must flag them until a deploy lands.
#[tokio::test]
async fn wireguard_regen_counts_as_user_mutation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("wg", 20)).await.unwrap();
    inv.add_server(&srv("node")).await.unwrap();
    inv.grant(&UserId("wg".into()), &ServerId("node".into()))
        .await
        .unwrap();
    inv.audit(
        "admin",
        "server.deploy",
        Some("node"),
        Some(&serde_json::json!({ "ssh_errors": [] })),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    inv.audit("admin", "user.wireguard.regen", Some("wg"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("wg".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "wireguard.regen after deploy → pending");

    // Deploy catches up → cleared.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("node"),
        Some(&serde_json::json!({ "ssh_errors": [] })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("wg".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert!(got.is_empty(), "deploy after regen clears pending");
}

/// `user.mint_tuic_password` changes the password protocols use on
/// every granted server; the detector must flag them.
#[tokio::test]
async fn tuic_mint_counts_as_user_mutation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("tuic", 21)).await.unwrap();
    inv.add_server(&srv("node")).await.unwrap();
    inv.grant(&UserId("tuic".into()), &ServerId("node".into()))
        .await
        .unwrap();
    inv.audit(
        "admin",
        "server.deploy",
        Some("node"),
        Some(&serde_json::json!({ "ssh_errors": [] })),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    inv.audit("admin", "user.mint_tuic_password", Some("tuic"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("tuic".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "mint_tuic_password after deploy → pending");
}

// ── Protocol/kernel mutations count for server_pending_deploy ──────

/// The four protocol/kernel audit actions must raise the server-side
/// pending-deploy flag until a fresh deploy lands.
#[tokio::test]
async fn protocol_kernel_mutations_raise_server_pending_deploy() {
    let actions = [
        "server.protocol.enable",
        "server.protocol.disable",
        "server.kernel.enable",
        "server.kernel.disable",
    ];
    for action in actions {
        let dir = TempDir::new().unwrap();
        let inv = open(&dir).await;
        inv.add_server(&srv("srv")).await.unwrap();
        // Baseline deploy → not pending.
        inv.audit(
            "admin",
            "server.deploy",
            Some("srv"),
            Some(&serde_json::json!({ "ssh_errors": [] })),
        )
        .await
        .unwrap();
        assert!(
            !inv.server_pending_deploy(&ServerId("srv".into()))
                .await
                .unwrap(),
            "{action}: baseline deploy → not pending"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        // Mutation → pending.
        inv.audit("admin", action, Some("srv"), None).await.unwrap();
        assert!(
            inv.server_pending_deploy(&ServerId("srv".into()))
                .await
                .unwrap(),
            "{action}: mutation after deploy → pending"
        );

        // Deploy catches up → cleared.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        inv.audit(
            "admin",
            "server.deploy",
            Some("srv"),
            Some(&serde_json::json!({ "ssh_errors": [] })),
        )
        .await
        .unwrap();
        assert!(
            !inv.server_pending_deploy(&ServerId("srv".into()))
                .await
                .unwrap(),
            "{action}: deploy after mutation clears pending"
        );
    }
}
