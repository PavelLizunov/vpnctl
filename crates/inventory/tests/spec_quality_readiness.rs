//! Independent tests derived from deploy-readiness-quality.md and the approved
//! public inventory contract. No implementation source was consulted.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::net::SocketAddr;

use chrono::{Duration, Utc};
use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::{ServiceQualitySample, SqliteInventory};

async fn fixture() -> (TempDir, SqliteInventory, ServerId) {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .unwrap();
    let sid = ServerId("quality-spec".into());
    inv.add_server(&Server {
        id: sid.clone(),
        address: "192.0.2.10".into(),
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
    (dir, inv, sid)
}

fn sample(sid: &ServerId, available: bool) -> ServiceQualitySample {
    ServiceQualitySample {
        ts: Utc::now(),
        server_id: sid.clone(),
        vantage: "spec control host".into(),
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

fn target(port: u16) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 10], port))
}

async fn record(inv: &SqliteInventory, row: &ServiceQualitySample, port: u16) {
    inv.record_service_quality_sample_for_targets(row, &[target(port)], &[target(22)])
        .await
        .unwrap();
}

async fn applied(inv: &SqliteInventory, sid: &ServerId) {
    inv.audit("spec", "server.deploy", Some(&sid.0), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn removing_user_durably_marks_all_formerly_granted_servers_pending() {
    let (dir, inv, first) = fixture().await;
    let second = ServerId("second-granted-server".into());
    let unrelated = ServerId("unrelated-server".into());
    for sid in [&second, &unrelated] {
        let mut server = inv.get_server(&first).await.unwrap().unwrap();
        server.id = sid.clone();
        inv.add_server(&server).await.unwrap();
    }
    let uid = UserId("deleted-user".into());
    inv.add_user(&User {
        id: uid.clone(),
        uuid: "spec-deleted-user-uuid".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    for sid in [&first, &second] {
        inv.grant(&uid, sid).await.unwrap();
    }
    for sid in [&first, &second, &unrelated] {
        applied(&inv, sid).await;
        assert!(!inv.server_pending_deploy(sid).await.unwrap());
    }

    // Only the public mutation is invoked: callers must not need to reconstruct
    // deleted grant links or append their own per-server audit after removal.
    inv.remove_user(&uid).await.unwrap();
    let audit_count = inv.recent_audit(100).await.unwrap().len();
    inv.remove_user(&uid).await.unwrap();
    assert_eq!(
        inv.recent_audit(100).await.unwrap().len(),
        audit_count,
        "retrying deletion of an absent user must not emit revoke audit spam"
    );
    for sid in [&first, &second] {
        assert!(
            inv.server_pending_deploy(sid).await.unwrap(),
            "{}: removed access still needs deployment",
            sid.0
        );
    }
    let reopened = SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .unwrap();
    for sid in [&first, &second] {
        assert!(
            reopened.server_pending_deploy(sid).await.unwrap(),
            "{}: deletion must survive reopen",
            sid.0
        );
        for action in [
            "server.deploy.failed",
            "server.deploy.stale",
            "server.deploy.skipped",
        ] {
            reopened
                .audit("spec", action, Some(&sid.0), None)
                .await
                .unwrap();
            assert!(
                reopened.server_pending_deploy(sid).await.unwrap(),
                "{}: {action} must not clear revoked access",
                sid.0
            );
        }
    }
    assert!(!reopened.server_pending_deploy(&unrelated).await.unwrap());
    applied(&reopened, &first).await;
    assert!(!reopened.server_pending_deploy(&first).await.unwrap());
    assert!(
        reopened.server_pending_deploy(&second).await.unwrap(),
        "deploying one affected node must not clear another"
    );
    applied(&reopened, &second).await;
    assert!(!reopened.server_pending_deploy(&second).await.unwrap());
    assert!(!reopened.server_pending_deploy(&unrelated).await.unwrap());
}

#[tokio::test]
async fn deleting_user_rolls_back_when_durable_audit_evidence_cannot_be_written() {
    let (dir, inv, sid) = fixture().await;
    let uid = UserId("retained-user".into());
    inv.add_user(&User {
        id: uid.clone(),
        uuid: "spec-retained-user-uuid".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&uid, &sid).await.unwrap();
    applied(&inv, &sid).await;
    // Approved fault-injection schema contract, confined to a disposable DB.
    let status = std::process::Command::new("python3")
        .args([
            "-c",
            "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DROP TABLE audit_log'); c.commit(); c.close()",
        ])
        .arg(dir.path().join("inventory.db"))
        .status()
        .unwrap();
    assert!(status.success(), "temporary audit fault injection failed");
    assert!(
        inv.remove_user(&uid).await.is_err(),
        "deletion without durable evidence must fail"
    );
    let retained = inv.users_for_server(&sid).await.unwrap();
    assert_eq!(
        retained.len(),
        1,
        "audit error must not cascade away the grant"
    );
    assert_eq!(
        retained[0].id, uid,
        "audit error must preserve the user and grant"
    );
}

#[tokio::test]
async fn every_granted_user_config_action_stays_pending_until_canonical_deploy() {
    for action in [
        "user.disable",
        "user.enable",
        "user.wireguard.regen",
        "user.mint_tuic_password",
        "boosty.disable",
        "boosty.enable",
        "user.set_vpn_router_device_id",
    ] {
        let (dir, inv, sid) = fixture().await;
        let other_sid = ServerId("unaffected-server".into());
        let mut other_server = inv.get_server(&sid).await.unwrap().unwrap();
        other_server.id = other_sid.clone();
        inv.add_server(&other_server).await.unwrap();
        let uid = UserId("changed-user".into());
        let other_uid = UserId("unaffected-user".into());
        for user_id in [&uid, &other_uid] {
            inv.add_user(&User {
                id: user_id.clone(),
                uuid: format!("spec-uuid-{}", user_id.0),
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
        inv.grant(&uid, &sid).await.unwrap();
        inv.grant(&other_uid, &other_sid).await.unwrap();
        applied(&inv, &sid).await;
        applied(&inv, &other_sid).await;
        assert!(
            !inv.server_pending_deploy(&sid).await.unwrap(),
            "{action}: baseline"
        );
        assert!(
            inv.users_pending_deploy_for_server(&sid)
                .await
                .unwrap()
                .is_empty()
        );

        inv.audit("spec", action, Some(&uid.0), None).await.unwrap();
        assert!(
            inv.server_pending_deploy(&sid).await.unwrap(),
            "{action}: mutation"
        );
        assert_eq!(
            inv.users_pending_deploy_for_server(&sid).await.unwrap(),
            vec![uid.clone()],
            "{action}: changed user must be pending"
        );
        let reopened = SqliteInventory::open(&dir.path().join("inventory.db"))
            .await
            .unwrap();
        // Attempts and a successful apply on another server cannot clear this
        // server's saved-but-unapplied change, including after a reopen.
        for attempt in [
            "server.deploy.failed",
            "server.deploy.skipped",
            "server.deploy.stale",
        ] {
            reopened
                .audit("spec", attempt, Some(&sid.0), None)
                .await
                .unwrap();
            assert!(
                reopened.server_pending_deploy(&sid).await.unwrap(),
                "{action}: {attempt}"
            );
            assert_eq!(
                reopened
                    .users_pending_deploy_for_server(&sid)
                    .await
                    .unwrap(),
                vec![uid.clone()],
                "{action}: {attempt} cannot clear the user"
            );
        }
        assert!(
            !reopened.server_pending_deploy(&other_sid).await.unwrap(),
            "{action}: unrelated server"
        );
        assert!(
            reopened
                .users_pending_deploy_for_server(&other_sid)
                .await
                .unwrap()
                .is_empty()
        );
        applied(&reopened, &other_sid).await;
        assert!(
            reopened.server_pending_deploy(&sid).await.unwrap(),
            "{action}: wrong server applied"
        );
        assert_eq!(
            reopened
                .users_pending_deploy_for_server(&sid)
                .await
                .unwrap(),
            vec![uid]
        );
        applied(&reopened, &sid).await;
        assert!(
            !reopened.server_pending_deploy(&sid).await.unwrap(),
            "{action}: canonical apply"
        );
        assert!(
            reopened
                .users_pending_deploy_for_server(&sid)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn separate_in_memory_inventories_have_distinct_coordination_identities() {
    let first = SqliteInventory::open(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    let second = SqliteInventory::open(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    assert_ne!(
        first.coordination_identity(),
        second.coordination_identity()
    );
    assert_eq!(
        first.coordination_identity(),
        first.clone().coordination_identity()
    );
}

#[tokio::test]
async fn coordination_identity_matches_clones_and_reopens_but_not_distinct_databases() {
    let (dir, inv, _sid) = fixture().await;
    let cloned = inv.clone();
    let reopened = SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .unwrap();
    let distinct = SqliteInventory::open(&dir.path().join("other.db"))
        .await
        .unwrap();
    assert_eq!(inv.coordination_identity(), cloned.coordination_identity());
    assert_eq!(
        inv.coordination_identity(),
        reopened.coordination_identity()
    );
    assert_ne!(
        inv.coordination_identity(),
        distinct.coordination_identity()
    );
}

#[tokio::test]
async fn coordination_identity_resolves_symlinks_to_the_same_database() {
    let (dir, inv, _sid) = fixture().await;
    let alias = dir.path().join("alias.db");
    std::os::unix::fs::symlink(dir.path().join("inventory.db"), &alias).unwrap();
    let through_alias = SqliteInventory::open(&alias).await.unwrap();
    assert_eq!(
        inv.coordination_identity(),
        through_alias.coordination_identity(),
        "aliases of one database must share the coordination scope"
    );
}

#[tokio::test]
async fn recreated_server_cannot_inherit_prior_incarnation_provisioning() {
    let (dir, inv, sid) = fixture().await;
    let server = inv.get_server(&sid).await.unwrap().unwrap();
    applied(&inv, &sid).await;
    record(&inv, &sample(&sid, true), 443).await;
    assert_eq!(
        inv.provisioned_service_quality_for_server(&sid, 24, 1)
            .await
            .unwrap()
            .sample_count,
        1,
        "the previous incarnation must actually have measured service"
    );

    inv.remove_server(&sid).await.unwrap();
    inv.add_server(&server).await.unwrap();
    // A fresh connection must not resurrect an old success for this reused ID.
    let reopened = SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .unwrap();
    record(&reopened, &sample(&sid, false), 443).await;
    let measurement = reopened
        .service_quality_measurement_for_server(&sid)
        .await
        .unwrap();
    assert_eq!(measurement.provisioned_at, None);
    assert_eq!(measurement.measurement_started_at, None);
    let quality = reopened
        .provisioned_service_quality_for_server(&sid, 24, 1)
        .await
        .unwrap();
    assert_eq!(quality.sample_count, 0);
    assert_eq!(quality.score, None);
    assert!(
        reopened
            .provisioned_service_quality_samples_for_server(&sid, 24)
            .await
            .unwrap()
            .is_empty()
    );

    // Only a new canonical success can unlock the replacement server.
    applied(&reopened, &sid).await;
    record(&reopened, &sample(&sid, true), 443).await;
    let current = reopened
        .provisioned_service_quality_samples_for_server(&sid, 24)
        .await
        .unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].successes, 3);
}

#[tokio::test]
async fn never_provisioned_quality_is_unknown_even_with_many_failure_samples() {
    let (_dir, inv, sid) = fixture().await;
    for minute in 1..=12 {
        let mut row = sample(&sid, false);
        row.ts -= Duration::minutes(minute);
        record(&inv, &row, 443).await;
    }

    let current = inv
        .provisioned_service_quality_for_server(&sid, 24, 1)
        .await
        .unwrap();
    assert_eq!(current.sample_count, 0);
    assert_eq!(current.score, None);
    assert_eq!(current.availability_pct, None);
    assert!(
        inv.provisioned_service_quality_samples_for_server(&sid, 24)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        inv.service_quality_samples_for_server(&sid, 24)
            .await
            .unwrap()
            .len(),
        12,
        "preprovision evidence must remain in raw history"
    );
    assert_eq!(
        inv.service_quality_measurement_for_server(&sid)
            .await
            .unwrap()
            .provisioned_at,
        None
    );
}

#[tokio::test]
async fn failed_skipped_and_stale_attempts_do_not_provision_service() {
    let (_dir, inv, sid) = fixture().await;
    for action in [
        "server.deploy.failed",
        "server.deploy.skipped",
        "server.deploy.stale",
    ] {
        inv.audit("spec", action, Some(&sid.0), None).await.unwrap();
        record(&inv, &sample(&sid, true), 443).await;
        let measurement = inv
            .service_quality_measurement_for_server(&sid)
            .await
            .unwrap();
        assert_eq!(measurement.provisioned_at, None, "{action} is not success");
        let score = inv
            .provisioned_service_quality_for_server(&sid, 24, 1)
            .await
            .unwrap();
        assert_eq!(score.sample_count, 0, "{action} cannot unlock quality");
        assert_eq!(score.score, None);
    }
}

#[tokio::test]
async fn first_success_excludes_earlier_failures_without_erasing_them() {
    let (_dir, inv, sid) = fixture().await;
    let mut before = sample(&sid, false);
    before.ts -= Duration::minutes(5);
    record(&inv, &before, 443).await;
    applied(&inv, &sid).await;
    let after = sample(&sid, true);
    record(&inv, &after, 443).await;

    let rows = inv
        .provisioned_service_quality_samples_for_server(&sid, 24)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].successes, 3);
    let measurement = inv
        .service_quality_measurement_for_server(&sid)
        .await
        .unwrap();
    assert!(measurement.provisioned_at.is_some());
    assert!(measurement.measurement_started_at.is_some());
    assert!(measurement.target_identity.is_some());
    assert_eq!(
        inv.service_quality_samples_for_server(&sid, 24)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn ordinary_redeploy_preserves_real_failures_and_measurement_epoch() {
    let (dir, inv, sid) = fixture().await;
    applied(&inv, &sid).await;
    record(&inv, &sample(&sid, false), 443).await;
    let before = inv
        .service_quality_measurement_for_server(&sid)
        .await
        .unwrap();
    applied(&inv, &sid).await;
    record(&inv, &sample(&sid, true), 443).await;

    // Reopening is a public persistence boundary, not a simulated worker state.
    let reopened = SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .unwrap();
    let after = reopened
        .service_quality_measurement_for_server(&sid)
        .await
        .unwrap();
    assert_eq!(before.provisioned_at, after.provisioned_at);
    assert_eq!(before.measurement_started_at, after.measurement_started_at);
    assert_eq!(before.target_identity, after.target_identity);
    let score = reopened
        .provisioned_service_quality_for_server(&sid, 24, 1)
        .await
        .unwrap();
    assert_eq!(score.sample_count, 2);
    assert_eq!(score.availability_pct, Some(50.0));
    let rows = reopened
        .provisioned_service_quality_samples_for_server(&sid, 24)
        .await
        .unwrap();
    assert!(rows.iter().any(|row| row.successes == 0));
}

#[tokio::test]
async fn changed_targets_and_return_to_old_targets_do_not_pool_epochs() {
    let (_dir, inv, sid) = fixture().await;
    applied(&inv, &sid).await;
    // Deliberately equal timestamps: insertion order must distinguish A→B→A.
    let failed = sample(&sid, false);
    let mut good = sample(&sid, true);
    good.ts = failed.ts;
    record(&inv, &failed, 443).await;
    let a = inv
        .service_quality_measurement_for_server(&sid)
        .await
        .unwrap();
    record(&inv, &failed, 8443).await;
    let b = inv
        .service_quality_measurement_for_server(&sid)
        .await
        .unwrap();
    assert_ne!(
        a.target_identity, b.target_identity,
        "equal-sized target sets differ"
    );
    assert_eq!(
        inv.provisioned_service_quality_for_server(&sid, 24, 1)
            .await
            .unwrap()
            .sample_count,
        1
    );
    record(&inv, &good, 443).await;
    let current = inv
        .provisioned_service_quality_samples_for_server(&sid, 24)
        .await
        .unwrap();
    assert_eq!(
        current.len(),
        1,
        "return to A starts a new measurement epoch"
    );
    assert_eq!(current[0].successes, 3);
    assert_eq!(
        inv.service_quality_samples_for_server(&sid, 24)
            .await
            .unwrap()
            .len(),
        3,
        "target changes must not erase incident history"
    );
}

#[tokio::test]
async fn target_order_is_canonical_but_control_population_and_vantage_are_not_pooled() {
    let (_dir, inv, sid) = fixture().await;
    applied(&inv, &sid).await;
    let mut row = sample(&sid, false);
    row.target_count = 2;
    inv.record_service_quality_sample_for_targets(
        &row,
        &[target(443), target(8443)],
        &[target(22), target(2222)],
    )
    .await
    .unwrap();
    let first = inv
        .service_quality_measurement_for_server(&sid)
        .await
        .unwrap();
    inv.record_service_quality_sample_for_targets(
        &row,
        &[target(8443), target(443)],
        &[target(2222), target(22)],
    )
    .await
    .unwrap();
    let reordered = inv
        .service_quality_measurement_for_server(&sid)
        .await
        .unwrap();
    assert_eq!(first.target_identity, reordered.target_identity);
    assert_eq!(
        inv.provisioned_service_quality_for_server(&sid, 24, 1)
            .await
            .unwrap()
            .sample_count,
        2
    );

    inv.record_service_quality_sample_for_targets(
        &row,
        &[target(443), target(8443)],
        &[target(22)],
    )
    .await
    .unwrap();
    let control_changed = inv
        .service_quality_measurement_for_server(&sid)
        .await
        .unwrap();
    assert_ne!(first.target_identity, control_changed.target_identity);
    row.vantage = "different spec control host".into();
    inv.record_service_quality_sample_for_targets(
        &row,
        &[target(443), target(8443)],
        &[target(22)],
    )
    .await
    .unwrap();
    let vantage_changed = inv
        .service_quality_measurement_for_server(&sid)
        .await
        .unwrap();
    assert_ne!(
        control_changed.target_identity,
        vantage_changed.target_identity
    );
    assert_eq!(
        inv.provisioned_service_quality_for_server(&sid, 24, 1)
            .await
            .unwrap()
            .sample_count,
        1
    );
}

#[tokio::test]
async fn unidentified_legacy_samples_remain_raw_not_current_quality() {
    let (_dir, inv, sid) = fixture().await;
    applied(&inv, &sid).await;
    inv.record_service_quality_sample(&sample(&sid, false))
        .await
        .unwrap();
    let score = inv
        .provisioned_service_quality_for_server(&sid, 24, 1)
        .await
        .unwrap();
    assert_eq!(score.sample_count, 0);
    assert_eq!(score.score, None);
    assert_eq!(
        inv.service_quality_samples_for_server(&sid, 24)
            .await
            .unwrap()
            .len(),
        1
    );
    record(&inv, &sample(&sid, true), 443).await;
    let current = inv
        .provisioned_service_quality_samples_for_server(&sid, 24)
        .await
        .unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].successes, 3);
}
