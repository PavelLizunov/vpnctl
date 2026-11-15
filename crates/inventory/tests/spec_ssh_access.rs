#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Independent integration tests derived from docs/specs/ssh-access-status.md.

use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;
use vpnctl_core::{Server, ServerId};
use vpnctl_inventory::{
    SqliteInventory, SshAccessCheck, SshAccessFailure, SshAccessRoute, SshAccessState,
};

fn server(id: &str, address: &str) -> Server {
    Server {
        id: ServerId(id.to_owned()),
        address: address.to_owned(),
        ssh_port: 22,
        ssh_user: "root".to_owned(),
        kernels: Vec::new(),
        enabled_protocols: Vec::new(),
        trusted_host_fingerprint: Some(
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        ),
        hoster: "spec-fixture".to_owned(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn observed_at() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

fn check(
    state: SshAccessState,
    failure: Option<SshAccessFailure>,
    checked_at: DateTime<Utc>,
) -> SshAccessCheck {
    SshAccessCheck {
        state,
        failure,
        checked_at,
    }
}

fn available(checked_at: DateTime<Utc>) -> SshAccessCheck {
    check(SshAccessState::Available, None, checked_at)
}

fn assert_check(actual: Option<SshAccessCheck>, expected: &SshAccessCheck) {
    let actual = actual.expect("expected a persisted SSH observation");
    assert_eq!(actual.state, expected.state);
    assert_eq!(actual.failure, expected.failure);
    assert_eq!(actual.checked_at, expected.checked_at);
}

async fn fixture() -> (TempDir, SqliteInventory, Server, Server) {
    let dir = TempDir::new().unwrap();
    let inventory = SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .unwrap();
    let jump = server("jump", "192.0.2.10");
    let mut target = server("target", "192.0.2.20");
    target.jump_via = Some(jump.id.clone());
    inventory.add_server(&jump).await.unwrap();
    inventory.add_server(&target).await.unwrap();
    (dir, inventory, target, jump)
}

async fn audit_count(inventory: &SqliteInventory) -> usize {
    inventory.recent_audit(1000).await.unwrap().len()
}

// Mutations model an independent operator changing the current inventory while a
// persisted observation still contains the endpoint used by the earlier probe.
async fn update_endpoint(path: &Path, id: &ServerId, column: &str, value: &str) {
    let statement = match column {
        "address" => "UPDATE servers SET address = ? WHERE id = ?",
        "ssh_port" => "UPDATE servers SET ssh_port = ? WHERE id = ?",
        "ssh_user" => "UPDATE servers SET ssh_user = ? WHERE id = ?",
        "trusted_host_fingerprint" => {
            "UPDATE servers SET trusted_host_fingerprint = ? WHERE id = ?"
        }
        "jump_via" => "UPDATE servers SET jump_via = ? WHERE id = ?",
        _ => panic!("unsupported fixture mutation"),
    };
    let options = SqliteConnectOptions::new().filename(path);
    let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
    let result = sqlx::query(statement)
        .bind(value)
        .bind(&id.0)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(result.rows_affected(), 1);
    pool.close().await;
}

#[tokio::test]
async fn independent_routes_persist_for_servers_without_kernels() {
    let (dir, inventory, target, jump) = fixture().await;
    let at = observed_at();
    let initial = inventory
        .ssh_access_for_server(&target.id, at, 300)
        .await
        .unwrap();
    assert!(initial.direct.is_none());
    assert!(initial.jump.is_none());

    let direct = check(
        SshAccessState::Unavailable,
        Some(SshAccessFailure::Authentication),
        at,
    );
    let via_jump = available(at + Duration::seconds(1));
    inventory
        .record_ssh_access(&target, SshAccessRoute::Direct, None, &direct)
        .await
        .unwrap();
    inventory
        .record_ssh_access(&target, SshAccessRoute::Jump, Some(&jump), &via_jump)
        .await
        .unwrap();
    let status = inventory
        .ssh_access_for_server(&target.id, at + Duration::seconds(1), 300)
        .await
        .unwrap();
    assert_check(status.direct, &direct);
    assert_check(status.jump, &via_jump);

    drop(inventory);
    let reopened = SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .unwrap();
    let status = reopened
        .ssh_access_for_server(&target.id, at + Duration::seconds(1), 300)
        .await
        .unwrap();
    assert_check(status.direct, &direct);
    assert_check(status.jump, &via_jump);
}

#[tokio::test]
async fn invalid_observations_leave_both_routes_and_audit_unchanged() {
    let (_dir, inventory, target, jump) = fixture().await;
    let at = observed_at();
    let original = available(at);
    inventory
        .record_ssh_access(&target, SshAccessRoute::Direct, None, &original)
        .await
        .unwrap();
    inventory
        .record_ssh_access(&target, SshAccessRoute::Jump, Some(&jump), &original)
        .await
        .unwrap();
    let without_jump = server("direct-only", "192.0.2.91");
    inventory.add_server(&without_jump).await.unwrap();
    let audits_before = audit_count(&inventory).await;

    let malformed_available = check(
        SshAccessState::Available,
        Some(SshAccessFailure::Connection),
        at + Duration::seconds(1),
    );
    let malformed_unavailable = check(SshAccessState::Unavailable, None, at + Duration::seconds(1));
    let future = available(Utc::now() + Duration::days(1));
    for invalid in [malformed_available, malformed_unavailable, future] {
        assert!(
            inventory
                .record_ssh_access(&target, SshAccessRoute::Direct, None, &invalid)
                .await
                .is_err()
        );
    }
    assert!(
        inventory
            .record_ssh_access(&target, SshAccessRoute::Direct, Some(&jump), &original)
            .await
            .is_err()
    );
    let wrong_jump = server("wrong-jump", "192.0.2.99");
    assert!(
        inventory
            .record_ssh_access(&target, SshAccessRoute::Jump, Some(&wrong_jump), &original)
            .await
            .is_err()
    );
    assert!(
        inventory
            .record_ssh_access(&target, SshAccessRoute::Jump, None, &original)
            .await
            .is_err()
    );
    let missing = server("missing", "192.0.2.90");
    assert!(
        inventory
            .record_ssh_access(&missing, SshAccessRoute::Direct, None, &original)
            .await
            .is_err()
    );
    assert!(
        inventory
            .ssh_access_for_server(&missing.id, at, 300)
            .await
            .is_err()
    );
    assert!(
        inventory
            .record_ssh_access(&without_jump, SshAccessRoute::Jump, Some(&jump), &original)
            .await
            .is_err()
    );

    let status = inventory
        .ssh_access_for_server(&target.id, at + Duration::seconds(1), 300)
        .await
        .unwrap();
    assert_check(status.direct, &original);
    assert_check(status.jump, &original);
    assert_eq!(audit_count(&inventory).await, audits_before);
}

#[tokio::test]
async fn missing_jump_details_can_persist_typed_unknown() {
    let (_dir, inventory, target, _jump) = fixture().await;
    let at = observed_at();
    let unknown = check(
        SshAccessState::Unknown,
        Some(SshAccessFailure::InvalidRoute),
        at,
    );
    inventory
        .record_ssh_access(&target, SshAccessRoute::Jump, None, &unknown)
        .await
        .unwrap();
    let status = inventory
        .ssh_access_for_server(&target.id, at, 300)
        .await
        .unwrap();
    assert!(status.direct.is_none());
    assert_check(status.jump, &unknown);
}

#[tokio::test]
async fn freshness_includes_zero_and_exact_max_age_and_preserves_timestamps() {
    let (_dir, inventory, target, _jump) = fixture().await;
    let at = observed_at();
    let original = available(at);
    inventory
        .record_ssh_access(&target, SshAccessRoute::Direct, None, &original)
        .await
        .unwrap();
    let audits_before = audit_count(&inventory).await;
    for (now, max_age) in [(at, 0), (at, 300), (at + Duration::seconds(300), 300)] {
        let status = inventory
            .ssh_access_for_server(&target.id, now, max_age)
            .await
            .unwrap();
        assert_check(status.direct, &original);
    }
    let stale = check(SshAccessState::Unknown, Some(SshAccessFailure::Stale), at);
    for (now, max_age) in [
        (at + Duration::seconds(1), 0),
        (at + Duration::seconds(301), 300),
        (at - Duration::seconds(1), 300),
    ] {
        let status = inventory
            .ssh_access_for_server(&target.id, now, max_age)
            .await
            .unwrap();
        assert_check(status.direct, &stale);
    }
    let fresh_again = inventory
        .ssh_access_for_server(&target.id, at, 300)
        .await
        .unwrap();
    assert_check(fresh_again.direct, &original);
    assert_eq!(audit_count(&inventory).await, audits_before);
}

#[tokio::test]
async fn older_and_equal_observations_cannot_replace_either_route_or_add_audits() {
    let (_dir, inventory, target, jump) = fixture().await;
    let at = observed_at();
    let latest = available(at);
    for (route, via) in [
        (SshAccessRoute::Direct, None),
        (SshAccessRoute::Jump, Some(&jump)),
    ] {
        inventory
            .record_ssh_access(&target, route, via, &latest)
            .await
            .unwrap();
    }
    let audits_before = audit_count(&inventory).await;
    for timestamp in [at - Duration::seconds(1), at] {
        let older = check(
            SshAccessState::Unavailable,
            Some(SshAccessFailure::Timeout),
            timestamp,
        );
        for (route, via) in [
            (SshAccessRoute::Direct, None),
            (SshAccessRoute::Jump, Some(&jump)),
        ] {
            inventory
                .record_ssh_access(&target, route, via, &older)
                .await
                .unwrap();
        }
    }
    let status = inventory
        .ssh_access_for_server(&target.id, at, 300)
        .await
        .unwrap();
    assert_check(status.direct, &latest);
    assert_check(status.jump, &latest);
    assert_eq!(audit_count(&inventory).await, audits_before);
}

#[tokio::test]
async fn target_endpoint_and_pin_changes_invalidate_both_routes() {
    for (column, value) in [
        ("address", "192.0.2.21"),
        ("ssh_port", "2222"),
        ("ssh_user", "operator"),
        (
            "trusted_host_fingerprint",
            "SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        ),
    ] {
        let (dir, inventory, target, jump) = fixture().await;
        let at = observed_at();
        for (route, via) in [
            (SshAccessRoute::Direct, None),
            (SshAccessRoute::Jump, Some(&jump)),
        ] {
            inventory
                .record_ssh_access(&target, route, via, &available(at))
                .await
                .unwrap();
        }
        update_endpoint(&dir.path().join("inventory.db"), &target.id, column, value).await;
        let status = inventory
            .ssh_access_for_server(&target.id, at, 300)
            .await
            .unwrap();
        assert!(status.direct.is_none(), "target {column} changed");
        assert!(status.jump.is_none(), "target {column} changed");
    }
}

#[tokio::test]
async fn jump_endpoint_and_pin_changes_invalidate_only_jump() {
    for (column, value) in [
        ("address", "192.0.2.11"),
        ("ssh_port", "2222"),
        ("ssh_user", "operator"),
        (
            "trusted_host_fingerprint",
            "SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        ),
    ] {
        let (dir, inventory, target, jump) = fixture().await;
        let at = observed_at();
        let original = available(at);
        inventory
            .record_ssh_access(&target, SshAccessRoute::Direct, None, &original)
            .await
            .unwrap();
        inventory
            .record_ssh_access(&target, SshAccessRoute::Jump, Some(&jump), &original)
            .await
            .unwrap();
        update_endpoint(&dir.path().join("inventory.db"), &jump.id, column, value).await;
        let status = inventory
            .ssh_access_for_server(&target.id, at, 300)
            .await
            .unwrap();
        assert_check(status.direct, &original);
        assert!(status.jump.is_none(), "jump {column} changed");
    }
}

#[tokio::test]
async fn changing_configured_jump_preserves_direct_and_invalidates_jump() {
    let (dir, inventory, target, jump) = fixture().await;
    let at = observed_at();
    let original = available(at);
    for (route, via) in [
        (SshAccessRoute::Direct, None),
        (SshAccessRoute::Jump, Some(&jump)),
    ] {
        inventory
            .record_ssh_access(&target, route, via, &original)
            .await
            .unwrap();
    }
    let alternate = server("alternate-jump", "192.0.2.30");
    inventory.add_server(&alternate).await.unwrap();
    update_endpoint(
        &dir.path().join("inventory.db"),
        &target.id,
        "jump_via",
        &alternate.id.0,
    )
    .await;
    let status = inventory
        .ssh_access_for_server(&target.id, at, 300)
        .await
        .unwrap();
    assert_check(status.direct, &original);
    assert!(status.jump.is_none());
}

#[tokio::test]
async fn equivalent_heartbeats_update_time_without_duplicate_audits() {
    let (dir, inventory, target, _jump) = fixture().await;
    let at = observed_at();
    let before = audit_count(&inventory).await;
    let initial = available(at);
    inventory
        .record_ssh_access(&target, SshAccessRoute::Direct, None, &initial)
        .await
        .unwrap();
    assert_eq!(audit_count(&inventory).await, before + 1);
    let heartbeat = available(at + Duration::seconds(1));
    inventory
        .record_ssh_access(&target, SshAccessRoute::Direct, None, &heartbeat)
        .await
        .unwrap();
    assert_eq!(audit_count(&inventory).await, before + 1);
    let status = inventory
        .ssh_access_for_server(&target.id, heartbeat.checked_at, 300)
        .await
        .unwrap();
    assert_check(status.direct, &heartbeat);

    for (offset, failure) in [
        (2, SshAccessFailure::Connection),
        (3, SshAccessFailure::Authentication),
    ] {
        let changed = check(
            SshAccessState::Unavailable,
            Some(failure),
            at + Duration::seconds(offset),
        );
        inventory
            .record_ssh_access(&target, SshAccessRoute::Direct, None, &changed)
            .await
            .unwrap();
        assert_eq!(audit_count(&inventory).await, before + offset as usize);
    }

    update_endpoint(
        &dir.path().join("inventory.db"),
        &target.id,
        "address",
        "192.0.2.21",
    )
    .await;
    let changed_target = inventory.get_server(&target.id).await.unwrap().unwrap();
    let new_identity = check(
        SshAccessState::Unavailable,
        Some(SshAccessFailure::Authentication),
        at + Duration::seconds(4),
    );
    inventory
        .record_ssh_access(&changed_target, SshAccessRoute::Direct, None, &new_identity)
        .await
        .unwrap();
    assert_eq!(audit_count(&inventory).await, before + 4);
    let status = inventory
        .ssh_access_for_server(&target.id, new_identity.checked_at, 300)
        .await
        .unwrap();
    assert_check(status.direct, &new_identity);
}
