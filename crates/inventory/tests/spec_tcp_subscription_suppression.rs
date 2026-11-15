#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Duration, Utc};
use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctl_inventory::{ServiceQualitySample, SqliteInventory};

const PATH_A: &str = "office-network:tcp-population-a";
const PATH_B: &str = "other-network:tcp-population-b";
const GAP: u64 = 3600;

#[derive(Clone, Copy)]
enum Round {
    Failure,
    Partial,
    Success,
    IncompleteTargets,
    Unknown,
}

fn server(id: &str, address: &str) -> Server {
    Server {
        id: ServerId(id.to_owned()),
        address: address.to_owned(),
        ssh_port: 22,
        ssh_user: "root".to_owned(),
        kernels: Vec::<KernelId>::new(),
        enabled_protocols: Vec::<ProtocolId>::new(),
        trusted_host_fingerprint: None,
        hoster: "spec-fixture".to_owned(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn sample(server: &Server, ts: DateTime<Utc>, round: Round) -> ServiceQualitySample {
    let (target_count, available_targets, attempts, successes) = match round {
        Round::Failure => (2, 0, 4, 0),
        Round::Partial => (2, 1, 4, 1),
        Round::Success => (2, 2, 4, 4),
        Round::IncompleteTargets => (2, 1, 4, 4),
        Round::Unknown => (0, 0, 0, 0),
    };
    ServiceQualitySample {
        ts,
        server_id: server.id.clone(),
        vantage: "spec-observer".to_owned(),
        target_count,
        available_targets,
        attempts,
        successes,
        tcp_rtt_ms: (0..successes).map(|_| 35).collect(),
        control_attempts: 0,
        control_successes: 0,
        control_rtt_ms: Vec::new(),
        icmp_attempts: None,
        icmp_successes: None,
        icmp_rtt_ms: None,
    }
}

async fn inventory() -> (TempDir, SqliteInventory) {
    let directory = tempfile::tempdir().unwrap();
    let inventory = SqliteInventory::open(&directory.path().join("inventory.db"))
        .await
        .unwrap();
    (directory, inventory)
}

async fn registered(inventory: &SqliteInventory, id: &str, address: &str) -> Server {
    let server = server(id, address);
    inventory
        .register_server(&server, "spec-test")
        .await
        .unwrap();
    server
}

async fn record(
    inventory: &SqliteInventory,
    server: &Server,
    ts: DateTime<Utc>,
    identity: &str,
    round: Round,
    gap: u64,
) {
    inventory
        .record_service_path(&sample(server, ts, round), identity, gap)
        .await
        .unwrap();
}

async fn suppressed(inventory: &SqliteInventory, server: &Server) -> bool {
    inventory
        .is_server_auto_suppressed(&server.id)
        .await
        .unwrap()
}

async fn toggle_audits(inventory: &SqliteInventory) -> (usize, usize) {
    let audit = inventory.recent_audit(1000).await.unwrap();
    (
        audit
            .iter()
            .filter(|entry| entry.action == "server.auto_suppressed")
            .count(),
        audit
            .iter()
            .filter(|entry| entry.action == "server.auto_restored")
            .count(),
    )
}

#[tokio::test]
async fn registration_opts_in_while_low_level_addition_retains_opt_out() {
    let (_directory, inventory) = inventory().await;
    let low_level = server("fixture", "198.51.100.42");
    inventory.add_server(&low_level).await.unwrap();
    let registered = registered(&inventory, "registered", "198.51.100.43").await;

    assert_eq!(
        inventory
            .server_auto_suppress_state(&low_level.id)
            .await
            .unwrap(),
        (false, None)
    );
    assert_eq!(
        inventory
            .server_auto_suppress_state(&registered.id)
            .await
            .unwrap(),
        (true, None)
    );
    assert!(!suppressed(&inventory, &low_level).await);
    assert!(!suppressed(&inventory, &registered).await);
    assert_eq!(toggle_audits(&inventory).await, (0, 0));
}

#[tokio::test]
async fn only_consecutive_full_failures_hide_and_consecutive_full_successes_restore() {
    let (_directory, inventory) = inventory().await;
    let server = registered(&inventory, "rounds", "198.51.100.42").await;
    let anchor = Utc::now() - Duration::minutes(10);
    let rounds = [
        (Round::Failure, false),
        (Round::Unknown, false),
        (Round::Failure, false),
        (Round::Partial, false),
        (Round::Failure, false),
        (Round::Failure, true),
        (Round::Success, true),
        (Round::Partial, true),
        (Round::Success, true),
        (Round::Unknown, true),
        (Round::Success, true),
        (Round::IncompleteTargets, true),
        (Round::Success, true),
        (Round::Success, false),
    ];

    for (index, (round, expected)) in rounds.into_iter().enumerate() {
        record(
            &inventory,
            &server,
            anchor + Duration::seconds(i64::try_from(index).unwrap()),
            PATH_A,
            round,
            GAP,
        )
        .await;
        assert_eq!(
            suppressed(&inventory, &server).await,
            expected,
            "suppression after round {index}"
        );
    }
    assert_eq!(toggle_audits(&inventory).await, (1, 1));
}

#[tokio::test]
async fn failure_and_recovery_streaks_survive_reopening_the_inventory() {
    let (directory, inventory) = inventory().await;
    let server = registered(&inventory, "persistent", "198.51.100.42").await;
    let anchor = Utc::now() - Duration::minutes(10);
    record(&inventory, &server, anchor, PATH_A, Round::Failure, GAP).await;
    drop(inventory);

    let inventory = SqliteInventory::open(&directory.path().join("inventory.db"))
        .await
        .unwrap();
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(1),
        PATH_A,
        Round::Failure,
        GAP,
    )
    .await;
    assert!(suppressed(&inventory, &server).await);
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(2),
        PATH_A,
        Round::Success,
        GAP,
    )
    .await;
    drop(inventory);

    let inventory = SqliteInventory::open(&directory.path().join("inventory.db"))
        .await
        .unwrap();
    assert!(suppressed(&inventory, &server).await);
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(3),
        PATH_A,
        Round::Success,
        GAP,
    )
    .await;
    assert!(!suppressed(&inventory, &server).await);
    assert_eq!(toggle_audits(&inventory).await, (1, 1));
}

#[tokio::test]
async fn servers_and_paths_have_independent_failure_and_recovery_streaks() {
    let (_directory, inventory) = inventory().await;
    let first = registered(&inventory, "first", "198.51.100.42").await;
    let second = registered(&inventory, "second", "198.51.100.43").await;
    let anchor = Utc::now() - Duration::minutes(10);

    record(&inventory, &first, anchor, PATH_A, Round::Failure, GAP).await;
    record(
        &inventory,
        &first,
        anchor + Duration::seconds(1),
        PATH_B,
        Round::Failure,
        GAP,
    )
    .await;
    assert!(!suppressed(&inventory, &first).await);
    record(&inventory, &second, anchor, PATH_A, Round::Failure, GAP).await;
    assert!(!suppressed(&inventory, &second).await);
    record(
        &inventory,
        &second,
        anchor + Duration::seconds(1),
        PATH_A,
        Round::Failure,
        GAP,
    )
    .await;
    assert!(suppressed(&inventory, &second).await);
    record(
        &inventory,
        &first,
        anchor + Duration::seconds(2),
        PATH_A,
        Round::Failure,
        GAP,
    )
    .await;
    assert!(suppressed(&inventory, &first).await);
    record(
        &inventory,
        &first,
        anchor + Duration::seconds(3),
        PATH_A,
        Round::Success,
        GAP,
    )
    .await;
    record(
        &inventory,
        &first,
        anchor + Duration::seconds(4),
        PATH_B,
        Round::Success,
        GAP,
    )
    .await;
    assert!(suppressed(&inventory, &first).await);
    record(
        &inventory,
        &first,
        anchor + Duration::seconds(5),
        PATH_B,
        Round::Success,
        GAP,
    )
    .await;
    assert!(!suppressed(&inventory, &first).await);
    assert!(suppressed(&inventory, &second).await);
    assert_eq!(toggle_audits(&inventory).await, (2, 1));
}

#[tokio::test]
async fn duplicates_and_per_path_out_of_order_samples_do_not_advance_streaks() {
    let (_directory, inventory) = inventory().await;
    let server = registered(&inventory, "ordered", "198.51.100.42").await;
    let anchor = Utc::now() - Duration::minutes(10);

    for offset in [0, 0, -1] {
        record(
            &inventory,
            &server,
            anchor + Duration::seconds(offset),
            PATH_A,
            Round::Failure,
            GAP,
        )
        .await;
        assert!(!suppressed(&inventory, &server).await);
    }
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(1),
        PATH_A,
        Round::Failure,
        GAP,
    )
    .await;
    assert!(suppressed(&inventory, &server).await);
    for offset in [2, 2, 1] {
        record(
            &inventory,
            &server,
            anchor + Duration::seconds(offset),
            PATH_A,
            Round::Success,
            GAP,
        )
        .await;
        assert!(suppressed(&inventory, &server).await);
    }
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(3),
        PATH_A,
        Round::Success,
        GAP,
    )
    .await;
    assert!(!suppressed(&inventory, &server).await);
    assert_eq!(toggle_audits(&inventory).await, (1, 1));
}

#[tokio::test]
async fn stale_samples_never_hide_or_restore_a_server() {
    let (_directory, inventory) = inventory().await;
    let server = registered(&inventory, "stale", "198.51.100.42").await;
    let anchor = Utc::now() - Duration::minutes(10);

    for offset in [0, 1] {
        record(
            &inventory,
            &server,
            anchor + Duration::seconds(offset),
            PATH_A,
            Round::Failure,
            60,
        )
        .await;
        assert!(!suppressed(&inventory, &server).await);
    }
    assert_eq!(toggle_audits(&inventory).await, (0, 0));

    for offset in [2, 3] {
        record(
            &inventory,
            &server,
            anchor + Duration::seconds(offset),
            PATH_A,
            Round::Failure,
            GAP,
        )
        .await;
    }
    assert!(suppressed(&inventory, &server).await);
    for offset in [4, 5] {
        record(
            &inventory,
            &server,
            anchor + Duration::seconds(offset),
            PATH_A,
            Round::Success,
            60,
        )
        .await;
        assert!(suppressed(&inventory, &server).await);
    }
    assert_eq!(toggle_audits(&inventory).await, (1, 0));
}

#[tokio::test]
async fn gaps_reset_unconfirmed_streaks_but_preserve_confirmed_incidents() {
    let (_directory, inventory) = inventory().await;
    let server = registered(&inventory, "gaps", "198.51.100.42").await;
    let boundary = registered(&inventory, "gap-boundary", "198.51.100.43").await;
    let now = Utc::now();
    record(
        &inventory,
        &boundary,
        now - Duration::seconds(100),
        PATH_A,
        Round::Failure,
        GAP,
    )
    .await;
    record(
        &inventory,
        &boundary,
        now - Duration::seconds(40),
        PATH_A,
        Round::Failure,
        60,
    )
    .await;
    assert!(suppressed(&inventory, &boundary).await);
    record(
        &inventory,
        &server,
        now - Duration::seconds(600),
        PATH_A,
        Round::Failure,
        GAP,
    )
    .await;
    record(
        &inventory,
        &server,
        now - Duration::seconds(200),
        PATH_A,
        Round::Failure,
        300,
    )
    .await;
    assert!(!suppressed(&inventory, &server).await);
    record(
        &inventory,
        &server,
        now - Duration::seconds(190),
        PATH_A,
        Round::Failure,
        300,
    )
    .await;
    assert!(suppressed(&inventory, &server).await);

    inventory
        .set_server_auto_suppress(&server.id, false)
        .await
        .unwrap();
    assert!(!suppressed(&inventory, &server).await);
    inventory
        .set_server_auto_suppress(&server.id, true)
        .await
        .unwrap();
    record(
        &inventory,
        &server,
        now - Duration::seconds(40),
        PATH_A,
        Round::Failure,
        60,
    )
    .await;
    assert!(suppressed(&inventory, &server).await);
    record(
        &inventory,
        &server,
        now - Duration::seconds(30),
        PATH_A,
        Round::Success,
        60,
    )
    .await;
    assert!(suppressed(&inventory, &server).await);
    record(
        &inventory,
        &server,
        now - Duration::seconds(20),
        PATH_A,
        Round::Success,
        60,
    )
    .await;
    assert!(!suppressed(&inventory, &server).await);
}

#[tokio::test]
async fn opting_out_clears_suppression_immediately_and_prevents_new_toggles() {
    let (_directory, inventory) = inventory().await;
    let server = server("opt-out", "198.51.100.42");
    inventory.add_server(&server).await.unwrap();
    let anchor = Utc::now() - Duration::minutes(10);
    for offset in [0, 1] {
        record(
            &inventory,
            &server,
            anchor + Duration::seconds(offset),
            PATH_A,
            Round::Failure,
            GAP,
        )
        .await;
    }
    assert!(!suppressed(&inventory, &server).await);
    inventory
        .set_server_auto_suppress(&server.id, true)
        .await
        .unwrap();
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(2),
        PATH_A,
        Round::Failure,
        GAP,
    )
    .await;
    assert!(suppressed(&inventory, &server).await);
    inventory
        .set_server_auto_suppress(&server.id, false)
        .await
        .unwrap();
    assert!(!suppressed(&inventory, &server).await);
    for offset in [3, 4] {
        record(
            &inventory,
            &server,
            anchor + Duration::seconds(offset),
            PATH_A,
            Round::Failure,
            GAP,
        )
        .await;
    }
    inventory
        .set_server_auto_suppress(&server.id, false)
        .await
        .unwrap();
    assert_eq!(
        inventory
            .server_auto_suppress_state(&server.id)
            .await
            .unwrap(),
        (false, None)
    );
    assert!(!suppressed(&inventory, &server).await);
    assert_eq!(toggle_audits(&inventory).await, (1, 1));
}

#[tokio::test]
async fn invalid_samples_fail_without_audit_or_detector_mutation() {
    let (_directory, inventory) = inventory().await;
    let server = registered(&inventory, "invalid", "198.51.100.42").await;
    let anchor = Utc::now() - Duration::minutes(10);
    record(&inventory, &server, anchor, PATH_A, Round::Failure, GAP).await;
    let before: Vec<_> = inventory
        .recent_audit(1000)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| (entry.action, entry.target))
        .collect();
    let later = anchor + Duration::seconds(1);
    let mut invalid = Vec::new();
    let mut bad_targets = sample(&server, later, Round::Failure);
    bad_targets.available_targets = bad_targets.target_count + 1;
    invalid.push((bad_targets, PATH_A));
    let mut bad_successes = sample(&server, later, Round::Success);
    bad_successes.successes = bad_successes.attempts + 1;
    invalid.push((bad_successes, PATH_A));
    let mut bad_control = sample(&server, later, Round::Failure);
    bad_control.control_attempts = 1;
    bad_control.control_successes = 2;
    bad_control.control_rtt_ms = vec![20, 21];
    invalid.push((bad_control, PATH_A));
    let mut bad_icmp = sample(&server, later, Round::Failure);
    bad_icmp.icmp_attempts = Some(1);
    bad_icmp.icmp_successes = Some(2);
    bad_icmp.icmp_rtt_ms = Some(vec![20, 21]);
    invalid.push((bad_icmp, PATH_A));
    invalid.push((
        sample(&server, Utc::now() + Duration::hours(1), Round::Failure),
        PATH_A,
    ));
    invalid.push((sample(&server, later, Round::Failure), ""));
    invalid.push((sample(&server, later, Round::Failure), " \t "));
    let mut bad_vantage = sample(&server, later, Round::Failure);
    bad_vantage.vantage = " \t ".to_owned();
    invalid.push((bad_vantage, PATH_A));

    for (index, (sample, identity)) in invalid.into_iter().enumerate() {
        assert!(
            inventory
                .record_service_path(&sample, identity, GAP)
                .await
                .is_err(),
            "invalid sample {index} must fail"
        );
        assert!(!suppressed(&inventory, &server).await);
    }
    let after: Vec<_> = inventory
        .recent_audit(1000)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| (entry.action, entry.target))
        .collect();
    assert_eq!(before, after);
    record(&inventory, &server, later, PATH_A, Round::Failure, GAP).await;
    assert!(suppressed(&inventory, &server).await);
    assert_eq!(toggle_audits(&inventory).await, (1, 0));
}

#[tokio::test]
async fn latest_path_controls_hiding_with_insertion_order_breaking_timestamp_ties() {
    let (_directory, inventory) = inventory().await;
    let server = registered(&inventory, "latest", "198.51.100.42").await;
    let anchor = Utc::now() - Duration::minutes(10);
    record(&inventory, &server, anchor, PATH_A, Round::Failure, GAP).await;
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(20),
        PATH_B,
        Round::Partial,
        GAP,
    )
    .await;
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(10),
        PATH_A,
        Round::Failure,
        GAP,
    )
    .await;
    assert!(!suppressed(&inventory, &server).await);
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(20),
        PATH_A,
        Round::Failure,
        GAP,
    )
    .await;
    assert!(!suppressed(&inventory, &server).await);
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(21),
        PATH_A,
        Round::Failure,
        GAP,
    )
    .await;
    assert!(suppressed(&inventory, &server).await);

    record(
        &inventory,
        &server,
        anchor + Duration::seconds(40),
        PATH_A,
        Round::Partial,
        GAP,
    )
    .await;
    for offset in [25, 35] {
        record(
            &inventory,
            &server,
            anchor + Duration::seconds(offset),
            PATH_B,
            Round::Success,
            GAP,
        )
        .await;
        assert!(suppressed(&inventory, &server).await);
    }
    record(
        &inventory,
        &server,
        anchor + Duration::seconds(50),
        PATH_B,
        Round::Success,
        GAP,
    )
    .await;
    assert!(!suppressed(&inventory, &server).await);
    assert_eq!(toggle_audits(&inventory).await, (1, 1));
}
