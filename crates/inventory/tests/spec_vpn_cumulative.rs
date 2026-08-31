//! Black-box contract tests for cumulative VPN traffic ingestion.
//! Written from the approved public contract only; implementation not consulted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, VpnCumulativeCounter, VpnCumulativeTick};

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir))
        .await
        .expect("open inventory")
}

fn server(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: format!("{id}.example.com"),
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

fn user(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("uuid-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn counter(id: &str, upload_total: u64, download_total: u64) -> VpnCumulativeCounter {
    VpnCumulativeCounter {
        user_id: UserId(id.into()),
        upload_total,
        download_total,
    }
}

fn tick(
    server_upload_total: u64,
    server_download_total: u64,
    uptime_seconds: u64,
    active_connections: u32,
    users: Vec<VpnCumulativeCounter>,
) -> VpnCumulativeTick {
    VpnCumulativeTick {
        server_upload_total,
        server_download_total,
        uptime_seconds,
        active_connections,
        users,
    }
}

#[derive(Debug)]
struct RawRow {
    user_id: Option<String>,
    upload_bytes: u64,
    download_bytes: u64,
    active_connections: u32,
}

async fn rows(dir: &TempDir, server_id: &ServerId) -> Vec<RawRow> {
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(dir).display()))
        .await
        .expect("connect to test inventory");
    let raw: Vec<(Option<String>, i64, i64, i64)> = sqlx::query_as(
        "SELECT user_id, upload_bytes, download_bytes, active_connections \
         FROM vpn_connection_stats WHERE server_id = ? ORDER BY rowid",
    )
    .bind(&server_id.0)
    .fetch_all(&pool)
    .await
    .expect("read raw VPN rows");
    pool.close().await;
    raw.into_iter()
        .map(|(user_id, upload, download, active)| RawRow {
            user_id,
            upload_bytes: upload.try_into().expect("non-negative upload"),
            download_bytes: download.try_into().expect("non-negative download"),
            active_connections: active.try_into().expect("non-negative connections"),
        })
        .collect()
}

fn row_for<'a>(rows: &'a [RawRow], user_id: Option<&str>) -> &'a RawRow {
    rows.iter()
        .find(|row| row.user_id.as_deref() == user_id)
        .unwrap_or_else(|| panic!("missing raw row for {user_id:?}: {rows:?}"))
}

fn sums_for(rows: &[RawRow], user_id: Option<&str>) -> (u64, u64) {
    rows.iter()
        .filter(|row| row.user_id.as_deref() == user_id)
        .fold((0, 0), |(upload, download), row| {
            (upload + row.upload_bytes, download + row.download_bytes)
        })
}

async fn fixture(dir: &TempDir, users: &[&str]) -> (SqliteInventory, ServerId) {
    let inv = open(dir).await;
    let server_id = ServerId("edge-1".into());
    inv.add_server(&server("edge-1")).await.expect("add server");
    for id in users {
        inv.add_user(&user(id)).await.expect("add user");
    }
    (inv, server_id)
}

#[tokio::test]
async fn first_tick_seeds_then_monotonic_tick_persists_users_and_exact_remainder() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice", "bob"]).await;

    let seeded = inv
        .record_vpn_cumulative_stats(
            &server_id,
            &tick(
                1_000,
                2_000,
                3_600,
                2,
                vec![counter("alice", 100, 300), counter("bob", 200, 100)],
            ),
        )
        .await
        .unwrap();
    assert_eq!(seeded, 0, "the first tick only seeds baselines");
    assert!(rows(&dir, &server_id).await.is_empty());

    let written = inv
        .record_vpn_cumulative_stats(
            &server_id,
            &tick(
                1_600,
                2_700,
                3_660,
                7,
                vec![counter("alice", 200, 500), counter("bob", 400, 200)],
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        written, 2,
        "user deltas are immediate; remainder is pending"
    );

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(
            1_600,
            2_700,
            3_720,
            9,
            vec![counter("alice", 200, 500), counter("bob", 400, 200)],
        ),
    )
    .await
    .unwrap();

    let raw = rows(&dir, &server_id).await;
    assert_eq!(sums_for(&raw, Some("alice")), (100, 200));
    assert_eq!(sums_for(&raw, Some("bob")), (200, 100));
    assert_eq!(sums_for(&raw, None), (300, 400));
    assert_eq!(row_for(&raw, None).active_connections, 9);
    assert_eq!(raw.iter().map(|row| row.upload_bytes).sum::<u64>(), 600);
    assert_eq!(raw.iter().map(|row| row.download_bytes).sum::<u64>(), 700);
}

#[tokio::test]
async fn lower_totals_are_resets_and_current_values_become_deltas() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice"]).await;

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(
            5_000,
            7_000,
            86_400,
            1,
            vec![counter("alice", 3_000, 4_000)],
        ),
    )
    .await
    .unwrap();

    let written = inv
        .record_vpn_cumulative_stats(
            &server_id,
            &tick(500, 700, 86_460, 3, vec![counter("alice", 300, 400)]),
        )
        .await
        .unwrap();
    assert_eq!(written, 1);
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(500, 700, 86_520, 4, vec![counter("alice", 300, 400)]),
    )
    .await
    .unwrap();

    let raw = rows(&dir, &server_id).await;
    assert_eq!(sums_for(&raw, Some("alice")), (300, 400));
    assert_eq!(sums_for(&raw, None), (200, 300));
}

#[tokio::test]
async fn lower_uptime_resets_both_directions_even_when_one_counter_increases() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice"]).await;

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_000, 5_000, 86_400, 1, vec![counter("alice", 600, 3_000)]),
    )
    .await
    .unwrap();

    // Create server-ahead pending immediately before the restart.
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_200, 5_300, 86_460, 1, vec![counter("alice", 700, 3_100)]),
    )
    .await
    .unwrap();

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_500, 2_000, 120, 2, vec![counter("alice", 700, 1_000)]),
    )
    .await
    .unwrap();

    let after_restart = rows(&dir, &server_id).await;
    assert_eq!(
        sums_for(&after_restart, None),
        (100, 200),
        "a restart flushes old pending immediately"
    );
    assert_eq!(row_for(&after_restart, None).active_connections, 2);
    assert!(after_restart.iter().any(|row| {
        row.user_id.as_deref() == Some("alice")
            && (row.upload_bytes, row.download_bytes) == (700, 1_000)
    }));

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_500, 2_000, 180, 3, vec![counter("alice", 700, 1_000)]),
    )
    .await
    .unwrap();

    let raw = rows(&dir, &server_id).await;
    assert_eq!(
        sums_for(&raw, Some("alice")),
        (800, 1_100),
        "the restart observation contributes both fresh counter directions"
    );
    assert_eq!(
        sums_for(&raw, None),
        (900, 1_200),
        "old pending flushes and new restart excess matures exactly once"
    );
}

#[tokio::test]
async fn attributed_ahead_credit_is_repaid_without_emitting_bytes_twice() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice"]).await;

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_000, 1_000, 10_000, 1, vec![counter("alice", 500, 500)]),
    )
    .await
    .unwrap();

    // The asynchronous user read is ahead of the server read by 100 upload
    // bytes and 50 download bytes. The exact user delta must survive.
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_100, 1_100, 10_060, 1, vec![counter("alice", 700, 650)]),
    )
    .await
    .unwrap();

    // The server catches up while the user counter is unchanged. Its first
    // 100/50 bytes repay persisted credit; only 100/150 are new remainder.
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_300, 1_300, 10_120, 1, vec![counter("alice", 700, 650)]),
    )
    .await
    .unwrap();

    // The post-credit server excess is itself pending until one more quiet
    // observation proves it was not merely the opposite read order.
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_300, 1_300, 10_180, 1, vec![counter("alice", 700, 650)]),
    )
    .await
    .unwrap();

    let raw = rows(&dir, &server_id).await;
    let (user_upload, user_download) = sums_for(&raw, Some("alice"));
    let (remainder_upload, remainder_download) = sums_for(&raw, None);

    assert_eq!((user_upload, user_download), (200, 150));
    assert_eq!(
        (remainder_upload, remainder_download),
        (100, 150),
        "later server growth must repay per-direction credit before remainder"
    );
    assert_eq!(
        (
            user_upload + remainder_upload,
            user_download + remainder_download
        ),
        (300, 300),
        "raw bytes across both ticks must equal net server growth exactly once"
    );
}

#[tokio::test]
async fn server_ahead_pending_is_consumed_by_delayed_user_catch_up() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice"]).await;

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_000, 1_000, 20_000, 1, vec![counter("alice", 500, 500)]),
    )
    .await
    .unwrap();

    // The inbound read is ahead: 300 server bytes versus 100 user bytes.
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_300, 1_300, 20_060, 1, vec![counter("alice", 600, 600)]),
    )
    .await
    .unwrap();

    // The delayed user read catches up by exactly the 200/200 pending bytes.
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_300, 1_300, 20_120, 1, vec![counter("alice", 800, 800)]),
    )
    .await
    .unwrap();

    let raw = rows(&dir, &server_id).await;
    assert_eq!(sums_for(&raw, Some("alice")), (300, 300));
    assert_eq!(
        sums_for(&raw, None),
        (0, 0),
        "delayed user growth consumes pending instead of duplicating it"
    );
    assert!(
        raw.iter().all(|row| row.user_id.is_some()),
        "zero-byte active observations must not create NULL-user rows"
    );
}

#[tokio::test]
async fn mixed_reconciliation_consumes_prior_pending_before_current_server_growth() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice"]).await;

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_000, 1_000, 30_000, 1, vec![counter("alice", 500, 500)]),
    )
    .await
    .unwrap();

    // Establish 200/200 of prior pending without user growth.
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_200, 1_200, 30_060, 1, vec![counter("alice", 500, 500)]),
    )
    .await
    .unwrap();

    // User growth consumes the prior 200 pending first. The concurrent 100
    // server bytes therefore become the next pending, not an immediate match.
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_300, 1_300, 30_120, 1, vec![counter("alice", 700, 700)]),
    )
    .await
    .unwrap();

    // A final 100 user bytes consume that newer pending exactly.
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_300, 1_300, 30_180, 1, vec![counter("alice", 800, 800)]),
    )
    .await
    .unwrap();

    let raw = rows(&dir, &server_id).await;
    let users = sums_for(&raw, Some("alice"));
    let remainder = sums_for(&raw, None);
    assert_eq!(users, (300, 300), "user deltas remain immediate and exact");
    assert_eq!(remainder, (0, 0), "fully consumed pending is never emitted");
    assert_eq!(
        (users.0 + remainder.0, users.1 + remainder.1),
        (300, 300),
        "mixed reconciliation must not duplicate pending as NULL remainder"
    );
    assert!(raw.iter().all(|row| row.user_id.is_some()));
}

#[tokio::test]
async fn duplicate_users_fail_without_advancing_any_baseline() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice"]).await;

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(100, 100, 10_000, 1, vec![counter("alice", 40, 40)]),
    )
    .await
    .unwrap();

    let duplicate = inv
        .record_vpn_cumulative_stats(
            &server_id,
            &tick(
                200,
                200,
                10_060,
                2,
                vec![counter("alice", 80, 80), counter("alice", 80, 80)],
            ),
        )
        .await;
    assert!(duplicate.is_err(), "duplicate users must reject the tick");
    assert!(rows(&dir, &server_id).await.is_empty());

    let written = inv
        .record_vpn_cumulative_stats(
            &server_id,
            &tick(200, 200, 10_060, 2, vec![counter("alice", 80, 80)]),
        )
        .await
        .unwrap();
    assert_eq!(written, 1);
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(200, 200, 10_120, 3, vec![counter("alice", 80, 80)]),
    )
    .await
    .unwrap();
    let raw = rows(&dir, &server_id).await;
    assert_eq!(sums_for(&raw, Some("alice")), (40, 40));
    assert_eq!(
        sums_for(&raw, None),
        (60, 60),
        "the rejected tick must not advance server or user baselines"
    );
}

#[tokio::test]
async fn unknown_user_rolls_back_rows_and_all_baselines() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice"]).await;

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(100, 100, 10_000, 1, vec![counter("alice", 40, 40)]),
    )
    .await
    .unwrap();

    let unknown = inv
        .record_vpn_cumulative_stats(
            &server_id,
            &tick(
                200,
                200,
                10_060,
                2,
                vec![counter("alice", 80, 80), counter("ghost", 10, 10)],
            ),
        )
        .await;
    assert!(
        unknown.is_err(),
        "an unknown user must reject the whole tick"
    );
    assert!(rows(&dir, &server_id).await.is_empty());

    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(200, 200, 10_060, 2, vec![counter("alice", 80, 80)]),
    )
    .await
    .unwrap();
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(200, 200, 10_120, 3, vec![counter("alice", 80, 80)]),
    )
    .await
    .unwrap();
    let raw = rows(&dir, &server_id).await;
    assert_eq!(sums_for(&raw, Some("alice")), (40, 40));
    assert_eq!(sums_for(&raw, None), (60, 60));
}

#[tokio::test]
async fn reopening_the_database_continues_persisted_baselines() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice"]).await;
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(1_000, 2_000, 172_800, 1, vec![counter("alice", 400, 500)]),
    )
    .await
    .unwrap();
    drop(inv);

    let reopened = open(&dir).await;
    let written = reopened
        .record_vpn_cumulative_stats(
            &server_id,
            &tick(1_300, 2_500, 172_860, 4, vec![counter("alice", 500, 700)]),
        )
        .await
        .unwrap();
    assert_eq!(written, 1);
    reopened
        .record_vpn_cumulative_stats(
            &server_id,
            &tick(1_300, 2_500, 172_920, 5, vec![counter("alice", 500, 700)]),
        )
        .await
        .unwrap();
    let raw = rows(&dir, &server_id).await;
    assert_eq!(sums_for(&raw, Some("alice")), (100, 200));
    assert_eq!(sums_for(&raw, None), (200, 300));
}

#[tokio::test]
async fn empty_user_list_still_writes_the_full_server_remainder_after_seed() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &[]).await;

    assert_eq!(
        inv.record_vpn_cumulative_stats(&server_id, &tick(10, 20, 43_200, 0, vec![]))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        inv.record_vpn_cumulative_stats(&server_id, &tick(25, 50, 43_260, 17, vec![]))
            .await
            .unwrap(),
        0,
        "new inbound excess remains pending for one observation"
    );
    assert_eq!(
        inv.record_vpn_cumulative_stats(&server_id, &tick(25, 50, 43_320, u32::MAX, vec![]),)
            .await
            .unwrap(),
        1
    );

    let raw = rows(&dir, &server_id).await;
    assert_eq!(sums_for(&raw, None), (15, 30));
    assert_eq!(row_for(&raw, None).active_connections, u32::MAX);
}

#[tokio::test]
async fn deleting_a_server_cascades_its_cumulative_baseline() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice"]).await;
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(100, 100, 10_000, 1, vec![counter("alice", 50, 50)]),
    )
    .await
    .unwrap();

    inv.remove_server(&server_id).await.unwrap();
    inv.add_server(&server("edge-1")).await.unwrap();

    let written = inv
        .record_vpn_cumulative_stats(
            &server_id,
            &tick(500, 500, 7_200, 1, vec![counter("alice", 250, 250)]),
        )
        .await
        .unwrap();
    assert_eq!(
        written, 0,
        "recreated server must receive a fresh first tick"
    );
    assert!(rows(&dir, &server_id).await.is_empty());
}

#[tokio::test]
async fn deleting_a_user_cascades_only_that_users_cumulative_baseline() {
    let dir = TempDir::new().unwrap();
    let (inv, server_id) = fixture(&dir, &["alice"]).await;
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(100, 100, 10_000, 1, vec![counter("alice", 40, 40)]),
    )
    .await
    .unwrap();

    inv.remove_user(&UserId("alice".into())).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    let written = inv
        .record_vpn_cumulative_stats(
            &server_id,
            &tick(150, 150, 10_060, 1, vec![counter("alice", 10, 10)]),
        )
        .await
        .unwrap();
    assert_eq!(
        written, 0,
        "the recreated user is seeded and new inbound excess remains pending"
    );
    inv.record_vpn_cumulative_stats(
        &server_id,
        &tick(150, 150, 10_120, 2, vec![counter("alice", 10, 10)]),
    )
    .await
    .unwrap();
    let raw = rows(&dir, &server_id).await;
    assert_eq!(sums_for(&raw, None), (50, 50));
}
