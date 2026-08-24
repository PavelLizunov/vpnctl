//! Spec for `SqliteInventory::uptime_for_server` (`UptimeStat`).
//! Written from spec only — impl NOT consulted.
//! `record_node_health` always stamps `ts=now`; to pin specific ages
//! we raw-INSERT via a second sqlx pool to the same DB file with the
//! same ISO format the production writer uses. Same pattern as
//! `spec_sub_access.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use tempfile::TempDir;

use vpnctl_core::{KernelId, Server, ServerId};
use vpnctl_inventory::SqliteInventory;

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn srv(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "1.1.1.1".into(),
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

async fn raw_pool(path: &Path) -> sqlx::SqlitePool {
    sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
        .await
        .expect("raw pool")
}

/// Insert `node_health` row at `now - hours_ago h` with given sba
/// (None → SQL NULL → "unknown"). Only ts + sba matter for uptime.
async fn ins(pool: &sqlx::SqlitePool, sid: &str, sba: Option<bool>, hours_ago: i64) {
    let sample_id = format!("uptime-{sid}-{hours_ago}-{}", vpnctl_crypto::gen_uuid());
    sqlx::query(
        "INSERT INTO node_health (sample_id, ts, server_id, sing_box_active)
         VALUES (?1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2), ?3, ?4)",
    )
    .bind(sample_id)
    .bind(format!("-{hours_ago} hours"))
    .bind(sid)
    .bind(sba.map(i64::from))
    .execute(pool)
    .await
    .expect("INSERT node_health");
}

async fn stat(inv: &SqliteInventory, sid: &str, win: u32) -> vpnctl_inventory::UptimeStat {
    inv.uptime_for_server(&ServerId(sid.into()), win)
        .await
        .expect("uptime_for_server")
}

// 1. Empty server: every counter zero, every Option None.
#[tokio::test]
async fn empty_server_returns_all_zero_uptime_stat() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    let s = stat(&inv, "s1", 24).await;
    assert_eq!(s.window_hours, 24);
    assert_eq!(s.total_rows, 0);
    assert_eq!(s.up_rows, 0);
    assert_eq!(s.down_rows, 0);
    assert_eq!(s.unknown_rows, 0);
    assert_eq!(s.uptime_pct, None);
    assert!(s.last_outage_at.is_none());
    assert!(s.last_probe_at.is_none());
}

// 2. All-up: pct=100, no last_outage.
#[tokio::test]
async fn all_up_rows_yield_one_hundred_percent_uptime() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let raw = raw_pool(&db_path(&dir)).await;
    for i in 0..10 {
        ins(&raw, "s1", Some(true), i).await;
    }
    raw.close().await;

    let s = stat(&inv, "s1", 24).await;
    assert_eq!(s.total_rows, 10);
    assert_eq!(s.up_rows, 10);
    assert_eq!(s.down_rows, 0);
    assert_eq!(s.unknown_rows, 0);
    assert_eq!(s.uptime_pct, Some(100));
    assert!(s.last_outage_at.is_none(), "no down → no outage");
    assert!(s.last_probe_at.is_some(), "had probes");
}

// 3. All-down: pct=0, last_outage = most recent ts (= last_probe).
#[tokio::test]
async fn all_down_rows_yield_zero_percent_and_last_outage() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let raw = raw_pool(&db_path(&dir)).await;
    for h in (1..=5).rev() {
        ins(&raw, "s1", Some(false), h).await;
    }
    raw.close().await;

    let s = stat(&inv, "s1", 24).await;
    assert_eq!(s.down_rows, 5);
    assert_eq!(s.up_rows, 0);
    assert_eq!(s.uptime_pct, Some(0));
    let o = s.last_outage_at.expect("last_outage");
    let p = s.last_probe_at.expect("last_probe");
    assert_eq!(o, p, "newest row IS a down → last_outage = last_probe");
}

// 4. Mixed 9 up + 1 down → pct=90; last_outage = the down row.
#[tokio::test]
async fn mixed_up_and_down_pct_and_last_outage_pin_to_down_ts() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let raw = raw_pool(&db_path(&dir)).await;
    for h in (5..14).rev() {
        ins(&raw, "s1", Some(true), h).await;
    }
    ins(&raw, "s1", Some(false), 3).await; // newest of all
    raw.close().await;

    let s = stat(&inv, "s1", 24).await;
    assert_eq!(s.up_rows, 9);
    assert_eq!(s.down_rows, 1);
    assert_eq!(s.unknown_rows, 0);
    assert_eq!(s.total_rows, 10);
    assert_eq!(s.uptime_pct, Some(90));
    let o = s.last_outage_at.expect("last_outage");
    let p = s.last_probe_at.expect("last_probe");
    assert_eq!(o, p, "-3h down is newest in window");
}

// 5. Unknown rows excluded from denominator.
#[tokio::test]
async fn uptime_excludes_unknown_from_denominator() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let raw = raw_pool(&db_path(&dir)).await;
    ins(&raw, "s1", Some(true), 1).await;
    for _ in 0..99 {
        ins(&raw, "s1", None, 1).await;
    }
    raw.close().await;

    let s = stat(&inv, "s1", 24).await;
    assert_eq!(s.total_rows, 100);
    assert_eq!(s.up_rows, 1);
    assert_eq!(s.down_rows, 0);
    assert_eq!(s.unknown_rows, 99);
    assert_eq!(
        s.uptime_pct,
        Some(100),
        "1/(1+0) = 100; unknown is OUT of denominator"
    );
    assert!(s.last_outage_at.is_none(), "no down → no last_outage");
}

// 6. All-unknown: pct=None (not Some(0)).
#[tokio::test]
async fn all_unknown_rows_yield_none_uptime_pct() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let raw = raw_pool(&db_path(&dir)).await;
    for _ in 0..5 {
        ins(&raw, "s1", None, 1).await;
    }
    raw.close().await;

    let s = stat(&inv, "s1", 24).await;
    assert_eq!(s.total_rows, 5);
    assert_eq!(s.unknown_rows, 5);
    assert_eq!(s.up_rows, 0);
    assert_eq!(s.down_rows, 0);
    assert_eq!(s.uptime_pct, None, "undecidable → None, not Some(0)");
    assert!(s.last_outage_at.is_none());
    assert!(s.last_probe_at.is_some());
}

// 7. Window filters by ts age (24h excludes 100h-old; 168h includes).
#[tokio::test]
async fn window_filters_rows_by_ts_age() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let raw = raw_pool(&db_path(&dir)).await;
    ins(&raw, "s1", Some(true), 100).await; // ancient
    ins(&raw, "s1", Some(true), 1).await; // fresh
    raw.close().await;

    let day = stat(&inv, "s1", 24).await;
    assert_eq!(day.total_rows, 1, "24h excludes 100h-old");
    assert_eq!(day.up_rows, 1);

    let week = stat(&inv, "s1", 168).await;
    assert_eq!(week.total_rows, 2, "168h includes both");
    assert_eq!(week.up_rows, 2);
}

// 8. Per-server isolation.
#[tokio::test]
async fn other_servers_rows_do_not_contaminate_query() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("a")).await.unwrap();
    let mut b = srv("b");
    b.address = "2.2.2.2".into();
    inv.add_server(&b).await.unwrap();

    let raw = raw_pool(&db_path(&dir)).await;
    for _ in 0..3 {
        ins(&raw, "a", Some(true), 1).await;
    }
    for _ in 0..7 {
        ins(&raw, "b", Some(false), 1).await;
    }
    raw.close().await;

    let a = stat(&inv, "a", 24).await;
    assert_eq!(a.total_rows, 3);
    assert_eq!(a.up_rows, 3);
    assert_eq!(a.down_rows, 0);
    assert_eq!(a.uptime_pct, Some(100));
    assert!(a.last_outage_at.is_none(), "B's downs must not leak into A");

    let b = stat(&inv, "b", 24).await;
    assert_eq!(b.total_rows, 7);
    assert_eq!(b.down_rows, 7);
    assert_eq!(b.uptime_pct, Some(0));
}

// 9. last_outage = MAX(ts WHERE down); newer UP must NOT move it.
#[tokio::test]
async fn last_outage_is_max_down_ts_even_when_newer_up_exists() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let raw = raw_pool(&db_path(&dir)).await;
    ins(&raw, "s1", Some(false), 10).await;
    ins(&raw, "s1", Some(false), 5).await;
    ins(&raw, "s1", Some(true), 1).await;
    raw.close().await;

    let s = stat(&inv, "s1", 24).await;
    assert_eq!(s.up_rows, 1);
    assert_eq!(s.down_rows, 2);
    let o = s.last_outage_at.expect("last_outage");
    let p = s.last_probe_at.expect("last_probe");
    assert!(
        o < p,
        "newer up must NOT pull last_outage forward; outage={o}, probe={p}"
    );
}

// 10. Integer-truncated percentage (75%, 33%).
#[tokio::test]
async fn uptime_pct_is_integer_truncated() {
    async fn pct_for(ups: u32, downs: u32) -> Option<u8> {
        let dir = TempDir::new().unwrap();
        let inv = open(&dir).await;
        inv.add_server(&srv("s1")).await.unwrap();
        let raw = raw_pool(&db_path(&dir)).await;
        for _ in 0..ups {
            ins(&raw, "s1", Some(true), 1).await;
        }
        for _ in 0..downs {
            ins(&raw, "s1", Some(false), 2).await;
        }
        raw.close().await;
        stat(&inv, "s1", 24).await.uptime_pct
    }
    assert_eq!(pct_for(3, 1).await, Some(75), "3/(3+1)=75");
    assert_eq!(pct_for(1, 2).await, Some(33), "1/(1+2)=33 floor, not 34");
}
