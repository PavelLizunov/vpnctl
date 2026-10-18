#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use tempfile::TempDir;
use vpnctl_inventory::SqliteInventory;

async fn pool_before_0059(dir: &TempDir) -> sqlx::SqlitePool {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let opts = SqliteConnectOptions::new()
        .filename(dir.path().join("inv.db"))
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    let migrations_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".sql") && name.as_str() < "0059"
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let sql = std::fs::read_to_string(entry.path()).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.unwrap();
    }
    pool
}

async fn apply_0059(pool: &sqlx::SqlitePool) -> Option<String> {
    let sql = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations/0059_public_base_url.sql"),
    )
    .unwrap();
    sqlx::raw_sql(&sql).execute(pool).await.unwrap();
    sqlx::query_as::<_, (Option<String>,)>(
        "SELECT public_base_url FROM display_settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await
    .unwrap()
    .0
}

#[tokio::test]
async fn migration_keeps_existing_urls_for_installs_with_users() {
    let dir = TempDir::new().unwrap();
    let pool = pool_before_0059(&dir).await;
    sqlx::query(
        "INSERT INTO users (id, uuid, vpn_router_device_id) VALUES ('alice', 'u-1', 'a92b915032b48a2ed45ef72f4171e5f4')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        apply_0059(&pool).await.as_deref(),
        Some("https://ninitux.com")
    );
}

#[tokio::test]
async fn migration_leaves_fresh_installs_without_a_public_address() {
    let dir = TempDir::new().unwrap();
    let pool = pool_before_0059(&dir).await;
    assert_eq!(apply_0059(&pool).await, None);
}

#[tokio::test]
async fn public_base_url_roundtrip_and_clear() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    assert_eq!(inv.get_public_base_url().await.unwrap(), None);
    inv.set_public_base_url(Some("https://vpn.example.com"))
        .await
        .unwrap();
    assert_eq!(
        inv.get_public_base_url().await.unwrap().as_deref(),
        Some("https://vpn.example.com")
    );
    inv.set_public_base_url(None).await.unwrap();
    assert_eq!(inv.get_public_base_url().await.unwrap(), None);
}

#[tokio::test]
async fn audited_update_writes_one_row_per_change_and_none_for_noop() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let rows = |inv: &SqliteInventory| {
        let inv = inv.clone();
        async move {
            inv.recent_audit_paginated(50, 0, None, Some("settings.public_url.set"), None, None)
                .await
                .unwrap()
                .len()
        }
    };
    assert!(
        inv.update_public_base_url_audited("admin", Some("https://vpn.example.com"))
            .await
            .unwrap()
    );
    assert!(
        !inv.update_public_base_url_audited("admin", Some("https://vpn.example.com"))
            .await
            .unwrap()
    );
    assert_eq!(rows(&inv).await, 1);
    assert!(
        inv.update_public_base_url_audited("admin", None)
            .await
            .unwrap()
    );
    assert_eq!(rows(&inv).await, 2);
    assert_eq!(inv.get_public_base_url().await.unwrap(), None);
}
