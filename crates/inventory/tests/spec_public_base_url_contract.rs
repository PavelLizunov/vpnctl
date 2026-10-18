#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Spec tests for the inventory part of "Public base URL for user-facing links":
//! `SqliteInventory::get_public_base_url` / `set_public_base_url`
//! backed by `display_settings.public_base_url` (migration 0059).

use std::path::PathBuf;

use tempfile::TempDir;
use vpnctl_inventory::SqliteInventory;

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn fresh_inventory(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir))
        .await
        .expect("open fresh inventory")
}

// ---------------------------------------------------------------------------
// get_public_base_url
// ---------------------------------------------------------------------------

/// Fresh install has no pinned app devices, so migration 0059 must not seed
/// the owner domain: no owner domain is compiled in or seeded.
#[tokio::test]
async fn fresh_install_has_no_public_base_url() {
    let dir = TempDir::new().unwrap();
    let inv = fresh_inventory(&dir).await;

    let got = inv.get_public_base_url().await.unwrap();

    assert_eq!(got, None, "fresh install must not carry a public base URL");
}

/// Contract: "empty string reads as None".
#[tokio::test]
async fn get_public_base_url_reads_empty_string_as_none() {
    let dir = TempDir::new().unwrap();
    let inv = fresh_inventory(&dir).await;

    inv.set_public_base_url(Some("")).await.unwrap();

    assert_eq!(inv.get_public_base_url().await.unwrap(), None);
}

/// Boundary: an empty string written over an existing value must still read
/// back as None (not as the previous value, not as `Some("")`).
#[tokio::test]
async fn get_public_base_url_empty_string_over_existing_value_reads_as_none() {
    let dir = TempDir::new().unwrap();
    let inv = fresh_inventory(&dir).await;

    inv.set_public_base_url(Some("https://vpn.example.org"))
        .await
        .unwrap();
    inv.set_public_base_url(Some("")).await.unwrap();

    assert_eq!(inv.get_public_base_url().await.unwrap(), None);
}

/// The value is operator configuration stored in the DB: it survives a
/// daemon restart (re-open of the same file, migrations re-run).
#[tokio::test]
async fn get_public_base_url_persists_across_reopen() {
    let dir = TempDir::new().unwrap();
    {
        let inv = fresh_inventory(&dir).await;
        inv.set_public_base_url(Some("https://vpn.example.org"))
            .await
            .unwrap();
    }

    let reopened = SqliteInventory::open(&db_path(&dir)).await.unwrap();

    assert_eq!(
        reopened.get_public_base_url().await.unwrap().as_deref(),
        Some("https://vpn.example.org"),
    );
}

// ---------------------------------------------------------------------------
// set_public_base_url
// ---------------------------------------------------------------------------

/// Happy path: a configured base reads back exactly.
#[tokio::test]
async fn set_public_base_url_round_trips_value() {
    let dir = TempDir::new().unwrap();
    let inv = fresh_inventory(&dir).await;

    inv.set_public_base_url(Some("https://vpn.example.org"))
        .await
        .unwrap();

    assert_eq!(
        inv.get_public_base_url().await.unwrap().as_deref(),
        Some("https://vpn.example.org"),
    );
}

/// Contract: "None clears".
#[tokio::test]
async fn set_public_base_url_none_clears_existing_value() {
    let dir = TempDir::new().unwrap();
    let inv = fresh_inventory(&dir).await;

    inv.set_public_base_url(Some("https://vpn.example.org"))
        .await
        .unwrap();
    inv.set_public_base_url(None).await.unwrap();

    assert_eq!(inv.get_public_base_url().await.unwrap(), None);
}

/// Edge: clearing when nothing is configured succeeds and stays None.
#[tokio::test]
async fn set_public_base_url_none_on_unset_succeeds_and_stays_none() {
    let dir = TempDir::new().unwrap();
    let inv = fresh_inventory(&dir).await;

    inv.set_public_base_url(None).await.unwrap();

    assert_eq!(inv.get_public_base_url().await.unwrap(), None);
}

/// A later set replaces the earlier value (single setting, not a list).
#[tokio::test]
async fn set_public_base_url_overwrites_previous_value() {
    let dir = TempDir::new().unwrap();
    let inv = fresh_inventory(&dir).await;

    inv.set_public_base_url(Some("https://old.example.org"))
        .await
        .unwrap();
    inv.set_public_base_url(Some("http://new.example.net:8443"))
        .await
        .unwrap();

    assert_eq!(
        inv.get_public_base_url().await.unwrap().as_deref(),
        Some("http://new.example.net:8443"),
    );
}

/// Saving the same value twice is a no-op that still reads back the value.
#[tokio::test]
async fn set_public_base_url_same_value_twice_keeps_value() {
    let dir = TempDir::new().unwrap();
    let inv = fresh_inventory(&dir).await;

    inv.set_public_base_url(Some("https://vpn.example.org"))
        .await
        .unwrap();
    inv.set_public_base_url(Some("https://vpn.example.org"))
        .await
        .unwrap();

    assert_eq!(
        inv.get_public_base_url().await.unwrap().as_deref(),
        Some("https://vpn.example.org"),
    );
}

/// Boundary: the fullest accepted shape `http(s)://host[:port][/path]`
/// (IP host, maximum port, multi-segment path) is stored byte-for-byte.
#[tokio::test]
async fn set_public_base_url_stores_host_port_path_verbatim() {
    let dir = TempDir::new().unwrap();
    let inv = fresh_inventory(&dir).await;
    let value = "http://192.168.0.236:65535/vpn/edge";

    inv.set_public_base_url(Some(value)).await.unwrap();

    assert_eq!(
        inv.get_public_base_url().await.unwrap().as_deref(),
        Some(value)
    );
}
