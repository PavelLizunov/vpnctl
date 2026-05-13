//! Integration spec for `SqliteInventory`. Tests numbered after rules
//! 1-15 in the test-writer brief; written from the spec only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::path::PathBuf;

use serde_json::json;
use tempfile::TempDir;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn server(id: &str) -> Server {
    Server {
        id: ServerId(id.to_string()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernel: KernelId("sing-box".to_string()),
        enabled_protocols: vec![
            ProtocolId("vless+reality".to_string()),
            ProtocolId("tuic-v5".to_string()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".to_string(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("uuid-of-{id}"),
        tuic_password: Some(format!("tuic-{id}")),
        wireguard_pubkey: None,
        sub_token: None, // inventory generates
    }
}

// Rule 1: open creates the file and is idempotent.
#[tokio::test]
async fn open_creates_file_and_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);
    assert!(!path.exists());
    let inv1 = SqliteInventory::open(&path).await.expect("first open");
    assert!(path.exists(), "open must create db file");
    inv1.add_server(&server("s1")).await.unwrap();
    inv1.close().await;

    let inv2 = SqliteInventory::open(&path).await.expect("second open");
    let got = inv2.get_server(&ServerId("s1".into())).await.unwrap();
    assert!(got.is_some(), "data must survive close + reopen");
    inv2.close().await;
}

// Rule 2: WAL is enabled — sidecar `<db>-wal` appears after a write.
#[tokio::test]
async fn wal_journal_mode_is_enabled() {
    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);
    let inv = SqliteInventory::open(&path).await.unwrap();
    inv.add_server(&server("s1")).await.unwrap();

    let wal = path.with_file_name(format!(
        "{}-wal",
        path.file_name().unwrap().to_string_lossy()
    ));
    assert!(wal.exists(), "expected WAL sidecar at {wal:?}");
    inv.close().await;
}

// Rule 3: FK enforcement is ON. With FKs off, granting a non-existent
// (user, server) pair would silently insert. So a pre-condition violation
// must error.
#[tokio::test]
async fn foreign_keys_are_enforced() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let res = inv
        .grant(&UserId("ghost".into()), &ServerId("phantom".into()))
        .await;
    assert!(res.is_err(), "FK enforcement is OFF");
}

// Rule 4: add_server is atomic. A duplicate protocol (PK violation in
// server_protocols) must roll back the parent server insert.
#[tokio::test]
async fn add_server_is_atomic_on_protocol_failure() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let mut s = server("atomic");
    s.enabled_protocols = vec![
        ProtocolId("vless+reality".to_string()),
        ProtocolId("vless+reality".to_string()),
    ];
    let res = inv.add_server(&s).await;
    assert!(res.is_err(), "duplicate protocol must fail add_server");

    let got = inv.get_server(&ServerId("atomic".into())).await.unwrap();
    assert!(got.is_none(), "server row leaked: {got:?}");
}

// Rule 5: duplicate add_server -> AlreadyExists("server <id>").
#[tokio::test]
async fn add_server_duplicate_returns_already_exists() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("dup")).await.unwrap();
    let err = inv.add_server(&server("dup")).await.unwrap_err();
    match err {
        SqliteInventoryError::AlreadyExists(msg) => {
            assert_eq!(msg, "server dup", "wrong payload: {msg:?}");
        }
        other => panic!("expected AlreadyExists, got: {other:?}"),
    }
}

// Rule 6: duplicate add_user -> AlreadyExists("user <id>").
#[tokio::test]
async fn add_user_duplicate_returns_already_exists() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    let err = inv.add_user(&user("alice")).await.unwrap_err();
    match err {
        SqliteInventoryError::AlreadyExists(msg) => {
            assert_eq!(msg, "user alice", "wrong payload: {msg:?}");
        }
        other => panic!("expected AlreadyExists, got: {other:?}"),
    }
}

// Rule 7: get_server(missing) -> Ok(None).
#[tokio::test]
async fn get_server_missing_returns_none() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let got = inv.get_server(&ServerId("nope".into())).await.unwrap();
    assert!(got.is_none(), "missing id must be Ok(None), got {got:?}");
}

// Rule 8: enabled_protocols round-trips (set equality).
#[tokio::test]
async fn enabled_protocols_round_trip() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let mut s = server("rt");
    s.enabled_protocols = vec![
        ProtocolId("vless+reality".into()),
        ProtocolId("tuic-v5".into()),
    ];
    inv.add_server(&s).await.unwrap();

    let got = inv
        .get_server(&ServerId("rt".into()))
        .await
        .unwrap()
        .expect("exists");
    let want: HashSet<_> = s.enabled_protocols.iter().cloned().collect();
    let have: HashSet<_> = got.enabled_protocols.iter().cloned().collect();
    assert_eq!(want, have, "protocol set mismatch");
    assert_eq!(got.enabled_protocols.len(), s.enabled_protocols.len());
}

// Rule 9: update_trusted_fingerprint is observable through get_server.
#[tokio::test]
async fn update_trusted_fingerprint_is_observable() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("fp")).await.unwrap();
    let id = ServerId("fp".into());

    let before = inv.get_server(&id).await.unwrap().unwrap();
    assert!(before.trusted_host_fingerprint.is_none());

    // 43-char unpadded base64 — what `russh::keys::PublicKey::fingerprint`
    // actually returns. SqliteInventory enforces this shape.
    let fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    inv.update_trusted_fingerprint(&id, fp).await.unwrap();

    let after = inv.get_server(&id).await.unwrap().unwrap();
    assert_eq!(
        after.trusted_host_fingerprint.as_deref(),
        Some(fp),
        "fingerprint update did not persist"
    );
}

// Rule 10: set_server_secret is upsert (overwrites, no duplicate row).
#[tokio::test]
async fn set_server_secret_is_upsert() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s")).await.unwrap();
    let id = ServerId("s".into());

    inv.set_server_secret(&id, "vless.private_key", "AAA")
        .await
        .unwrap();
    inv.set_server_secret(&id, "vless.private_key", "BBB")
        .await
        .expect("second set must overwrite");

    let got = inv
        .get_server_secret(&id, "vless.private_key")
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("BBB"), "did not overwrite");

    let all = inv.list_server_secrets(&id).await.unwrap();
    assert_eq!(all.len(), 1, "duplicate row leaked: {all:?}");
}

// Rule 11: FK CASCADE — removing a user removes its grants.
#[tokio::test]
async fn remove_user_cascades_to_grants() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("srv")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();
    inv.add_user(&user("u2")).await.unwrap();
    let srv = ServerId("srv".into());
    inv.grant(&UserId("u1".into()), &srv).await.unwrap();
    inv.grant(&UserId("u2".into()), &srv).await.unwrap();

    assert_eq!(inv.users_for_server(&srv).await.unwrap().len(), 2);
    inv.remove_user(&UserId("u1".into())).await.unwrap();

    let after = inv.users_for_server(&srv).await.unwrap();
    let ids: Vec<_> = after.iter().map(|u| u.id.0.as_str()).collect();
    assert_eq!(ids, vec!["u2"], "u1 grant did not cascade");
}

// Rule 12: removing a server cleans server_protocols, server_secrets, grants.
#[tokio::test]
async fn remove_server_cascades_to_dependents() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("s")).await.unwrap();
    inv.add_user(&user("u")).await.unwrap();
    let sid = ServerId("s".into());
    let uid = UserId("u".into());

    inv.set_server_secret(&sid, "vless.private_key", "AAA")
        .await
        .unwrap();
    inv.grant(&uid, &sid).await.unwrap();

    assert!(!inv.list_server_secrets(&sid).await.unwrap().is_empty());
    assert_eq!(inv.servers_for_user(&uid).await.unwrap().len(), 1);

    inv.remove_server(&sid).await.unwrap();

    assert!(
        inv.list_server_secrets(&sid).await.unwrap().is_empty(),
        "secrets did not CASCADE"
    );
    assert!(
        inv.servers_for_user(&uid).await.unwrap().is_empty(),
        "grants did not CASCADE"
    );

    // Re-adding the same id with the same protocols would PK-violate
    // server_protocols if the old rows leaked.
    inv.add_server(&server("s"))
        .await
        .expect("server_protocols must also CASCADE");
}

// Rule 13: grant is idempotent.
#[tokio::test]
async fn grant_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("s")).await.unwrap();
    inv.add_user(&user("u")).await.unwrap();
    let sid = ServerId("s".into());
    let uid = UserId("u".into());

    inv.grant(&uid, &sid).await.unwrap();
    inv.grant(&uid, &sid)
        .await
        .expect("second grant must not error");

    let users = inv.users_for_server(&sid).await.unwrap();
    assert_eq!(users.len(), 1, "duplicate grant row: {users:?}");
}

// Rule 14: audit accepts None/Some payload; recent_audit DESC by id, limit clips.
#[tokio::test]
async fn audit_recent_order_limit_payload() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.audit("cli", "first", Some("t1"), None).await.unwrap();
    let p2 = json!({ "k": "v", "n": 42 });
    inv.audit("cli", "second", Some("t2"), Some(&p2))
        .await
        .unwrap();
    inv.audit("system", "third", None, Some(&json!([1, 2, 3])))
        .await
        .unwrap();

    let three = inv.recent_audit(10).await.unwrap();
    assert_eq!(three.len(), 3);
    let actions: Vec<_> = three.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, vec!["third", "second", "first"], "DESC order");
    assert!(three[0].id > three[1].id && three[1].id > three[2].id);

    assert_eq!(inv.recent_audit(2).await.unwrap().len(), 2, "limit clip");

    let second = three.iter().find(|e| e.action == "second").unwrap();
    assert_eq!(second.payload.as_ref().unwrap(), &p2, "payload round-trip");
    let first = three.iter().find(|e| e.action == "first").unwrap();
    assert!(first.payload.is_none(), "None payload must be NULL");
    assert_eq!(first.target.as_deref(), Some("t1"));
    let third = three.iter().find(|e| e.action == "third").unwrap();
    assert!(third.target.is_none(), "None target must be NULL");
}

// Rule 15: AuditEntry.ts is RFC3339-parseable UTC.
#[tokio::test]
async fn audit_ts_is_rfc3339_utc() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.audit("cli", "tick", None, None).await.unwrap();
    let rows = inv.recent_audit(1).await.unwrap();
    let row = rows.first().expect("at least one row");

    let s = row.ts.to_rfc3339();
    let parsed = chrono::DateTime::parse_from_rfc3339(&s)
        .expect("ts must be RFC3339")
        .with_timezone(&chrono::Utc);
    assert_eq!(parsed, row.ts);
    // `DateTime<Utc>::offset()` returns the `Utc` singleton, whose Display
    // is the literal "UTC" — not "+00:00". Format-print the offset to
    // verify it's actually zero.
    assert_eq!(
        row.ts.format("%:z").to_string(),
        "+00:00",
        "ts not UTC: {s}"
    );
}
