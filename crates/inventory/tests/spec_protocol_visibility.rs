//! Spec for migration `0018_protocol_visibility.sql` — per-(server,
//! protocol) `hidden` flag + per-(user, server, protocol) deny override.
//!
//! Two orthogonal axes of "is this protocol exposed on this user's
//! subscription URL"; deny-by-OR resolution:
//!
//!   server.hidden=1 OR override.state='disabled'  →  hidden
//!   server.hidden=0 AND override absent           →  visible
//!
//! Tests pin the SqliteInventory public API contracts confirmed by
//! Pavel 2026-05-20 without depending on impl internals.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open")
}

fn srv(id: &str, protocols: &[&str]) -> Server {
    Server {
        id: ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: protocols.iter().map(|p| ProtocolId((*p).into())).collect(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn usr(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("global-uuid-of-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
    }
}

fn sid(id: &str) -> ServerId {
    ServerId(id.into())
}
fn pid(id: &str) -> ProtocolId {
    ProtocolId(id.into())
}
fn uid(id: &str) -> UserId {
    UserId(id.into())
}

// Rule 1 — default state. Fresh (server, protocol) row has hidden=0,
// so the read returns false AND the resolved visible list contains it.
#[tokio::test]
async fn fresh_protocol_is_visible_and_not_hidden() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv("vps-x", &["vless+reality"]))
        .await
        .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();
    inv.grant(&uid("alice"), &sid("vps-x")).await.unwrap();

    assert!(
        !inv.is_server_protocol_hidden(&sid("vps-x"), &pid("vless+reality"))
            .await
            .unwrap()
    );
    let v = inv
        .visible_protocols_for_subscription(&uid("alice"), &sid("vps-x"))
        .await
        .unwrap();
    assert_eq!(v, vec![pid("vless+reality")]);
}

// Rules 2 + 3 — hide path then unhide path; visibility flips for EVERY
// user; the row stays in server_protocols (soft-hide, NOT remove).
#[tokio::test]
async fn hide_then_unhide_round_trip_for_every_user() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv("vps-x", &["vless+reality"]))
        .await
        .unwrap();
    for who in ["alice", "bob"] {
        inv.add_user(&usr(who)).await.unwrap();
        inv.grant(&uid(who), &sid("vps-x")).await.unwrap();
    }

    inv.set_server_protocol_hidden(&sid("vps-x"), &pid("vless+reality"), true)
        .await
        .unwrap();
    assert!(
        inv.is_server_protocol_hidden(&sid("vps-x"), &pid("vless+reality"))
            .await
            .unwrap()
    );
    for who in ["alice", "bob"] {
        let v = inv
            .visible_protocols_for_subscription(&uid(who), &sid("vps-x"))
            .await
            .unwrap();
        assert!(v.is_empty(), "hide must exclude for {who}, got {v:?}");
    }

    inv.set_server_protocol_hidden(&sid("vps-x"), &pid("vless+reality"), false)
        .await
        .unwrap();
    assert!(
        !inv.is_server_protocol_hidden(&sid("vps-x"), &pid("vless+reality"))
            .await
            .unwrap()
    );
    for who in ["alice", "bob"] {
        let v = inv
            .visible_protocols_for_subscription(&uid(who), &sid("vps-x"))
            .await
            .unwrap();
        assert_eq!(v, vec![pid("vless+reality")]);
    }
}

// Rule 4 — set_server_protocol_hidden on missing (sid, pid) → Invalid.
// NOT raw Sqlx — caller maps to 400 with a helpful message.
#[tokio::test]
async fn hide_on_missing_row_returns_invalid_not_sqlx() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv("vps-x", &["vless+reality"]))
        .await
        .unwrap();

    let res = inv
        .set_server_protocol_hidden(&sid("vps-x"), &pid("tuic-v5"), true)
        .await;
    match res {
        Err(SqliteInventoryError::Invalid(_)) => {}
        Err(other) => panic!("expected Invalid, got {other:?}"),
        Ok(()) => panic!("expected Err, got Ok"),
    }
}

// Rule 5 — per-user override INSERT path. disabled=true hides ONLY for
// that user. list_protocol_overrides_for_user map reflects the state.
#[tokio::test]
async fn per_user_override_insert_excludes_only_that_user() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv("vps-x", &["vless+reality"]))
        .await
        .unwrap();
    for who in ["alice", "bob"] {
        inv.add_user(&usr(who)).await.unwrap();
        inv.grant(&uid(who), &sid("vps-x")).await.unwrap();
    }

    inv.set_grant_protocol_override(&uid("alice"), &sid("vps-x"), &pid("vless+reality"), true)
        .await
        .unwrap();

    let alice_v = inv
        .visible_protocols_for_subscription(&uid("alice"), &sid("vps-x"))
        .await
        .unwrap();
    assert!(alice_v.is_empty(), "alice override excludes pid");

    let bob_v = inv
        .visible_protocols_for_subscription(&uid("bob"), &sid("vps-x"))
        .await
        .unwrap();
    assert_eq!(bob_v, vec![pid("vless+reality")]);

    let map = inv
        .list_protocol_overrides_for_user(&uid("alice"))
        .await
        .unwrap();
    assert_eq!(map.get(&(sid("vps-x"), pid("vless+reality"))), Some(&true));
    assert_eq!(map.len(), 1);

    let bob_map = inv
        .list_protocol_overrides_for_user(&uid("bob"))
        .await
        .unwrap();
    assert!(bob_map.is_empty());
}

// Rule 6 — DELETE path. disabled=false drops the row; visibility back.
// disabled=true twice is a no-op (INSERT OR IGNORE semantics).
#[tokio::test]
async fn per_user_override_delete_restores_visibility() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv("vps-x", &["vless+reality"]))
        .await
        .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();
    inv.grant(&uid("alice"), &sid("vps-x")).await.unwrap();

    for _ in 0..2 {
        inv.set_grant_protocol_override(&uid("alice"), &sid("vps-x"), &pid("vless+reality"), true)
            .await
            .unwrap();
    }
    inv.set_grant_protocol_override(&uid("alice"), &sid("vps-x"), &pid("vless+reality"), false)
        .await
        .unwrap();

    let map = inv
        .list_protocol_overrides_for_user(&uid("alice"))
        .await
        .unwrap();
    assert!(map.is_empty());
    let v = inv
        .visible_protocols_for_subscription(&uid("alice"), &sid("vps-x"))
        .await
        .unwrap();
    assert_eq!(v, vec![pid("vless+reality")]);
}

// Rule 7 — override without a grant → Invalid (NOT Sqlx). Composite FK
// pre-check surfaces a friendly diagnostic instead of raw constraint err.
#[tokio::test]
async fn override_without_grant_returns_invalid_not_sqlx() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv("vps-x", &["vless+reality"]))
        .await
        .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();
    // No grant on purpose.

    let res = inv
        .set_grant_protocol_override(&uid("alice"), &sid("vps-x"), &pid("vless+reality"), true)
        .await;
    match res {
        Err(SqliteInventoryError::Invalid(_)) => {}
        Err(other) => panic!("expected Invalid, got {other:?}"),
        Ok(()) => panic!("expected Err, got Ok"),
    }
}

// Rule 8 — composite FK ON DELETE CASCADE. revoke() drops every
// protocol override for that (user, server) pair. No orphan rows.
#[tokio::test]
async fn revoke_cascades_protocol_overrides() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv("vps-x", &["vless+reality", "tuic-v5"]))
        .await
        .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();
    inv.grant(&uid("alice"), &sid("vps-x")).await.unwrap();

    for proto in ["vless+reality", "tuic-v5"] {
        inv.set_grant_protocol_override(&uid("alice"), &sid("vps-x"), &pid(proto), true)
            .await
            .unwrap();
    }
    let before = inv
        .list_protocol_overrides_for_user(&uid("alice"))
        .await
        .unwrap();
    assert_eq!(before.len(), 2);

    inv.revoke(&uid("alice"), &sid("vps-x")).await.unwrap();

    let after = inv
        .list_protocol_overrides_for_user(&uid("alice"))
        .await
        .unwrap();
    assert!(after.is_empty(), "cascade left overrides: {after:?}");
}

// Rule 9 — both axes simultaneously. server.hidden=1 AND override
// disabled=true → still excluded. Deny-by-OR (pinned against future
// regression switching to AND).
#[tokio::test]
async fn both_axes_at_once_exclude() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv("vps-x", &["vless+reality"]))
        .await
        .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();
    inv.grant(&uid("alice"), &sid("vps-x")).await.unwrap();

    inv.set_server_protocol_hidden(&sid("vps-x"), &pid("vless+reality"), true)
        .await
        .unwrap();
    inv.set_grant_protocol_override(&uid("alice"), &sid("vps-x"), &pid("vless+reality"), true)
        .await
        .unwrap();

    let v = inv
        .visible_protocols_for_subscription(&uid("alice"), &sid("vps-x"))
        .await
        .unwrap();
    assert!(v.is_empty(), "deny-by-OR must exclude, got {v:?}");
}

// Rule 10 — audit trail. Each successful set_server_protocol_hidden +
// set_grant_protocol_override writes ONE audit_log row with the matching
// action + target + payload contents.
#[tokio::test]
async fn writes_audit_rows_with_matching_payloads() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv("vps-x", &["vless+reality"]))
        .await
        .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();
    inv.grant(&uid("alice"), &sid("vps-x")).await.unwrap();

    inv.set_server_protocol_hidden(&sid("vps-x"), &pid("vless+reality"), true)
        .await
        .unwrap();
    inv.set_grant_protocol_override(&uid("alice"), &sid("vps-x"), &pid("vless+reality"), true)
        .await
        .unwrap();

    let recent = inv.recent_audit(50).await.unwrap();

    let hide = recent
        .iter()
        .find(|r| r.action == "server_protocol.set_hidden")
        .expect("server_protocol.set_hidden audit row");
    assert_eq!(hide.target.as_deref(), Some("vps-x"));
    let p = hide.payload.as_ref().expect("hide payload");
    assert_eq!(p["server_id"], serde_json::json!("vps-x"));
    assert_eq!(p["protocol_id"], serde_json::json!("vless+reality"));
    assert_eq!(p["old_hidden"], serde_json::json!(false));
    assert_eq!(p["new_hidden"], serde_json::json!(true));

    let ov = recent
        .iter()
        .find(|r| r.action == "grant_protocol.set_override")
        .expect("grant_protocol.set_override audit row");
    assert_eq!(ov.target.as_deref(), Some("alice"));
    let p = ov.payload.as_ref().expect("override payload");
    assert_eq!(p["user_id"], serde_json::json!("alice"));
    assert_eq!(p["server_id"], serde_json::json!("vps-x"));
    assert_eq!(p["protocol_id"], serde_json::json!("vless+reality"));
    assert_eq!(p["disabled"], serde_json::json!(true));
}

// Rule 11 — ordering invariant. Output is alphabetical by protocol_id
// regardless of insertion order. 4 protocols inserted out of order.
#[tokio::test]
async fn visible_protocols_are_alphabetically_sorted() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv(
        "vps-x",
        &["vless+reality", "anytls", "trojan", "tuic-v5"],
    ))
    .await
    .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();
    inv.grant(&uid("alice"), &sid("vps-x")).await.unwrap();

    let v = inv
        .visible_protocols_for_subscription(&uid("alice"), &sid("vps-x"))
        .await
        .unwrap();
    let v_strs: Vec<&str> = v.iter().map(|p| p.0.as_str()).collect();
    assert_eq!(v_strs, vec!["anytls", "trojan", "tuic-v5", "vless+reality"]);
}

// Spec hardening — visible_protocols_for_subscription returns the
// visible-on-server list even WITHOUT a grant for (uid, sid). The caller
// is expected to grant-filter via servers_for_user first; this query
// must not silently require a JOIN to grants.
#[tokio::test]
async fn visible_protocols_returns_server_list_without_grant() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&srv("vps-x", &["vless+reality", "tuic-v5"]))
        .await
        .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();
    // No grant on purpose.

    let v = inv
        .visible_protocols_for_subscription(&uid("alice"), &sid("vps-x"))
        .await
        .unwrap();
    let v_strs: Vec<&str> = v.iter().map(|p| p.0.as_str()).collect();
    assert_eq!(v_strs, vec!["tuic-v5", "vless+reality"]);
}
