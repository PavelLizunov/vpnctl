//! Spec for migration `0018_protocol_visibility.sql` — per-(server,
//! protocol) `hidden` flag + per-(user, server, protocol) deny override.
//! Two orthogonal axes; deny-by-OR resolution:
//!   server.hidden=1 OR override.state='disabled' → hidden
//!   server.hidden=0 AND override absent          → visible
//! Tests pin the public SqliteInventory API from the Pavel-confirmed
//! 2026-05-20 spec without depending on impl internals.

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
        disabled: false,
    }
}

fn s(id: &str) -> ServerId {
    ServerId(id.into())
}
fn p(id: &str) -> ProtocolId {
    ProtocolId(id.into())
}
fn u(id: &str) -> UserId {
    UserId(id.into())
}

// Single-line helpers keep the file inside the spec's 300-line budget
// (rustfmt would otherwise pivot every `.await.unwrap()` chain onto 3
// lines apiece).
async fn setup(dir: &TempDir, protocols: &[&str]) -> SqliteInventory {
    let inv = open(dir).await;
    inv.add_server(&srv("vps-x", protocols)).await.unwrap();
    inv
}
async fn add_grant(inv: &SqliteInventory, who: &str) {
    inv.add_user(&usr(who)).await.unwrap();
    inv.grant(&u(who), &s("vps-x")).await.unwrap();
}
async fn hide(inv: &SqliteInventory, proto: &str, h: bool) {
    inv.set_server_protocol_hidden(&s("vps-x"), &p(proto), h)
        .await
        .unwrap()
}
async fn is_hid(inv: &SqliteInventory, proto: &str) -> bool {
    inv.is_server_protocol_hidden(&s("vps-x"), &p(proto))
        .await
        .unwrap()
}
async fn over(inv: &SqliteInventory, who: &str, proto: &str, dis: bool) {
    inv.set_grant_protocol_override(&u(who), &s("vps-x"), &p(proto), dis)
        .await
        .unwrap()
}
async fn visible(inv: &SqliteInventory, who: &str) -> Vec<String> {
    inv.visible_protocols_for_subscription(&u(who), &s("vps-x"))
        .await
        .unwrap()
        .into_iter()
        .map(|x| x.0)
        .collect()
}
async fn overrides(inv: &SqliteInventory, who: &str) -> usize {
    inv.list_protocol_overrides_for_user(&u(who))
        .await
        .unwrap()
        .len()
}

// Rule 1 — fresh row: hidden=false, visible list contains the proto.
#[tokio::test]
async fn fresh_protocol_is_visible_and_not_hidden() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality"]).await;
    add_grant(&inv, "alice").await;
    assert!(!is_hid(&inv, "vless+reality").await);
    assert_eq!(visible(&inv, "alice").await, vec!["vless+reality"]);
}

// Rules 2 + 3 — hide then unhide; flips for EVERY user; row stays in
// server_protocols (soft-hide, distinct from remove_server_protocol).
#[tokio::test]
async fn hide_then_unhide_round_trip_for_every_user() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality"]).await;
    add_grant(&inv, "alice").await;
    add_grant(&inv, "bob").await;

    hide(&inv, "vless+reality", true).await;
    assert!(is_hid(&inv, "vless+reality").await);
    for w in ["alice", "bob"] {
        assert!(visible(&inv, w).await.is_empty(), "exclude for {w}");
    }

    hide(&inv, "vless+reality", false).await;
    assert!(!is_hid(&inv, "vless+reality").await);
    for w in ["alice", "bob"] {
        assert_eq!(visible(&inv, w).await, vec!["vless+reality"]);
    }
}

// Rule 4 — hide on missing (sid, pid) row → Invalid, NOT raw Sqlx.
#[tokio::test]
async fn hide_on_missing_row_returns_invalid_not_sqlx() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality"]).await;
    let res = inv
        .set_server_protocol_hidden(&s("vps-x"), &p("tuic-v5"), true)
        .await;
    match res {
        Err(SqliteInventoryError::Invalid(_)) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }
}

// Rule 5 — per-user override INSERT path. disabled=true hides ONLY for
// that user; list_protocol_overrides_for_user reflects the state.
#[tokio::test]
async fn per_user_override_insert_excludes_only_that_user() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality"]).await;
    add_grant(&inv, "alice").await;
    add_grant(&inv, "bob").await;

    over(&inv, "alice", "vless+reality", true).await;

    assert!(visible(&inv, "alice").await.is_empty(), "excludes pid");
    assert_eq!(visible(&inv, "bob").await, vec!["vless+reality"]);

    let map = inv
        .list_protocol_overrides_for_user(&u("alice"))
        .await
        .unwrap();
    assert_eq!(map.get(&(s("vps-x"), p("vless+reality"))), Some(&true));
    assert_eq!(map.len(), 1);
    assert_eq!(overrides(&inv, "bob").await, 0);
}

// Rule 6 — DELETE path. disabled=false drops the row; visibility back.
// disabled=true twice is a no-op (INSERT OR IGNORE semantics).
#[tokio::test]
async fn per_user_override_delete_restores_visibility() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality"]).await;
    add_grant(&inv, "alice").await;

    over(&inv, "alice", "vless+reality", true).await;
    over(&inv, "alice", "vless+reality", true).await; // idempotent
    over(&inv, "alice", "vless+reality", false).await;

    assert_eq!(overrides(&inv, "alice").await, 0);
    assert_eq!(visible(&inv, "alice").await, vec!["vless+reality"]);
}

// Rule 7 — override without a grant → Invalid (NOT Sqlx). Composite FK
// pre-check turns the raw constraint error into a friendly diagnostic.
#[tokio::test]
async fn override_without_grant_returns_invalid_not_sqlx() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality"]).await;
    inv.add_user(&usr("alice")).await.unwrap();
    // No grant on purpose.

    let res = inv
        .set_grant_protocol_override(&u("alice"), &s("vps-x"), &p("vless+reality"), true)
        .await;
    match res {
        Err(SqliteInventoryError::Invalid(_)) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }
}

// Rule 8 — composite FK ON DELETE CASCADE. revoke() drops every
// protocol override for that (user, server) pair.
#[tokio::test]
async fn revoke_cascades_protocol_overrides() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality", "tuic-v5"]).await;
    add_grant(&inv, "alice").await;

    for proto in ["vless+reality", "tuic-v5"] {
        over(&inv, "alice", proto, true).await;
    }
    assert_eq!(overrides(&inv, "alice").await, 2);

    inv.revoke(&u("alice"), &s("vps-x")).await.unwrap();
    assert_eq!(
        overrides(&inv, "alice").await,
        0,
        "cascade must drop overrides"
    );
}

// Rule 9 — both axes simultaneously. server.hidden=1 AND override
// disabled=true → still excluded. Deny-by-OR.
#[tokio::test]
async fn both_axes_at_once_exclude() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality"]).await;
    add_grant(&inv, "alice").await;
    hide(&inv, "vless+reality", true).await;
    over(&inv, "alice", "vless+reality", true).await;
    assert!(visible(&inv, "alice").await.is_empty(), "deny-by-OR");
}

// Rule 10 — audit trail. Each successful set_server_protocol_hidden +
// set_grant_protocol_override writes ONE audit_log row with matching
// action + target + payload contents.
#[tokio::test]
async fn writes_audit_rows_with_matching_payloads() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality"]).await;
    add_grant(&inv, "alice").await;
    hide(&inv, "vless+reality", true).await;
    over(&inv, "alice", "vless+reality", true).await;

    let recent = inv.recent_audit(50).await.unwrap();
    let h = recent
        .iter()
        .find(|r| r.action == "server.protocol.set_hidden")
        .expect("set_hidden audit row");
    assert_eq!(h.target.as_deref(), Some("vps-x"));
    let pay = h.payload.as_ref().expect("hide payload");
    assert_eq!(pay["server_id"], serde_json::json!("vps-x"));
    assert_eq!(pay["protocol_id"], serde_json::json!("vless+reality"));
    assert_eq!(pay["old_hidden"], serde_json::json!(false));
    assert_eq!(pay["new_hidden"], serde_json::json!(true));

    let o = recent
        .iter()
        .find(|r| r.action == "grant.protocol.set_override")
        .expect("set_override audit row");
    assert_eq!(o.target.as_deref(), Some("alice"));
    let pay = o.payload.as_ref().expect("override payload");
    assert_eq!(pay["user_id"], serde_json::json!("alice"));
    assert_eq!(pay["server_id"], serde_json::json!("vps-x"));
    assert_eq!(pay["protocol_id"], serde_json::json!("vless+reality"));
    assert_eq!(pay["disabled"], serde_json::json!(true));
}

// Rule 11 — alphabetical ordering, regardless of insertion order.
#[tokio::test]
async fn visible_protocols_are_alphabetically_sorted() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality", "anytls", "trojan", "tuic-v5"]).await;
    add_grant(&inv, "alice").await;
    assert_eq!(
        visible(&inv, "alice").await,
        vec!["anytls", "trojan", "tuic-v5", "vless+reality"]
    );
}

// Spec hardening — visible_protocols_for_subscription returns the
// visible-on-server list even WITHOUT a grant for (uid, sid). The query
// must not silently start requiring a JOIN to grants.
#[tokio::test]
async fn visible_protocols_returns_server_list_without_grant() {
    let dir = TempDir::new().unwrap();
    let inv = setup(&dir, &["vless+reality", "tuic-v5"]).await;
    inv.add_user(&usr("alice")).await.unwrap();
    // No grant on purpose.
    assert_eq!(
        visible(&inv, "alice").await,
        vec!["tuic-v5", "vless+reality"]
    );
}
