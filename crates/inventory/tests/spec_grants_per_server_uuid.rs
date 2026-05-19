//! Spec for `grants.client_uuid` — the per-(user, server) VLESS UUID
//! override introduced by migration `0016_grants_per_server_uuid.sql`
//! (Phase 1 of the ninitux subscription-server absorption — see
//! `docs/COMPREHENSIVE_AUDIT_2026-05-19.md`).
//!
//! Behaviour pinned here:
//!
//!   1. Migration backfills `client_uuid` from the user's global
//!      `users.uuid` for every pre-existing grant. Result: every
//!      `(user, server)` pair's effective uuid is byte-identical to
//!      the pre-Phase-1 rendering.
//!
//!   2. `users_for_server` returns each peer with `uuid` already
//!      overridden by `grants.client_uuid` when one is set, else
//!      falls back to `users.uuid`.
//!
//!   3. `client_uuid_for(user, server)` returns the same effective
//!      uuid, OR `None` when no grant exists.
//!
//!   4. `set_grant_client_uuid` mutates an EXISTING grant and refuses
//!      with `Invalid` when the grant doesn't exist (callers must
//!      `grant()` first).
//!
//!   5. `revoke()` followed by `grant()` resets `client_uuid` to NULL
//!      (the new grant row's default), so a re-grant returns the
//!      global `users.uuid` until the operator sets a fresh override.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

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
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("global-uuid-of-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
    }
}

// Rule 1 — backfill correctness. After opening a fresh DB (which runs
// migration 0016) AND after adding grants the normal way, the per-grant
// uuid returned by users_for_server matches the user's global uuid.
//
// This is the byte-equality invariant: a /sub/<token> response rendered
// by the daemon BEFORE Phase 2 import script runs must be identical to
// what it would have returned without migration 0016.
#[tokio::test]
async fn grants_render_with_users_uuid_until_an_override_is_set() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    // users_for_server: peer's uuid is the user's global uuid (no
    // override has been set; backfill — if it ran at all on this
    // grant — copied users.uuid into client_uuid, so COALESCE picks
    // either side and they're equal).
    let peers = inv
        .users_for_server(&ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].id.0, "alice");
    assert_eq!(peers[0].uuid, "global-uuid-of-alice");

    // client_uuid_for: same value.
    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("global-uuid-of-alice"));
}

// Rule 2 — once an override is set, BOTH the bulk render path
// (`users_for_server`) AND the point lookup (`client_uuid_for`) reflect
// it. The user's global uuid is untouched.
#[tokio::test]
async fn override_changes_only_the_per_server_render_not_user_identity() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "12345678-1234-1234-1234-123456789abc",
    )
    .await
    .unwrap();

    // users_for_server: per-server uuid is returned.
    let peers = inv
        .users_for_server(&ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(peers[0].uuid, "12345678-1234-1234-1234-123456789abc");

    // client_uuid_for: per-server uuid.
    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("12345678-1234-1234-1234-123456789abc"));

    // The user's global identity is UNCHANGED — sub_token lookups,
    // audit-log targets, /admin/users/{id} routing etc. all keep
    // pointing to the same user object via the global uuid.
    let alice = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.uuid, "global-uuid-of-alice");
}

// Rule 2.5 — overrides are per-(user, server). Setting one server's
// override does NOT bleed into a DIFFERENT server's grant for the same
// user. This is the whole point of moving to per-server uuids: a leak
// on one server doesn't compromise the user's identity on the others.
#[tokio::test]
async fn override_on_one_server_does_not_leak_to_other_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-de")).await.unwrap();
    inv.add_server(&server("vps-is")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-de".into()))
        .await
        .unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-is".into()))
        .await
        .unwrap();

    // Override only on vps-de.
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-de".into()),
        "deadbeef-0000-0000-0000-de00de00de00",
    )
    .await
    .unwrap();

    // vps-de reports the override; vps-is reports the global uuid.
    let de = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-de".into()))
        .await
        .unwrap();
    assert_eq!(de.as_deref(), Some("deadbeef-0000-0000-0000-de00de00de00"));
    let is = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-is".into()))
        .await
        .unwrap();
    assert_eq!(is.as_deref(), Some("global-uuid-of-alice"));

    let peers_is = inv
        .users_for_server(&ServerId("vps-is".into()))
        .await
        .unwrap();
    assert_eq!(peers_is[0].uuid, "global-uuid-of-alice");
}

// Rule 3 — `client_uuid_for` returns None when no grant exists. This is
// the signal callers use to skip a (user, server) pair without
// surfacing an error.
#[tokio::test]
async fn client_uuid_for_returns_none_when_no_grant() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    // NB: deliberately no grant call.

    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got, None);
}

// Rule 4 — `set_grant_client_uuid` errors with `Invalid` when no grant
// exists for the pair. Callers must `grant()` first. Critical: this
// prevents the migration script from silently materialising a grant
// that the operator hasn't approved (a bug class that would diverge
// vpnctld inventory from the operator's intent).
#[tokio::test]
async fn set_grant_client_uuid_errors_when_no_grant() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    // Use a syntactically valid UUID so the shape gate doesn't fire
    // first — we want to exercise the «no grant exists» branch
    // specifically, not the malformed-uuid branch.
    let err = inv
        .set_grant_client_uuid(
            &UserId("alice".into()),
            &ServerId("vps-x".into()),
            "11111111-2222-3333-4444-555555555555",
        )
        .await
        .expect_err("must refuse when grant doesn't exist");
    match err {
        SqliteInventoryError::Invalid(m) => {
            assert!(
                m.contains("no grant for user=alice server=vps-x"),
                "got: {m}"
            );
        }
        other => panic!("expected Invalid, got: {other:?}"),
    }
}

// Rule 4.5 — `set_grant_client_uuid` is idempotent for the same value;
// callers don't have to read-before-write.
#[tokio::test]
async fn set_grant_client_uuid_is_idempotent_same_value() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "0000beef-1111-2222-3333-444444444444",
    )
    .await
    .unwrap();
    // Second call with same value is a no-op SQL-wise but must not
    // error.
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "0000beef-1111-2222-3333-444444444444",
    )
    .await
    .unwrap();

    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("0000beef-1111-2222-3333-444444444444"));
}

// Rule 5 — revoke + re-grant resets the override to NULL. The new
// grant row uses the default (NULL → COALESCE picks users.uuid), which
// means the operator who revokes-then-re-grants gets the user's global
// uuid as the effective per-server value until they explicitly set a
// fresh override. This is the safe default — re-grants don't carry
// over a stale per-server uuid that might have been baked into a
// long-gone server config.
#[tokio::test]
async fn revoke_then_grant_resets_client_uuid_to_null() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "99999999-aaaa-bbbb-cccc-dddddddddddd",
    )
    .await
    .unwrap();
    // Sanity: override is in effect.
    assert_eq!(
        inv.client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
            .await
            .unwrap()
            .as_deref(),
        Some("99999999-aaaa-bbbb-cccc-dddddddddddd")
    );

    inv.revoke(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    // After re-grant: client_uuid is NULL (the DEFAULT), so the
    // effective uuid is the user's GLOBAL uuid again.
    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("global-uuid-of-alice"));
}

// Rule 6 — `grant()` is still idempotent when the row already exists
// (ON CONFLICT DO NOTHING) AND it must NOT clear an existing override
// in that no-op path. This pins that the ninitux migration's "grant
// then set client_uuid" recipe is safe to re-run.
#[tokio::test]
async fn re_grant_on_existing_row_does_not_clear_override() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "11111111-2222-3333-4444-555555555555",
    )
    .await
    .unwrap();

    // Re-grant — should be a SQL no-op (ON CONFLICT DO NOTHING).
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    // Override must STILL be in effect.
    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some("11111111-2222-3333-4444-555555555555"));
}

// Rule 7 — `set_grant_client_uuid` rejects malformed UUID strings. Pins
// the write-boundary shape gate so a Phase 2 import script that emits
// one bad row fails loudly per-row instead of silently bricking a user
// (the server's sing-box would reject the malformed inbound entry on
// reload and the user would lose access with no telemetry signalling
// the cause — a worst-case silent failure mode).
#[tokio::test]
async fn set_grant_client_uuid_rejects_malformed_uuid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    for bad in ["", "  ", "not-a-uuid", "11111111-2222-3333-4444"] {
        let res = inv
            .set_grant_client_uuid(&UserId("alice".into()), &ServerId("vps-x".into()), bad)
            .await;
        match res {
            Err(SqliteInventoryError::Invalid(m)) => {
                assert!(
                    m.contains("not a valid UUID"),
                    "expected 'not a valid UUID' diagnostic for bad={bad:?}, got: {m}"
                );
            }
            Err(other) => {
                panic!("expected Invalid for bad={bad:?}, got: {other:?}");
            }
            Ok(()) => panic!("expected Err for bad={bad:?}, but the write succeeded"),
        }
    }

    // And confirm the column was NOT mutated to any of the bad values.
    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(
        got.as_deref(),
        Some("global-uuid-of-alice"),
        "rejected writes must not have side-effects on the column"
    );
}

// Rule 8 — every `set_grant_client_uuid` call lands a `grant.set_client_uuid`
// audit row whose payload records both the prior + new uuid. So the
// operator can trace «when did this user's vps-de-01 uuid change?»
// without grepping logs.
#[tokio::test]
async fn set_grant_client_uuid_writes_audit_row_with_old_and_new_uuid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    .await
    .unwrap();

    let recent = inv.recent_audit(10).await.unwrap();
    let row = recent
        .iter()
        .find(|r| r.action == "grant.set_client_uuid")
        .expect("grant.set_client_uuid audit row must be written");
    assert_eq!(row.target.as_deref(), Some("alice"));
    let payload = row.payload.as_ref().expect("payload must be present");
    assert_eq!(payload["server_id"], serde_json::json!("vps-x"));
    // First call → old was NULL (no prior override).
    assert_eq!(payload["old_client_uuid"], serde_json::Value::Null);
    assert_eq!(
        payload["new_client_uuid"],
        serde_json::json!("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    );

    // A second call should record the previous value as the old uuid.
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "11111111-2222-3333-4444-555555555555",
    )
    .await
    .unwrap();
    let recent = inv.recent_audit(10).await.unwrap();
    let row = recent
        .iter()
        .find(|r| {
            r.action == "grant.set_client_uuid"
                && r.payload
                    .as_ref()
                    .and_then(|p| p["new_client_uuid"].as_str())
                    == Some("11111111-2222-3333-4444-555555555555")
        })
        .expect("second grant.set_client_uuid audit row must be present");
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(
        payload["old_client_uuid"],
        serde_json::json!("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    );
}

// Rule 9 — FK CASCADE on the new column. Deleting a user must cascade
// the grants AND their client_uuid (the override has no separate
// lifecycle from its parent grant). Pins that the new column lives
// «inside» the grant row, not as a side-table that could survive a
// user delete.
#[tokio::test]
async fn remove_user_cascades_to_grant_and_client_uuid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "11111111-2222-3333-4444-555555555555",
    )
    .await
    .unwrap();

    inv.remove_user(&UserId("alice".into())).await.unwrap();

    // The grant + its client_uuid must be gone.
    let got = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got, None);
    let peers = inv
        .users_for_server(&ServerId("vps-x".into()))
        .await
        .unwrap();
    assert!(
        peers.is_empty(),
        "peers list must be empty after user delete"
    );
}

// Rule 10 — fresh grant rows post-migration have NULL `client_uuid`
// in the raw column (NOT a COALESCE'd value masking a missing
// backfill). The runtime correctness in earlier tests depends on
// COALESCE picking up users.uuid when client_uuid is NULL — those
// tests would still pass if the column was somehow populated with
// the user's uuid by something OTHER than the migration backfill
// (e.g. a future trigger or an over-eager `grant()` change). This
// test reads the raw column via direct sqlx, so an inverted impl
// (column always written) would be caught here.
#[tokio::test]
async fn fresh_grant_starts_with_null_client_uuid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    // Open a raw sqlx pool to the same DB and SELECT the column
    // directly — bypass the COALESCE that the public API applies.
    use sqlx::Row;
    let url = format!("sqlite://{}?mode=ro", db_path(&dir).display());
    let raw = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let row = sqlx::query(
        "SELECT client_uuid FROM grants WHERE user_id = 'alice' AND server_id = 'vps-x'",
    )
    .fetch_one(&raw)
    .await
    .unwrap();
    let raw_value: Option<String> = row.try_get("client_uuid").unwrap();
    assert_eq!(
        raw_value, None,
        "fresh grant must have NULL client_uuid; if this test starts \
         failing, an implementation change is auto-populating the column \
         on insert — that breaks the «override» semantics (operator can no \
         longer distinguish «never overridden» from «explicitly set to \
         users.uuid»)"
    );

    // Sanity: the public read path still returns users.uuid via
    // COALESCE — the override semantics work end-to-end.
    let public = inv
        .client_uuid_for(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(public.as_deref(), Some("global-uuid-of-alice"));
    raw.close().await;
}

// Rule 11 — `SqliteInventory::user_with_per_server_uuid` swaps the
// user's uuid to the per-server override OR returns the original
// (cloned) when no grant or no override. This is the consolidated
// helper used by both `cli/cmd/sub.rs` and `daemon/handlers/sub.rs`
// (extracted to kill 3-way duplication).
#[tokio::test]
async fn user_with_per_server_uuid_swaps_only_when_override_differs() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("vps-x")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    let alice = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("vps-x".into()))
        .await
        .unwrap();

    // Case 1 — no override yet: helper returns user with global uuid
    // (other fields preserved verbatim).
    let got = inv
        .user_with_per_server_uuid(&alice, &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.uuid, "global-uuid-of-alice");
    assert_eq!(got.id, alice.id);

    // Case 2 — override set: helper returns user with overridden uuid.
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &ServerId("vps-x".into()),
        "11111111-2222-3333-4444-555555555555",
    )
    .await
    .unwrap();
    let got = inv
        .user_with_per_server_uuid(&alice, &ServerId("vps-x".into()))
        .await
        .unwrap();
    assert_eq!(got.uuid, "11111111-2222-3333-4444-555555555555");
    // The user we PASSED IN is unmutated — helper clones.
    assert_eq!(alice.uuid, "global-uuid-of-alice");

    // Case 3 — no grant: returns user unchanged (safe fallback for
    // a /sub render path that hit an inconsistent state).
    let got = inv
        .user_with_per_server_uuid(&alice, &ServerId("nope".into()))
        .await
        .unwrap();
    assert_eq!(got.uuid, "global-uuid-of-alice");
}

// Rule 12 — `User::with_per_server_uuid` (the shared helper extracted
// to vpnctl-core) replaces `User.uuid` and leaves every other field
// untouched. Pinned here because every share-link / client_config
// call-site (cli/sub, daemon/sub, daemon/admin × 2) depends on this
// contract for byte-equivalence with the pre-Phase-1 rendering.
#[test]
fn with_per_server_uuid_replaces_uuid_field_only() {
    let alice = user("alice");
    let mut expected = alice.clone();
    expected.uuid = "per-server-replacement".to_string();

    let got = alice.with_per_server_uuid("per-server-replacement");

    assert_eq!(got.id, expected.id);
    assert_eq!(got.uuid, "per-server-replacement");
    assert_eq!(got.tuic_password, alice.tuic_password);
    assert_eq!(got.wireguard_pubkey, alice.wireguard_pubkey);
    assert_eq!(got.wireguard_private, alice.wireguard_private);
    assert_eq!(got.sub_token, alice.sub_token);

    // Original User must NOT be mutated — helper returns a clone.
    assert_eq!(alice.uuid, "global-uuid-of-alice");
}
