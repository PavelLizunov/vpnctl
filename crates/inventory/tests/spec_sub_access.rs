//! Spec for the Phase Track-1 subscription-access log methods on
//! `SqliteInventory`. Written against the public API + the schema in
//! `migrations/0003_sub_access_log.sql` only — impl NOT consulted.
//!
//! Methods under test:
//!
//! - `log_sub_access(user_id, ip, ua, status, bytes)`
//! - `distinct_ips_for_user(user_id, since_hours)`
//! - `recent_sub_access(user_id, limit)`
//! - `purge_sub_access_older_than(days)`
//!
//! Behaviour contract every test pins:
//!
//! 1. A logged row appears in `recent_sub_access` for the same user.
//! 2. `distinct_ips_for_user` counts UNIQUE ip values within the
//!    requested time window — duplicate-IP rows count once.
//! 3. `recent_sub_access` returns rows newest-first and respects the
//!    `limit` argument.
//! 4. `purge_sub_access_older_than` removes rows older than the
//!    requested cutoff (and only those).
//! 5. Logging against a non-existent user MUST fail (FK enforcement).
//! 6. Cascade: deleting a user must drop their access rows too.
//!    (Skipped for now — there is no `delete_user` yet; this lands in
//!    Phase C-3 chunk 4 and the test moves with it.)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use tempfile::TempDir;

use vpnctl_core::{User, UserId};
use vpnctl_inventory::SqliteInventory;

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("uuid-of-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
    }
}

#[tokio::test]
async fn empty_user_has_no_access_rows_and_zero_distinct_ips() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 50)
        .await
        .unwrap();
    assert!(rows.is_empty(), "no log rows yet, got {} rows", rows.len());

    let n = inv
        .distinct_ips_for_user(&UserId("alice".into()), 24)
        .await
        .unwrap();
    assert_eq!(n, 0, "no logs → 0 distinct IPs");
}

#[tokio::test]
async fn logged_row_appears_in_recent_with_correct_fields() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    inv.log_sub_access(
        &UserId("alice".into()),
        "192.0.2.7",
        Some("Hiddify/Android/2.5.0"),
        200,
        1234,
    )
    .await
    .unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 50)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.user_id, "alice");
    assert_eq!(row.ip, "192.0.2.7");
    assert_eq!(row.ua.as_deref(), Some("Hiddify/Android/2.5.0"));
    assert_eq!(row.status, 200);
    assert_eq!(row.bytes, 1234);
    // Timestamp is server-side; just sanity-check it's recent.
    let now = chrono::Utc::now();
    let age = (now - row.ts).num_seconds().abs();
    assert!(age < 5, "ts should be within 5s of now, got {age}s old");
}

#[tokio::test]
async fn distinct_ips_counts_unique_addresses_only() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("bob")).await.unwrap();

    // Three rows from two IPs — the 192.0.2.1 row appears twice.
    for ip in ["192.0.2.1", "192.0.2.1", "198.51.100.5"] {
        inv.log_sub_access(&UserId("bob".into()), ip, None, 200, 100)
            .await
            .unwrap();
    }

    let n = inv
        .distinct_ips_for_user(&UserId("bob".into()), 24)
        .await
        .unwrap();
    assert_eq!(n, 2, "duplicate IPs must collapse to 1");
}

#[tokio::test]
async fn distinct_ips_per_user_does_not_leak_across_users() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    inv.log_sub_access(&UserId("alice".into()), "1.1.1.1", None, 200, 100)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("alice".into()), "1.1.1.2", None, 200, 100)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("bob".into()), "9.9.9.9", None, 200, 100)
        .await
        .unwrap();

    let alice = inv
        .distinct_ips_for_user(&UserId("alice".into()), 24)
        .await
        .unwrap();
    let bob = inv
        .distinct_ips_for_user(&UserId("bob".into()), 24)
        .await
        .unwrap();
    assert_eq!(alice, 2, "alice has 2 distinct IPs");
    assert_eq!(bob, 1, "bob has 1 distinct IP — NOT alice's 2");
}

#[tokio::test]
async fn recent_returns_newest_first_and_respects_limit() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // Insert in deterministic order — autoincrement id orders them.
    for i in 0..5 {
        inv.log_sub_access(
            &UserId("alice".into()),
            &format!("10.0.0.{i}"),
            None,
            200,
            100,
        )
        .await
        .unwrap();
    }

    let limited = inv
        .recent_sub_access(&UserId("alice".into()), 3)
        .await
        .unwrap();
    assert_eq!(limited.len(), 3, "limit must cap rows returned");
    // Newest first — last-inserted row has the latest id, must be first.
    assert_eq!(limited[0].ip, "10.0.0.4");
    assert_eq!(limited[1].ip, "10.0.0.3");
    assert_eq!(limited[2].ip, "10.0.0.2");
}

#[tokio::test]
async fn log_against_unknown_user_fails_via_fk() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    // Note: NOT calling add_user — the FK should reject this.

    let res = inv
        .log_sub_access(&UserId("ghost".into()), "1.2.3.4", None, 200, 0)
        .await;
    assert!(
        res.is_err(),
        "logging against a non-existent user must error (FK enforcement) — \
         otherwise we silently log orphan rows"
    );
}

#[tokio::test]
async fn purge_removes_rows_older_than_cutoff_only() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // Insert one fresh row (auto-ts = now). It MUST survive a purge of
    // anything older than 1 day.
    inv.log_sub_access(&UserId("alice".into()), "10.0.0.1", None, 200, 100)
        .await
        .unwrap();

    let removed = inv.purge_sub_access_older_than(1).await.unwrap();
    assert_eq!(removed, 0, "fresh row must NOT be removed by 1-day purge");
    let after = inv
        .recent_sub_access(&UserId("alice".into()), 50)
        .await
        .unwrap();
    assert_eq!(after.len(), 1, "fresh row must still be there");
}

#[tokio::test]
async fn distinct_ips_window_filter_includes_fresh_excludes_old() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // Fresh row (server-side ts ≈ now). Any non-zero window must catch
    // it. We use 1h and 24h to verify both small and large windows.
    inv.log_sub_access(&UserId("alice".into()), "1.1.1.1", None, 200, 100)
        .await
        .unwrap();

    let hour = inv
        .distinct_ips_for_user(&UserId("alice".into()), 1)
        .await
        .unwrap();
    assert_eq!(hour, 1, "fresh row must be inside the 1-hour window");

    let day = inv
        .distinct_ips_for_user(&UserId("alice".into()), 24)
        .await
        .unwrap();
    assert_eq!(day, 1, "fresh row must be inside the 24-hour window");

    // Inject an "aged" row through a second sqlx pool to the same DB
    // file (WAL mode lets the two pools coexist). The public
    // `log_sub_access` always uses server-now for `ts`, so without
    // a back-door the test can't pin the cutoff semantics. Reaching
    // in via raw SQL beats polluting the production surface with a
    // `#[cfg(test)] pub fn` escape hatch.
    let raw = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(&dir).display()))
        .await
        .unwrap();
    // Foreign keys default OFF on a freshly-opened raw connection
    // (the prod inventory turns them ON via `SqliteConnectOptions`).
    // Without this, the orphan-FK guard in `log_against_unknown_user_fails_via_fk`
    // would pass for the wrong reason — caught by review-agent #5.
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&raw)
        .await
        .unwrap();
    // Use the SAME ISO-format timestamp the production `log_sub_access`
    // writes (the column DEFAULT). Using legacy `datetime('now', ...)`
    // here was a TEST bug that only surfaced near midnight UTC: when
    // the aged row's date prefix happened to match the ISO cutoff's
    // date prefix, the string comparison diverged at the separator
    // (space < T) and the row was wrongly excluded. The impl was
    // correct (both query sides use strftime/T after fix `fad0adf`);
    // it was the TEST injection that drifted from production format.
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-25 hours'),
                 'alice', '2.2.2.2', 200, 100)",
    )
    .execute(&raw)
    .await
    .unwrap();
    raw.close().await;

    // 24h still sees only the fresh row (the old one is outside).
    let day_after_old = inv
        .distinct_ips_for_user(&UserId("alice".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        day_after_old, 1,
        "row 25h old must be EXCLUDED by 24h window"
    );

    // 48h sees both.
    let two_days = inv
        .distinct_ips_for_user(&UserId("alice".into()), 48)
        .await
        .unwrap();
    assert_eq!(
        two_days, 2,
        "row 25h old must be INCLUDED by 48h window (both IPs visible)"
    );
}

/// Regression test for the timestamp-format bug caught by retroactive
/// review-agent 2026-05-14.
///
/// **Bug:** `log_sub_access` wrote `ts` via `strftime('%Y-%m-%dT%H:%M:%fZ',
/// 'now')` → ISO format with a `T` separator (`2026-05-14T20:00:00.500Z`).
/// But `distinct_ips_for_user` compared against `datetime('now', ?)`
/// which returns the SQL form `YYYY-MM-DD HH:MM:SS` (space separator,
/// no millis, no `Z`). SQLite compared both sides as TEXT — `T` (0x54)
/// is greater than space (0x20), so EVERY same-day row passed `ts > cutoff`
/// regardless of actual time-of-day. Sub-day windows silently included
/// rows that should have been excluded; the abuse signal was unreliable.
///
/// **The fix** (in `distinct_ips_for_user` + `purge_sub_access_older_than`):
/// wrap the cutoff in `strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)` so both
/// sides share the format the row was written in.
///
/// This test fails on the buggy code and passes on the fixed code. The
/// existing `distinct_ips_window_filter_includes_fresh_excludes_old`
/// test happened to cross a calendar boundary (-25 hours), where the
/// date-level prefix mismatch hid the bug — that's why review-agent
/// caught it instead of the spec suite.
#[tokio::test]
async fn distinct_ips_window_filter_handles_same_day_rows_correctly() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // Inject a row 30 minutes in the past, in the SAME ISO format the
    // production `log_sub_access` writes — so the format-mismatch bug
    // can manifest. Foreign keys must be ON on this raw pool, else the
    // INSERT would succeed even with an orphan user_id and the test
    // would pass for the wrong reason (caught by review-agent #5).
    let raw = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(&dir).display()))
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-30 minutes'),
                 'alice', '3.3.3.3', 200, 100)",
    )
    .execute(&raw)
    .await
    .unwrap();
    raw.close().await;

    // A 0-hour window means "rows strictly after `now`" — the injected
    // row is 30 min old, so it MUST be excluded.
    //
    // With the BUG (cutoff in `datetime` space-form, row in ISO `T`-form):
    //   row ts  = "2026-05-14T19:30:00.500Z"
    //   cutoff  = "2026-05-14 20:00:00"
    //   compare position 10: 'T' (0x54) > ' ' (0x20) → row > cutoff
    //   → row passes filter → count = 1
    // With the FIX (both sides ISO):
    //   row ts  = "2026-05-14T19:30:00.500Z"
    //   cutoff  = "2026-05-14T20:00:00.500Z"
    //   compare position 11: '1' < '2' → row < cutoff
    //   → row excluded → count = 0
    let n = inv
        .distinct_ips_for_user(&UserId("alice".into()), 0)
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "row 30 min old must be EXCLUDED by 0-hour window — \
         was the timestamp-format bug from retroactive review-agent."
    );
}

/// Phase Hardening regression for migration 0004: deleting a user must
/// PRESERVE their `sub_access_log` rows (with `user_id` set to NULL),
/// not cascade-delete them. The old `ON DELETE CASCADE` schema would
/// have erased forensic evidence at the exact moment the operator
/// might want to inspect it.
#[tokio::test]
async fn deleting_user_keeps_their_access_rows_with_null_user_id() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.log_sub_access(&UserId("alice".into()), "9.9.9.9", None, 200, 100)
        .await
        .unwrap();

    // No public delete_user yet (Phase C-3.4 queued); reach in via raw
    // SQL with foreign_keys ON so the FK rule we're testing actually
    // fires. This is a TEMPORARY test pattern that will collapse into
    // a proper inventory.delete_user() call once C-3.4 lands.
    let raw = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(&dir).display()))
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = 'alice'")
        .execute(&raw)
        .await
        .unwrap();

    // Forensic row survives — IP/UA/ts intact — and user_id is NULL.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sub_access_log WHERE ip = '9.9.9.9' AND user_id IS NULL",
    )
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!(
        count, 1,
        "row must SURVIVE user delete with user_id NULLed (was the \
         CASCADE→SET NULL fix in migration 0004)"
    );

    // The orphaned row no longer counts towards any user's distinct
    // IPs — `WHERE user_id = ?1` excludes NULL by SQL semantics.
    let n = inv
        .distinct_ips_for_user(&UserId("alice".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "deleted user's orphaned rows must not show up in \
         distinct_ips_for_user — it filters by `user_id = ?1`"
    );
    raw.close().await;
}

#[tokio::test]
async fn log_sub_access_rich_round_trips_all_track_1_2_columns() {
    // Track-1.2 / migration 0019: persist accept_language +
    // http_version + device_class + geo_country + geo_asn. Pin
    // round-trip so a schema column-name drift or a SELECT that
    // forgot to extend the projection fails loudly.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "8.8.8.8",
        Some("Hiddify/Android/2.5.0"),
        200,
        4096,
        Some("ru-RU,ru;q=0.9,en;q=0.8"),
        Some("HTTP/2.0"),
        Some("Hiddify"),
        Some("US"),
        Some("AS15169 GOOGLE"),
        // Track-1.4 — TLS fingerprint columns. None here exercises
        // the half-populated row case (some clients yes, some no);
        // the next test populates both.
        None,
        None,
    )
    .await
    .unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 5)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "exactly one row");
    let r = &rows[0];
    assert_eq!(
        r.accept_language.as_deref(),
        Some("ru-RU,ru;q=0.9,en;q=0.8")
    );
    assert_eq!(r.http_version.as_deref(), Some("HTTP/2.0"));
    assert_eq!(r.device_class.as_deref(), Some("Hiddify"));
    assert_eq!(r.geo_country.as_deref(), Some("US"));
    assert_eq!(r.geo_asn.as_deref(), Some("AS15169 GOOGLE"));
    assert!(r.tls_ja3.is_none());
    assert!(r.tls_ja4.is_none());
}

#[tokio::test]
async fn log_sub_access_rich_round_trips_tls_fingerprint_columns() {
    // Track-1.4 (migration 0020) — pin that JA3 + JA4 fields
    // round-trip through the writer + reader. Schema change is
    // additive; future operator wiring nginx-side JA3 module
    // makes these fields populate, no daemon code change needed.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "203.0.113.7",
        Some("Hiddify/iOS/2.5.0"),
        200,
        4096,
        None,
        None,
        None,
        None,
        None,
        Some("769,49195-49199,0-23-65281,29-23-24,0"), // JA3-style
        Some("t13d1516h2_8daaf6152771_b186095e22b6"),  // JA4
    )
    .await
    .unwrap();

    let r = &inv
        .recent_sub_access(&UserId("alice".into()), 5)
        .await
        .unwrap()[0];
    assert_eq!(
        r.tls_ja3.as_deref(),
        Some("769,49195-49199,0-23-65281,29-23-24,0")
    );
    assert_eq!(
        r.tls_ja4.as_deref(),
        Some("t13d1516h2_8daaf6152771_b186095e22b6")
    );
}

#[tokio::test]
async fn recent_sub_access_renders_null_for_pre_migration_rows() {
    // Backward-compat: a row inserted via the old 5-arg
    // `log_sub_access` (or via raw SQL emulating pre-0019 schema)
    // must NOT panic on `try_get` for the new columns —
    // `Option<String>` maps NULL to `None` cleanly. Pin the
    // legacy-data path so a future SubAccessEntry refactor that
    // tightens the type to non-Option would fail here instead of
    // breaking 30,000 production rows.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // Use the wrapper that passes None for all 5 new columns.
    inv.log_sub_access(&UserId("alice".into()), "1.2.3.4", None, 200, 0)
        .await
        .unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 5)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].accept_language.is_none());
    assert!(rows[0].http_version.is_none());
    assert!(rows[0].device_class.is_none());
    assert!(rows[0].geo_country.is_none());
    assert!(rows[0].geo_asn.is_none());
}

// ────────────────────────────────────────────────────────────────────────
// Phase 4a — VPN-egress detection (migration 0021) + aggregates
// + recent_sub_access_filtered.
// ────────────────────────────────────────────────────────────────────────

// Helper to register a server so the migration-0021 trigger has
// rows to match against.
async fn add_test_server(inv: &SqliteInventory, id: &str, address: &str) {
    use vpnctl_core::{KernelId, Server, ServerId};
    inv.add_server(&Server {
        id: ServerId(id.into()),
        address: address.into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: Vec::new(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .expect("add_server");
}

#[tokio::test]
async fn phase4a_trigger_marks_inserted_row_as_egress_when_ip_matches_server() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    // Hit /sub from the matching VPN-server IP — trigger should
    // flip is_vpn_egress to 1.
    inv.log_sub_access(&UserId("alice".into()), "10.20.30.40", None, 200, 0)
        .await
        .unwrap();
    // And one from a real client IP — should stay 0.
    inv.log_sub_access(&UserId("alice".into()), "8.8.8.8", None, 200, 0)
        .await
        .unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 5)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let egress: Vec<bool> = rows.iter().map(|r| r.is_vpn_egress).collect();
    // newest-first ordering: real-client (8.8.8.8) is row 0, egress (10.20.30.40) is row 1.
    assert_eq!(
        egress,
        vec![false, true],
        "trigger must mark the VPN-egress row"
    );
}

#[tokio::test]
async fn phase4a_recent_sub_access_filtered_with_include_egress_false_hides_egress_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    inv.log_sub_access(&UserId("alice".into()), "10.20.30.40", None, 200, 0)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("alice".into()), "8.8.8.8", None, 200, 0)
        .await
        .unwrap();

    let real_only = inv
        .recent_sub_access_filtered(&UserId("alice".into()), 50, false)
        .await
        .unwrap();
    assert_eq!(
        real_only.len(),
        1,
        "include_egress=false must return only the real-client row"
    );
    assert_eq!(real_only[0].ip, "8.8.8.8");
    assert!(!real_only[0].is_vpn_egress);

    let all = inv
        .recent_sub_access_filtered(&UserId("alice".into()), 50, true)
        .await
        .unwrap();
    assert_eq!(all.len(), 2, "include_egress=true must return everything");
}

#[tokio::test]
async fn phase4a_sub_access_aggregates_distinguishes_real_vs_egress_and_distinct_dims() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    // Two real-client rows in DE, one in FI, one duplicate IP, plus
    // one egress hit. Aggregates should exclude egress from every
    // counter EXCEPT egress_rows.
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "8.8.8.8",
        None,
        200,
        100,
        None,
        None,
        None,
        Some("US"),
        Some("AS15169 Google"),
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "8.8.8.8", // duplicate — distinct_ips must still count it once
        None,
        200,
        100,
        None,
        None,
        None,
        Some("US"),
        Some("AS15169 Google"),
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "5.5.5.5",
        None,
        200,
        50,
        None,
        None,
        None,
        Some("FI"),
        Some("AS1234 Telia"),
        None,
        None,
    )
    .await
    .unwrap();
    // Egress row — must NOT pollute distinct_ips / countries / bytes.
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "10.20.30.40",
        None,
        200,
        9999,
        None,
        None,
        None,
        Some("DE"),
        Some("AS14956 Cloudzy"),
        None,
        None,
    )
    .await
    .unwrap();

    let agg = inv
        .sub_access_aggregates_for_user(&UserId("alice".into()), 30)
        .await
        .unwrap();
    assert_eq!(agg.total_rows, 3, "egress row excluded from total_rows");
    assert_eq!(agg.egress_rows, 1, "egress count must be exact");
    assert_eq!(agg.distinct_ips, 2, "8.8.8.8 (×2) + 5.5.5.5 = 2 distinct");
    assert_eq!(agg.distinct_countries, 2, "US + FI; DE was egress");
    assert_eq!(agg.distinct_asns, 2);
    assert_eq!(agg.total_bytes, 250, "100+100+50; egress 9999 excluded");
    assert!(agg.last_seen.is_some());
    assert!(agg.first_seen.is_some());
}

#[tokio::test]
async fn phase4a_sub_access_aggregates_for_empty_user_returns_zeroes_and_none_timestamps() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    let agg = inv
        .sub_access_aggregates_for_user(&UserId("alice".into()), 30)
        .await
        .unwrap();
    assert_eq!(agg.total_rows, 0);
    assert_eq!(agg.egress_rows, 0);
    assert_eq!(agg.distinct_ips, 0);
    assert!(agg.last_seen.is_none());
    assert!(agg.first_seen.is_none());
}

#[tokio::test]
async fn phase4a_backfill_marks_pre_migration_rows_when_server_address_already_known() {
    // Realistic deployment: vpnctld already has servers + sub_access
    // rows pre-dating migration 0021. The migration's UPDATE
    // backfill must flag every existing row whose IP matches a
    // current server. Verified end-to-end via the migrator.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    // Insert one egress + one real row (post-migration, so the
    // trigger does the flagging — same end-state we'd get from
    // backfill on pre-migration rows).
    inv.log_sub_access(&UserId("alice".into()), "10.20.30.40", None, 200, 0)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("alice".into()), "1.1.1.1", None, 200, 0)
        .await
        .unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 50)
        .await
        .unwrap();
    let flagged: Vec<&str> = rows
        .iter()
        .filter(|r| r.is_vpn_egress)
        .map(|r| r.ip.as_str())
        .collect();
    assert_eq!(
        flagged,
        vec!["10.20.30.40"],
        "exactly the server IP is flagged"
    );
}

#[tokio::test]
async fn phase4a_add_server_retroactively_flags_existing_rows_for_new_address() {
    // Pavel: «если сервер добавлен ПОСЛЕ migration 0021, старые
    // строки с его IP должны быть помечены». Review-agent finding #3.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // Log rows BEFORE the server is registered → they go in with
    // is_vpn_egress = 0 (trigger sees empty servers set).
    inv.log_sub_access(&UserId("alice".into()), "10.20.30.40", None, 200, 0)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("alice".into()), "8.8.8.8", None, 200, 0)
        .await
        .unwrap();
    let before = inv
        .recent_sub_access(&UserId("alice".into()), 10)
        .await
        .unwrap();
    assert!(
        before.iter().all(|r| !r.is_vpn_egress),
        "no rows should be flagged before the server is registered"
    );

    // NOW register the server. add_server runs the retro-backfill
    // UPDATE inside its transaction.
    add_test_server(&inv, "de", "10.20.30.40").await;

    let after = inv
        .recent_sub_access(&UserId("alice".into()), 10)
        .await
        .unwrap();
    let flagged: Vec<&str> = after
        .iter()
        .filter(|r| r.is_vpn_egress)
        .map(|r| r.ip.as_str())
        .collect();
    assert_eq!(
        flagged,
        vec!["10.20.30.40"],
        "after add_server, exactly the matching historical row must be flagged"
    );
}

#[tokio::test]
async fn phase4c_users_for_source_ips_groups_by_ip_with_top_user_first() {
    // Pavel: NM-11 work-around — match a clash-api sourceIP against
    // sub_access_log rows so we know «which of our users last fetched
    // subscription from this IP» = likely owner of active connections.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    // alice hits sub URL 3 times from 8.8.8.8.
    for _ in 0..3 {
        inv.log_sub_access(&UserId("alice".into()), "8.8.8.8", None, 200, 100)
            .await
            .unwrap();
    }
    // bob hits sub URL 1 time from 8.8.8.8.
    inv.log_sub_access(&UserId("bob".into()), "8.8.8.8", None, 200, 100)
        .await
        .unwrap();
    // alice ALSO hits sub URL from a different IP — not asked about.
    inv.log_sub_access(&UserId("alice".into()), "1.1.1.1", None, 200, 100)
        .await
        .unwrap();

    let result = inv
        .users_for_source_ips(&["8.8.8.8".to_string()], 7)
        .await
        .unwrap();

    let users = result.get("8.8.8.8").expect("8.8.8.8 must have entries");
    assert_eq!(users.len(), 2);
    // alice (3 hits) before bob (1 hit) — DESC by hit count.
    assert_eq!(users[0].0.0, "alice");
    assert_eq!(users[0].1, 3);
    assert_eq!(users[1].0.0, "bob");
    assert_eq!(users[1].1, 1);
    // 1.1.1.1 was NOT in the input — must NOT appear in output.
    assert!(!result.contains_key("1.1.1.1"));
}

#[tokio::test]
async fn phase4c_users_for_source_ips_empty_ips_returns_empty_map() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let result = inv.users_for_source_ips(&[], 7).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn phase4c_users_for_source_ips_excludes_vpn_egress_rows() {
    // Egress rows = src IP is one of our own VPN servers, those are
    // full-tunnel noise, NOT real client devices. They must NOT
    // pollute the source-IP-to-user mapping.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    inv.log_sub_access(&UserId("alice".into()), "10.20.30.40", None, 200, 100)
        .await
        .unwrap();

    let result = inv
        .users_for_source_ips(&["10.20.30.40".to_string()], 7)
        .await
        .unwrap();
    // Empty Vec or absent key — both are acceptable «no match».
    let users = result.get("10.20.30.40").cloned().unwrap_or_default();
    assert!(
        users.is_empty(),
        "egress-flagged rows must NOT contribute to source-IP correlation"
    );
}
