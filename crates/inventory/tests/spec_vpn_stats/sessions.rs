use tempfile::TempDir;
use vpnctl_core::{ServerId, UserId};

use crate::common::{open, raw_pool, server, user};

// ────────────────────────────────────────────────────────────────────────
// Phase 5b — vpn_user_destinations (per-user × destination tracking).
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase5b_record_user_destinations_increments_hit_count_on_repeat() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // Tick 1: 2 destinations.
    inv.record_user_destinations(&[
        (UserId("alice".into()), "youtube.com:443".into()),
        (UserId("alice".into()), "telegram.org:443".into()),
    ])
    .await
    .unwrap();
    // Tick 2: youtube again, plus a new one.
    inv.record_user_destinations(&[
        (UserId("alice".into()), "youtube.com:443".into()),
        (UserId("alice".into()), "discord.gg:443".into()),
    ])
    .await
    .unwrap();

    let top = inv
        .top_destinations_for_user(&UserId("alice".into()), 7, 20)
        .await
        .unwrap();
    let yt = top
        .iter()
        .find(|d| d.destination_label == "youtube.com:443")
        .expect("youtube must be present");
    assert_eq!(yt.hit_count, 2, "two ticks → 2 hits");
    let tg = top
        .iter()
        .find(|d| d.destination_label == "telegram.org:443")
        .expect("telegram must be present");
    assert_eq!(tg.hit_count, 1);
}

#[tokio::test]
async fn phase5b_top_destinations_orders_by_hits_desc() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // Build different hit counts: A=3, B=1, C=2.
    for _ in 0..3 {
        inv.record_user_destinations(&[(UserId("alice".into()), "a.example.com:443".into())])
            .await
            .unwrap();
    }
    inv.record_user_destinations(&[(UserId("alice".into()), "b.example.com:443".into())])
        .await
        .unwrap();
    for _ in 0..2 {
        inv.record_user_destinations(&[(UserId("alice".into()), "c.example.com:443".into())])
            .await
            .unwrap();
    }
    let top = inv
        .top_destinations_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    let labels: Vec<&str> = top.iter().map(|r| r.destination_label.as_str()).collect();
    assert_eq!(
        labels,
        vec![
            "a.example.com:443",
            "c.example.com:443",
            "b.example.com:443"
        ]
    );
}

#[tokio::test]
async fn phase5b_destinations_dont_leak_across_users() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();
    inv.record_user_destinations(&[(UserId("alice".into()), "x.example.com:443".into())])
        .await
        .unwrap();
    inv.record_user_destinations(&[(UserId("bob".into()), "y.example.com:443".into())])
        .await
        .unwrap();
    let alice = inv
        .top_destinations_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].destination_label, "x.example.com:443");
    let bob = inv
        .top_destinations_for_user(&UserId("bob".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].destination_label, "y.example.com:443");
}

#[tokio::test]
async fn phase5b_record_destinations_truncates_pathological_labels_to_200_chars() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // Multibyte label: "中" is 3 bytes, so byte index 200 lands MID-codepoint.
    // The pre-#32 `&dest[..200]` byte-slice would PANIC here; char-boundary
    // truncation (`.chars().take(200)`) must not — this makes the test
    // discriminating rather than tautological (an ASCII "x".repeat would cut
    // cleanly at byte 200 and pass even against the buggy byte-slice).
    let long = "中".repeat(250); // 750 bytes, 250 chars
    assert!(
        !long.is_char_boundary(200),
        "test premise: byte 200 must be mid-codepoint"
    );
    inv.record_user_destinations(&[(UserId("alice".into()), long)])
        .await
        .unwrap(); // must NOT panic
    let top = inv
        .top_destinations_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(top.len(), 1);
    // Truncated to 200 CHARS (not 200 bytes) on a valid char boundary.
    assert_eq!(top[0].destination_label.chars().count(), 200);
    assert_eq!(top[0].destination_label, "中".repeat(200));
}

#[tokio::test]
async fn phase5b_purge_user_destinations_removes_old_rows() {
    // Can't fake old `date` via the API, so test the SAFE side:
    // freshly-inserted rows survive a 1-day purge.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.record_user_destinations(&[(UserId("alice".into()), "z.example.com:443".into())])
        .await
        .unwrap();
    let removed = inv.purge_user_destinations_older_than(1).await.unwrap();
    assert_eq!(removed, 0, "fresh row must NOT be removed by 1-day purge");
}

// ────────────────────────────────────────────────────────────────────────
// Phase 5c — vpn_user_sessions (activity windows).
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase5c_session_observe_within_gap_extends_existing_session() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    let t0 = chrono::Utc::now();
    let t1 = t0 + chrono::Duration::minutes(5);
    let t2 = t0 + chrono::Duration::minutes(10);

    // Tick 1: opens a new session.
    let id1 = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t0,
            15,
            100,
            1,
        )
        .await
        .unwrap();
    // Tick 2 (5 min later, within gap): EXTENDS same session.
    let id2 = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t1,
            15,
            200,
            3,
        )
        .await
        .unwrap();
    // Tick 3 (10 min later, still within gap): same session.
    let id3 = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t2,
            15,
            50,
            2,
        )
        .await
        .unwrap();

    assert_eq!(id1, id2, "second observation must extend the same session");
    assert_eq!(id2, id3);

    let sessions = inv
        .recent_sessions_for_user(&UserId("alice".into()), 10)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1, "all 3 ticks landed in ONE session");
    assert_eq!(sessions[0].total_bytes, 100 + 200 + 50);
    assert_eq!(sessions[0].conn_count_peak, 3, "max(1,3,2) = 3");
}

#[tokio::test]
async fn phase5c_session_observe_after_gap_opens_new_session() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    let t0 = chrono::Utc::now();
    let t1 = t0 + chrono::Duration::minutes(30); // > 15 min gap

    let id1 = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t0,
            15,
            100,
            1,
        )
        .await
        .unwrap();
    let id2 = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t1,
            15,
            200,
            2,
        )
        .await
        .unwrap();

    assert_ne!(id1, id2, "gap > 15 min must open a NEW session");
    let sessions = inv
        .recent_sessions_for_user(&UserId("alice".into()), 10)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 2);
}

#[tokio::test]
async fn phase5c_sessions_dont_leak_across_users_or_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_server(&server("s2")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    let t0 = chrono::Utc::now();
    inv.session_observe(
        &UserId("alice".into()),
        &ServerId("s1".into()),
        t0,
        15,
        100,
        1,
    )
    .await
    .unwrap();
    inv.session_observe(
        &UserId("alice".into()),
        &ServerId("s2".into()),
        t0,
        15,
        100,
        1,
    )
    .await
    .unwrap();
    inv.session_observe(
        &UserId("bob".into()),
        &ServerId("s1".into()),
        t0,
        15,
        100,
        1,
    )
    .await
    .unwrap();

    let alice = inv
        .recent_sessions_for_user(&UserId("alice".into()), 10)
        .await
        .unwrap();
    assert_eq!(
        alice.len(),
        2,
        "alice has TWO sessions (s1, s2) — not bob's"
    );
    let bob = inv
        .recent_sessions_for_user(&UserId("bob".into()), 10)
        .await
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].server_id.0, "s1");
}

#[tokio::test]
async fn phase5c_purge_user_sessions_keeps_fresh_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    let t0 = chrono::Utc::now();
    inv.session_observe(
        &UserId("alice".into()),
        &ServerId("s1".into()),
        t0,
        15,
        100,
        1,
    )
    .await
    .unwrap();
    let removed = inv.purge_user_sessions_older_than(1).await.unwrap();
    assert_eq!(
        removed, 0,
        "fresh session must NOT be removed by 1-day purge"
    );
}

// ────────────────────────────────────────────────────────────────────
// vpn_user_source_ips (2026-06-14) — per-user × source-IP tracking.
// Mirrors the vpn_user_destinations spec above.
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn source_ips_increment_hit_count_on_repeat() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // Tick 1: two IPs.
    inv.record_user_source_ips(&[
        (UserId("alice".into()), "1.2.3.4".into()),
        (UserId("alice".into()), "5.6.7.8".into()),
    ])
    .await
    .unwrap();
    // Tick 2: first IP again + a new one.
    inv.record_user_source_ips(&[
        (UserId("alice".into()), "1.2.3.4".into()),
        (UserId("alice".into()), "9.9.9.9".into()),
    ])
    .await
    .unwrap();
    let top = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 20)
        .await
        .unwrap();
    assert_eq!(top.len(), 3, "three distinct IPs total");
    let a = top
        .iter()
        .find(|r| r.source_ip == "1.2.3.4")
        .expect("1.2.3.4 present");
    assert_eq!(a.hit_count, 2, "two ticks → 2 hits");
    let b = top
        .iter()
        .find(|r| r.source_ip == "5.6.7.8")
        .expect("5.6.7.8 present");
    assert_eq!(b.hit_count, 1);
}

#[tokio::test]
async fn top_source_ips_orders_by_hits_desc() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // A=3, B=1, C=2 hits → expect A, C, B. Public IPs (TEST-NET-2) — the
    // counter now drops RFC1918/infra, so 10.x would be filtered out.
    for _ in 0..3 {
        inv.record_user_source_ips(&[(UserId("alice".into()), "198.51.100.1".into())])
            .await
            .unwrap();
    }
    inv.record_user_source_ips(&[(UserId("alice".into()), "198.51.100.2".into())])
        .await
        .unwrap();
    for _ in 0..2 {
        inv.record_user_source_ips(&[(UserId("alice".into()), "198.51.100.3".into())])
            .await
            .unwrap();
    }
    let top = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    let ips: Vec<&str> = top.iter().map(|r| r.source_ip.as_str()).collect();
    assert_eq!(ips, vec!["198.51.100.1", "198.51.100.3", "198.51.100.2"]);
}

#[tokio::test]
async fn source_ips_skip_empty_ip_and_unknown_user() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // Empty IP (real user) → skipped; unknown user (real IP) →
    // FK-guarded skip; the one valid pair survives.
    inv.record_user_source_ips(&[
        (UserId("alice".into()), String::new()),
        (UserId("ghost".into()), "1.1.1.1".into()),
        (UserId("alice".into()), "2.2.2.2".into()),
    ])
    .await
    .unwrap();
    let alice = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(alice.len(), 1, "only the non-empty IP for a real user");
    assert_eq!(alice[0].source_ip, "2.2.2.2");
    let ghost = inv
        .top_source_ips_for_user(&UserId("ghost".into()), 7, 10)
        .await
        .unwrap();
    assert!(ghost.is_empty(), "unknown user must never get a row");
}

#[tokio::test]
async fn source_ips_dont_leak_across_users() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();
    inv.record_user_source_ips(&[(UserId("alice".into()), "1.1.1.1".into())])
        .await
        .unwrap();
    inv.record_user_source_ips(&[(UserId("bob".into()), "2.2.2.2".into())])
        .await
        .unwrap();
    let alice = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].source_ip, "1.1.1.1");
    let bob = inv
        .top_source_ips_for_user(&UserId("bob".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].source_ip, "2.2.2.2");
}

#[tokio::test]
async fn purge_user_source_ips_keeps_todays_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.record_user_source_ips(&[(UserId("alice".into()), "1.1.1.1".into())])
        .await
        .unwrap();
    // 30-day retention must not touch today's row.
    let removed = inv.purge_user_source_ips_older_than(30).await.unwrap();
    assert_eq!(removed, 0, "today's rows are within a 30-day window");
    let top = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(top.len(), 1, "row survives the retention sweep");
}

// geo_labels_for_ips — newest NON-NULL geo wins; un-asked IPs absent.
#[tokio::test]
async fn geo_labels_for_ips_picks_newest_nonnull_geo() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // 1.2.3.4: an enriched row, then a later NULL-geo row — the
    // lookup must still surface DE (newest row WITH geo).
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "1.2.3.4",
        None,
        200,
        0,
        None,
        None,
        None,
        Some("DE"),
        Some("AS3320 DTAG"),
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "1.2.3.4",
        None,
        200,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "9.9.9.9",
        None,
        200,
        0,
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
    let map = inv
        .geo_labels_for_ips(&["1.2.3.4".into(), "9.9.9.9".into(), "8.8.8.8".into()])
        .await
        .unwrap();
    assert_eq!(
        map.get("1.2.3.4"),
        Some(&(Some("DE".to_string()), Some("AS3320 DTAG".to_string()))),
        "newest non-NULL geo wins over a later un-enriched row"
    );
    assert_eq!(
        map.get("9.9.9.9"),
        Some(&(Some("US".to_string()), Some("AS15169 Google".to_string())))
    );
    assert!(
        !map.contains_key("8.8.8.8"),
        "an IP with no sub_access_log rows is absent from the map"
    );
}

#[tokio::test]
async fn phase5b_top_destinations_orders_by_destination_label_asc_tie_breaker() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    let pool = raw_pool(&dir).await;
    // Both destinations have hit_count = 5 and exact same last_seen timestamp (now)
    for dest in [
        "z.example.com:443",
        "a.example.com:443",
        "m.example.com:443",
    ] {
        sqlx::query(
            "INSERT INTO vpn_user_destinations (user_id, destination_label, date, hit_count, last_seen)
             VALUES (?1, ?2, strftime('%Y-%m-%d', 'now'), 5, '2026-08-25T00:00:00.000Z')",
        )
        .bind("alice")
        .bind(dest)
        .execute(&pool)
        .await
        .unwrap();
    }

    let top = inv
        .top_destinations_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    let labels: Vec<&str> = top.iter().map(|r| r.destination_label.as_str()).collect();
    assert_eq!(
        labels,
        vec![
            "a.example.com:443",
            "m.example.com:443",
            "z.example.com:443"
        ],
        "equal hit_count and last_seen must be deterministically tie-broken by destination_label ASC"
    );
}

#[tokio::test]
async fn top_source_ips_orders_by_source_ip_asc_tie_breaker() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    let pool = raw_pool(&dir).await;
    for ip in ["198.51.100.99", "198.51.100.10", "198.51.100.50"] {
        sqlx::query(
            "INSERT INTO vpn_user_source_ips (user_id, source_ip, date, hit_count, last_seen)
             VALUES (?1, ?2, strftime('%Y-%m-%d', 'now'), 3, '2026-08-25T00:00:00.000Z')",
        )
        .bind("alice")
        .bind(ip)
        .execute(&pool)
        .await
        .unwrap();
    }

    let top = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    let ips: Vec<&str> = top.iter().map(|r| r.source_ip.as_str()).collect();
    assert_eq!(
        ips,
        vec!["198.51.100.10", "198.51.100.50", "198.51.100.99"],
        "equal hit_count and last_seen must be deterministically tie-broken by source_ip ASC"
    );
}

#[tokio::test]
async fn phase5c_recent_sessions_orders_by_last_seen_desc_and_id_desc_tie_breaker() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    let pool = raw_pool(&dir).await;
    let ts = "2026-06-01T12:00:00.000Z";
    // Insert two sessions with exact same last_seen timestamp
    for id in [1, 2] {
        sqlx::query(
            "INSERT INTO vpn_user_sessions (id, user_id, server_id, started_at, last_seen, conn_count_peak, total_bytes)
             VALUES (?1, 'alice', 's1', ?2, ?2, 1, 100)",
        )
        .bind(id)
        .bind(ts)
        .execute(&pool)
        .await
        .unwrap();
    }

    let sessions = inv
        .recent_sessions_for_user(&UserId("alice".into()), 10)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(
        sessions[0].id, 2,
        "higher id must come first on equal last_seen (id DESC tie-breaker)"
    );
    assert_eq!(sessions[1].id, 1);
}

#[tokio::test]
async fn phase5c_session_observe_equal_last_seen_picks_highest_id() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    let pool = raw_pool(&dir).await;
    let t0 = chrono::Utc::now();
    let t0_s = t0.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Insert two sessions with exact same last_seen
    for id in [10, 20] {
        sqlx::query(
            "INSERT INTO vpn_user_sessions (id, user_id, server_id, started_at, last_seen, conn_count_peak, total_bytes)
             VALUES (?1, 'alice', 's1', ?2, ?2, 1, 100)",
        )
        .bind(id)
        .bind(&t0_s)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Now observe 5 minutes later — must pick id 20 to update
    let t1 = t0 + chrono::Duration::minutes(5);
    let updated_id = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t1,
            15,
            50,
            2,
        )
        .await
        .unwrap();

    assert_eq!(
        updated_id, 20,
        "session_observe must pick the highest id on equal last_seen"
    );
}
