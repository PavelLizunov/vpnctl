#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;

use super::spec_support::{Fixture, NodeFixture, Sample, UserFixture};

const GIB: i64 = 1024 * 1024 * 1024;

async fn fresh_health(fixture: &Fixture, node: &NodeFixture, observed_at: i64) {
    fixture
        .sample(
            node,
            Sample {
                total: Some(8192),
                available: Some(3072),
                load_x100: Some(237),
                observed_at,
            },
        )
        .await;
}

async fn traffic(fixture: &Fixture, node: &NodeFixture, hours: i64, total: i64) {
    let now = fixture.now();
    for offset in (0..=(hours - 1) * 6).rev() {
        fixture
            .nic_sample(
                node,
                now - offset * 600,
                if offset == 0 { total / 2 } else { 0 },
                if offset == 0 { total - total / 2 } else { 0 },
            )
            .await;
    }
}

async fn snapshot(fixture: &Fixture, user: &UserFixture) -> Value {
    let before = fixture.read_only_counts().await;
    let (status, headers, body) = fixture
        .request(&format!(
            "/api/v1/app/node-status/device/{}",
            user.device_id
        ))
        .await;
    assert_eq!(status.as_u16(), 200);
    assert!(
        headers["cache-control"]
            .to_str()
            .unwrap()
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("no-store"))
    );
    assert_eq!(before, fixture.read_only_counts().await);
    assert_eq!(body["schema"], 1);
    body
}

fn only_node(snapshot: &Value) -> &Value {
    let nodes = snapshot["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);
    &nodes[0]
}

#[tokio::test]
async fn activity_uses_exact_binary_gib_boundaries_and_preserves_existing_metrics() {
    for (bytes, expected) in [
        (0, "low"),
        (25 * GIB - 1, "low"),
        (25 * GIB, "medium"),
        (100 * GIB - 1, "medium"),
        (100 * GIB, "high"),
    ] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let node = fixture.node("192.0.2.60", true, "vpn-exit").await;
        fixture.grant(&user, &node).await;
        traffic(&fixture, &node, 20, bytes).await;
        fresh_health(&fixture, &node, fixture.now() - 1).await;
        let body = snapshot(&fixture, &user).await;
        let result = only_node(&body);
        assert_eq!(result["activity_level"], expected, "{bytes} bytes");
        assert_eq!(result["memory_total_mib"], 8192);
        assert_eq!(result["memory_available_mib"], 3072);
        assert_eq!(result["load_1min_x100"], 237);
        assert_eq!(result["endpoint_host"], "192.0.2.60");
        assert_eq!(result["freshness"], "fresh");
    }
}

#[tokio::test]
async fn fewer_than_twenty_distinct_observed_hours_remain_unknown() {
    for (hours, expected) in [(19, "unknown"), (20, "high")] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let node = fixture.node("192.0.2.61", true, "vpn-exit").await;
        fixture.grant(&user, &node).await;
        traffic(&fixture, &node, hours, 101 * GIB).await;
        fresh_health(&fixture, &node, fixture.now() - 1).await;
        let body = snapshot(&fixture, &user).await;
        assert_eq!(only_node(&body)["activity_level"], expected);
    }
}

#[tokio::test]
async fn stale_or_future_latest_health_cannot_make_traffic_activity_current() {
    for observation in [Some(-1), Some(1)] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let node = fixture.node("192.0.2.62", true, "vpn-exit").await;
        fixture.grant(&user, &node).await;
        traffic(&fixture, &node, 20, 101 * GIB).await;
        if let Some(direction) = observation {
            let observed_at = if direction < 0 {
                fixture.now() - i64::try_from(fixture.ttl()).unwrap() - 10
            } else {
                fixture.now() + 3600
            };
            fresh_health(&fixture, &node, observed_at).await;
        }
        let body = snapshot(&fixture, &user).await;
        assert_eq!(only_node(&body)["activity_level"], "unknown");
    }
}

#[tokio::test]
async fn absent_or_stale_traffic_is_unknown_even_with_fresh_health() {
    for seeded in [false, true] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let node = fixture.node("192.0.2.63", true, "vpn-exit").await;
        fixture.grant(&user, &node).await;
        if seeded {
            let end = fixture.now() - i64::try_from(fixture.ttl()).unwrap() - 10;
            for offset in (0..=120).rev() {
                fixture
                    .nic_sample(&node, end - offset * 600, 0, (120 - offset) * GIB)
                    .await;
            }
        }
        fresh_health(&fixture, &node, fixture.now() - 1).await;
        let body = snapshot(&fixture, &user).await;
        assert_eq!(only_node(&body)["activity_level"], "unknown");
    }
}

#[tokio::test]
async fn buckets_before_the_window_do_not_raise_current_activity() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.64", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    fixture
        .nic_sample(&node, fixture.now() - 25 * 3600, 100 * GIB, 100 * GIB)
        .await;
    traffic(&fixture, &node, 20, 25 * GIB - 1).await;
    fresh_health(&fixture, &node, fixture.now() - 1).await;
    let body = snapshot(&fixture, &user).await;
    assert_eq!(only_node(&body)["activity_level"], "low");
}

#[tokio::test]
async fn activity_does_not_expose_an_ungranted_node_or_weaken_authentication() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let granted = fixture.node("192.0.2.65", true, "vpn-exit").await;
    let other = fixture.node("192.0.2.66", true, "vpn-exit").await;
    fixture.grant(&user, &granted).await;
    traffic(&fixture, &granted, 20, 0).await;
    traffic(&fixture, &other, 20, 101 * GIB).await;
    for node in [&granted, &other] {
        fresh_health(&fixture, node, fixture.now() - 1).await;
    }
    let body = snapshot(&fixture, &user).await;
    let result = only_node(&body);
    assert_eq!(result["endpoint_host"], "192.0.2.65");
    assert_eq!(result["activity_level"], "low");
    let (status, _, rejected) = fixture
        .request("/api/v1/app/node-status/device/not-a-valid-credential")
        .await;
    assert_eq!(status.as_u16(), 401);
    assert!(rejected["nodes"].is_null());
    assert!(rejected["activity_level"].is_null());
}

#[tokio::test]
async fn invalid_in_window_traffic_is_unknown_instead_of_dropped_or_clamped() {
    for invalid in ["negative", "future", "overflow"] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let node = fixture.node("192.0.2.67", true, "vpn-exit").await;
        fixture.grant(&user, &node).await;
        traffic(&fixture, &node, 20, 0).await;
        let now = fixture.now();
        if invalid == "overflow" {
            // Two full counter cycles overflow u64 in the RX+TX total.
            fixture.nic_sample(&node, now, i64::MAX, i64::MAX).await;
            fixture.nic_sample(&node, now, 0, 0).await;
            fixture.nic_sample(&node, now, i64::MAX, i64::MAX).await;
        } else {
            fixture
                .nic_sample(
                    &node,
                    if invalid == "future" { now + 3600 } else { now },
                    if invalid == "negative" { -1 } else { 0 },
                    101 * GIB,
                )
                .await;
        }
        fresh_health(&fixture, &node, now).await;
        let body = snapshot(&fixture, &user).await;
        assert_eq!(only_node(&body)["activity_level"], "unknown", "{invalid}");
    }
}
