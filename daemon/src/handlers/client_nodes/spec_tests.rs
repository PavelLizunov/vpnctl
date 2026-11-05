#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::http::HeaderMap;
use serde_json::{Value, json};

use super::spec_support::{Fixture, Sample};

fn assert_keys(value: &Value, expected: &[&str]) {
    let mut actual: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

fn assert_safe_headers(headers: &HeaderMap) {
    assert!(
        headers
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .split(',')
            .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"))
    );
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["referrer-policy"], "no-referrer");
}

fn assert_node_contract(node: &Value) {
    assert_keys(
        node,
        &[
            "endpoint_host",
            "country_iso",
            "memory_total_mib",
            "memory_available_mib",
            "load_1min_x100",
            "observed_at",
            "age_seconds",
            "freshness",
        ],
    );
    assert!(node["endpoint_host"].is_string());
    if !node["country_iso"].is_null() {
        let country = node["country_iso"].as_str().unwrap();
        assert_eq!(country.len(), 2);
        assert!(country.bytes().all(|letter| letter.is_ascii_uppercase()));
    }
    for field in [
        "memory_total_mib",
        "memory_available_mib",
        "load_1min_x100",
        "observed_at",
    ] {
        assert!(node[field].is_null() || node[field].as_i64().is_some());
    }
    assert!(node["age_seconds"].is_null() || node["age_seconds"].as_u64().is_some());
    assert!(matches!(
        node["freshness"].as_str(),
        Some("unknown" | "fresh" | "stale")
    ));
}

async fn metadata(fixture: &Fixture, path: &str) -> Value {
    let before = fixture.now();
    let (status, headers, body) = fixture.request(path).await;
    let after = fixture.now();
    assert_eq!(status.as_u16(), 200, "metadata request {path}");
    assert_safe_headers(&headers);
    assert_eq!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap(),
        "application/json"
    );
    assert_keys(
        &body,
        &["schema", "generated_at", "max_age_seconds", "nodes"],
    );
    assert_eq!(body["schema"], 1);
    let generated_at = body["generated_at"].as_i64().unwrap();
    assert!(generated_at >= before && generated_at <= after);
    assert_eq!(body["max_age_seconds"], fixture.ttl());
    for node in body["nodes"].as_array().unwrap() {
        assert_node_contract(node);
    }
    body
}

async fn unauthorized(fixture: &Fixture, path: &str) -> Value {
    let (status, headers, body) = fixture.request(path).await;
    assert_eq!(status.as_u16(), 401, "unauthorized request {path}");
    assert_safe_headers(&headers);
    body
}

fn only_node(body: &Value) -> &Value {
    let nodes = body["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);
    &nodes[0]
}

fn assert_sample_clock(body: &Value, observed_at: i64) {
    let node = only_node(body);
    assert_eq!(node["observed_at"], observed_at);
    let generated_at = body["generated_at"].as_i64().unwrap();
    if observed_at > generated_at {
        assert_eq!(node["age_seconds"], Value::Null);
        assert_eq!(node["freshness"], "unknown");
    } else {
        let age = u64::try_from(i128::from(generated_at) - i128::from(observed_at)).unwrap();
        assert_eq!(node["age_seconds"], age);
        let ttl = body["max_age_seconds"].as_u64().unwrap();
        assert_eq!(
            node["freshness"],
            if age <= ttl { "fresh" } else { "stale" }
        );
    }
}

#[tokio::test]
async fn missing_credentials_share_the_generic_unauthorized_response() {
    for path in [
        "/api/v1/app/node-status/device",
        "/api/v1/app/node-status/device/",
        "/api/v1/app/node-status/subscription",
        "/api/v1/app/node-status/subscription/",
    ] {
        let fixture = Fixture::new().await;
        let generic = unauthorized(
            &fixture,
            "/api/v1/app/node-status/device/not-a-valid-credential",
        )
        .await;
        assert_eq!(unauthorized(&fixture, path).await, generic);
    }
}

#[tokio::test]
async fn malformed_credentials_share_the_generic_unauthorized_response() {
    for credential in ["not-a-valid-credential", "null", "0", "%20", "%2F"] {
        let fixture = Fixture::new().await;
        let device = unauthorized(
            &fixture,
            &format!("/api/v1/app/node-status/device/{credential}"),
        )
        .await;
        let subscription = unauthorized(
            &fixture,
            &format!("/api/v1/app/node-status/subscription/{credential}"),
        )
        .await;
        assert_eq!(device, subscription);
    }
}

#[tokio::test]
async fn well_formed_unknown_credentials_share_the_generic_unauthorized_response() {
    let fixture = Fixture::new().await;
    let other_inventory = Fixture::new().await;
    let unknown = other_inventory.user(false).await;
    let generic = unauthorized(
        &fixture,
        "/api/v1/app/node-status/device/not-a-valid-credential",
    )
    .await;
    assert_eq!(
        unauthorized(
            &fixture,
            &format!("/api/v1/app/node-status/device/{}", unknown.device_id)
        )
        .await,
        generic
    );
    assert_eq!(
        unauthorized(
            &fixture,
            &format!("/api/v1/app/node-status/subscription/{}", unknown.sub_token)
        )
        .await,
        generic
    );
}

#[tokio::test]
async fn disabled_users_cannot_authenticate_with_either_identity() {
    let fixture = Fixture::new().await;
    let disabled = fixture.user(true).await;
    let node = fixture.node("192.0.2.10", true, "vpn-exit").await;
    fixture.grant(&disabled, &node).await;
    let generic = unauthorized(
        &fixture,
        "/api/v1/app/node-status/device/not-a-valid-credential",
    )
    .await;
    assert_eq!(
        unauthorized(
            &fixture,
            &format!("/api/v1/app/node-status/device/{}", disabled.device_id)
        )
        .await,
        generic
    );
    assert_eq!(
        unauthorized(
            &fixture,
            &format!(
                "/api/v1/app/node-status/subscription/{}",
                disabled.sub_token
            )
        )
        .await,
        generic
    );
}

#[tokio::test]
async fn nested_trailing_and_encoded_segments_never_become_credentials() {
    for suffix in ["/", "/extra", "%2F", "%2Fextra"] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let generic = unauthorized(
            &fixture,
            "/api/v1/app/node-status/device/not-a-valid-credential",
        )
        .await;
        assert_eq!(
            unauthorized(
                &fixture,
                &format!("/api/v1/app/node-status/device/{}{suffix}", user.device_id),
            )
            .await,
            generic
        );
        assert_eq!(
            unauthorized(
                &fixture,
                &format!(
                    "/api/v1/app/node-status/subscription/{}{suffix}",
                    user.sub_token
                ),
            )
            .await,
            generic
        );
    }
}

#[tokio::test]
async fn an_enabled_user_with_no_grants_has_an_empty_node_projection() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    fixture.node("192.0.2.11", true, "vpn-exit").await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    assert_eq!(body["nodes"], json!([]));
}

#[tokio::test]
async fn a_users_projection_contains_only_that_users_granted_nodes() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let other = fixture.user(false).await;
    let own = fixture.node("192.0.2.12", true, "vpn-exit").await;
    let others = fixture.node("192.0.2.13", true, "vpn-exit").await;
    fixture.grant(&user, &own).await;
    fixture.grant(&other, &others).await;
    let own_body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    let other_body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/subscription/{}", other.sub_token),
    )
    .await;
    assert_eq!(only_node(&own_body)["endpoint_host"], "192.0.2.12");
    assert_eq!(only_node(&other_body)["endpoint_host"], "192.0.2.13");
}

#[tokio::test]
async fn revoked_grants_disappear_from_both_identity_projections() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.14", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    let before = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    assert_eq!(only_node(&before)["endpoint_host"], "192.0.2.14");
    fixture.revoke(&user, &node).await;
    for path in [
        format!("/api/v1/app/node-status/device/{}", user.device_id),
        format!("/api/v1/app/node-status/subscription/{}", user.sub_token),
    ] {
        assert_eq!(metadata(&fixture, &path).await["nodes"], json!([]));
    }
}

#[tokio::test]
async fn hidden_nodes_are_excluded_even_when_granted() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let visible = fixture.node("192.0.2.15", true, "vpn-exit").await;
    let hidden = fixture.node("192.0.2.16", false, "vpn-exit").await;
    fixture.grant(&user, &visible).await;
    fixture.grant(&user, &hidden).await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    assert_eq!(only_node(&body)["endpoint_host"], "192.0.2.15");
}

#[tokio::test]
async fn non_exit_nodes_are_excluded_even_when_visible_and_granted() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let exit = fixture.node("192.0.2.17", true, "vpn-exit").await;
    let non_exit = fixture.node("192.0.2.18", true, "vpn-entry").await;
    fixture.grant(&user, &exit).await;
    fixture.grant(&user, &non_exit).await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/subscription/{}", user.sub_token),
    )
    .await;
    assert_eq!(only_node(&body)["endpoint_host"], "192.0.2.17");
}

#[tokio::test]
async fn endpoint_hosts_are_projected_as_issued_without_invented_country_data() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let host = "gateway.synthetic.example.test";
    let node = fixture.node(host, true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    assert_eq!(only_node(&body)["endpoint_host"], host);
    assert_eq!(only_node(&body)["freshness"], "unknown");
}

#[tokio::test]
async fn device_and_subscription_identities_project_the_same_sample_data() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.19", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    let observed_at = fixture.now() - 10;
    fixture
        .sample(
            &node,
            Sample {
                total: Some(8192),
                available: Some(3072),
                load_x100: Some(237),
                observed_at,
            },
        )
        .await;
    let device = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    let subscription = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/subscription/{}", user.sub_token),
    )
    .await;
    assert_sample_clock(&device, observed_at);
    assert_sample_clock(&subscription, observed_at);
    let mut device_nodes = device["nodes"].clone();
    let mut subscription_nodes = subscription["nodes"].clone();
    for nodes in [&mut device_nodes, &mut subscription_nodes] {
        for node in nodes.as_array_mut().unwrap() {
            node.as_object_mut().unwrap().remove("age_seconds");
        }
    }
    assert_eq!(device_nodes, subscription_nodes);
}

#[tokio::test]
async fn absent_samples_keep_the_node_with_null_metrics_and_unknown_freshness() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.20", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/subscription/{}", user.sub_token),
    )
    .await;
    let node = only_node(&body);
    assert_eq!(node["endpoint_host"], "192.0.2.20");
    for field in [
        "memory_total_mib",
        "memory_available_mib",
        "load_1min_x100",
        "observed_at",
        "age_seconds",
    ] {
        assert_eq!(node[field], Value::Null, "absent sample field {field}");
    }
    assert_eq!(node["freshness"], "unknown");
}

#[tokio::test]
async fn valid_memory_and_unix_load_are_preserved_without_percentage_clamping() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.21", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    let observed_at = fixture.now() - 10;
    fixture
        .sample(
            &node,
            Sample {
                total: Some(8192),
                available: Some(3072),
                load_x100: Some(237),
                observed_at,
            },
        )
        .await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    let node = only_node(&body);
    assert_eq!(node["memory_total_mib"], 8192);
    assert_eq!(node["memory_available_mib"], 3072);
    assert_eq!(node["load_1min_x100"], 237);
    assert_sample_clock(&body, observed_at);
}

#[tokio::test]
async fn zero_available_memory_and_zero_load_are_valid_values() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.22", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    fixture
        .sample(
            &node,
            Sample {
                total: Some(1),
                available: Some(0),
                load_x100: Some(0),
                observed_at: fixture.now() - 1,
            },
        )
        .await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    assert_eq!(only_node(&body)["memory_total_mib"], 1);
    assert_eq!(only_node(&body)["memory_available_mib"], 0);
    assert_eq!(only_node(&body)["load_1min_x100"], 0);
}

#[tokio::test]
async fn available_memory_equal_to_total_is_valid_at_the_inclusive_boundary() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.23", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    fixture
        .sample(
            &node,
            Sample {
                total: Some(4096),
                available: Some(4096),
                load_x100: Some(100),
                observed_at: fixture.now() - 1,
            },
        )
        .await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/subscription/{}", user.sub_token),
    )
    .await;
    assert_eq!(only_node(&body)["memory_total_mib"], 4096);
    assert_eq!(only_node(&body)["memory_available_mib"], 4096);
}

#[tokio::test]
async fn invalid_memory_pairs_become_null_without_discarding_valid_load_or_time() {
    for (total, available) in [(0, 0), (-1, 0), (100, -1), (100, 101)] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let node = fixture.node("192.0.2.24", true, "vpn-exit").await;
        fixture.grant(&user, &node).await;
        let observed_at = fixture.now() - 10;
        fixture
            .sample(
                &node,
                Sample {
                    total: Some(total),
                    available: Some(available),
                    load_x100: Some(345),
                    observed_at,
                },
            )
            .await;
        let body = metadata(
            &fixture,
            &format!("/api/v1/app/node-status/device/{}", user.device_id),
        )
        .await;
        assert_eq!(only_node(&body)["memory_total_mib"], Value::Null);
        assert_eq!(only_node(&body)["memory_available_mib"], Value::Null);
        assert_eq!(only_node(&body)["load_1min_x100"], 345);
        assert_sample_clock(&body, observed_at);
    }
}

#[tokio::test]
async fn incomplete_memory_pairs_become_null_together() {
    for (total, available) in [(None, None), (None, Some(64)), (Some(128), None)] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let node = fixture.node("192.0.2.25", true, "vpn-exit").await;
        fixture.grant(&user, &node).await;
        fixture
            .sample(
                &node,
                Sample {
                    total,
                    available,
                    load_x100: Some(50),
                    observed_at: fixture.now() - 1,
                },
            )
            .await;
        let body = metadata(
            &fixture,
            &format!("/api/v1/app/node-status/subscription/{}", user.sub_token),
        )
        .await;
        assert_eq!(only_node(&body)["memory_total_mib"], Value::Null);
        assert_eq!(only_node(&body)["memory_available_mib"], Value::Null);
        assert_eq!(only_node(&body)["load_1min_x100"], 50);
    }
}

#[tokio::test]
async fn missing_or_out_of_range_load_is_null_without_discarding_valid_memory() {
    for load_x100 in [
        None,
        Some(-1),
        Some(i64::MIN),
        Some(i64::from(u32::MAX) + 1),
        Some(i64::MAX),
    ] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let node = fixture.node("192.0.2.26", true, "vpn-exit").await;
        fixture.grant(&user, &node).await;
        fixture
            .sample(
                &node,
                Sample {
                    total: Some(2048),
                    available: Some(512),
                    load_x100,
                    observed_at: fixture.now() - 1,
                },
            )
            .await;
        let body = metadata(
            &fixture,
            &format!("/api/v1/app/node-status/device/{}", user.device_id),
        )
        .await;
        assert_eq!(only_node(&body)["load_1min_x100"], Value::Null);
        assert_eq!(only_node(&body)["memory_total_mib"], 2048);
        assert_eq!(only_node(&body)["memory_available_mib"], 512);
    }
}

#[tokio::test]
async fn valid_memory_and_load_upper_bound_values_are_preserved() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.27", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    fixture
        .sample(
            &node,
            Sample {
                total: Some(i64::MAX),
                available: Some(i64::MAX),
                load_x100: Some(i64::from(u32::MAX)),
                observed_at: fixture.now() - 1,
            },
        )
        .await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/subscription/{}", user.sub_token),
    )
    .await;
    for field in ["memory_total_mib", "memory_available_mib"] {
        assert_eq!(only_node(&body)[field], i64::MAX);
    }
    assert_eq!(only_node(&body)["load_1min_x100"], u32::MAX);
}

#[tokio::test]
async fn the_default_effective_probe_interval_produces_a_1320_second_ttl() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    assert_eq!(fixture.ttl(), 1320);
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    assert_eq!(body["max_age_seconds"], 1320);
}

#[tokio::test]
async fn current_samples_have_server_derived_nonnegative_age_and_freshness() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.28", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    let observed_at = fixture.now();
    fixture
        .sample(
            &node,
            Sample {
                total: None,
                available: None,
                load_x100: None,
                observed_at,
            },
        )
        .await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    assert_sample_clock(&body, observed_at);
    assert_eq!(only_node(&body)["freshness"], "fresh");
}

#[tokio::test]
async fn samples_inside_the_ttl_are_fresh() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.29", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    let observed_at = fixture.now() - i64::try_from(fixture.ttl() / 2).unwrap();
    fixture
        .sample(
            &node,
            Sample {
                total: None,
                available: None,
                load_x100: None,
                observed_at,
            },
        )
        .await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/subscription/{}", user.sub_token),
    )
    .await;
    assert_sample_clock(&body, observed_at);
    assert_eq!(only_node(&body)["freshness"], "fresh");
}

#[tokio::test]
async fn the_ttl_freshness_boundary_is_inclusive_at_the_response_server_time() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.30", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    let observed_at = fixture.now() - i64::try_from(fixture.ttl()).unwrap();
    fixture
        .sample(
            &node,
            Sample {
                total: None,
                available: None,
                load_x100: None,
                observed_at,
            },
        )
        .await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/device/{}", user.device_id),
    )
    .await;
    // A real second may elapse during the request; judge the exact reported age.
    assert_sample_clock(&body, observed_at);
}

#[tokio::test]
async fn samples_older_than_the_ttl_keep_values_and_timestamp_while_stale() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node("192.0.2.31", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    let observed_at = fixture.now() - i64::try_from(fixture.ttl()).unwrap() - 1;
    fixture
        .sample(
            &node,
            Sample {
                total: Some(4096),
                available: Some(1024),
                load_x100: Some(456),
                observed_at,
            },
        )
        .await;
    let body = metadata(
        &fixture,
        &format!("/api/v1/app/node-status/subscription/{}", user.sub_token),
    )
    .await;
    let node = only_node(&body);
    assert_eq!(node["memory_total_mib"], 4096);
    assert_eq!(node["memory_available_mib"], 1024);
    assert_eq!(node["load_1min_x100"], 456);
    assert_eq!(node["freshness"], "stale");
    assert_sample_clock(&body, observed_at);
}

#[tokio::test]
async fn future_samples_keep_values_but_have_null_age_and_unknown_freshness() {
    for distant_future in [false, true] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let node = fixture.node("192.0.2.32", true, "vpn-exit").await;
        fixture.grant(&user, &node).await;
        let observed_at = if distant_future {
            253_402_300_799
        } else {
            fixture.now() + 60
        };
        fixture
            .sample(
                &node,
                Sample {
                    total: Some(1024),
                    available: Some(256),
                    load_x100: Some(321),
                    observed_at,
                },
            )
            .await;
        let body = metadata(
            &fixture,
            &format!("/api/v1/app/node-status/device/{}", user.device_id),
        )
        .await;
        assert_eq!(only_node(&body)["memory_total_mib"], 1024);
        assert_eq!(only_node(&body)["memory_available_mib"], 256);
        assert_eq!(only_node(&body)["load_1min_x100"], 321);
        assert_eq!(only_node(&body)["freshness"], "unknown");
        assert_sample_clock(&body, observed_at);
    }
}

#[tokio::test]
async fn polling_success_and_auth_failures_do_not_mutate_inventory_or_access_counts() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let disabled = fixture.user(true).await;
    let node = fixture.node("192.0.2.33", true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    fixture.grant(&disabled, &node).await;
    fixture
        .sample(
            &node,
            Sample {
                total: Some(512),
                available: Some(128),
                load_x100: Some(17),
                observed_at: fixture.now() - 1,
            },
        )
        .await;
    let before = fixture.read_only_counts().await;
    for path in [
        format!("/api/v1/app/node-status/device/{}", user.device_id),
        format!("/api/v1/app/node-status/subscription/{}", user.sub_token),
    ] {
        let body = metadata(&fixture, &path).await;
        assert_eq!(only_node(&body)["endpoint_host"], "192.0.2.33");
    }
    for path in [
        "/api/v1/app/node-status/device/not-a-valid-credential".to_owned(),
        "/api/v1/app/node-status/subscription/not-a-valid-credential".to_owned(),
        format!("/api/v1/app/node-status/device/{}", disabled.device_id),
        format!(
            "/api/v1/app/node-status/subscription/{}",
            disabled.sub_token
        ),
    ] {
        unauthorized(&fixture, &path).await;
    }
    assert_eq!(fixture.read_only_counts().await, before);
}

#[tokio::test]
async fn the_61st_immediate_request_is_throttled_without_using_another_identitys_budget() {
    for identity in ["device", "subscription"] {
        let fixture = Fixture::new().await;
        let user = fixture.user(false).await;
        let other_user = fixture.user(false).await;
        let (credential, other_credential) = if identity == "device" {
            (&user.device_id, &other_user.device_id)
        } else {
            (&user.sub_token, &other_user.sub_token)
        };
        let path = format!("/api/v1/app/node-status/{identity}/{credential}");
        let other_path = format!("/api/v1/app/node-status/{identity}/{other_credential}");
        let before = fixture.read_only_counts().await;
        for _ in 0..60 {
            assert_eq!(metadata(&fixture, &path).await["nodes"], json!([]));
        }
        let (status, headers, _) = fixture.request(&path).await;
        assert_eq!(status.as_u16(), 429);
        assert_safe_headers(&headers);
        assert!(!headers["retry-after"].to_str().unwrap().trim().is_empty());
        assert_eq!(metadata(&fixture, &other_path).await["nodes"], json!([]));
        assert_eq!(fixture.read_only_counts().await, before);
    }
}
