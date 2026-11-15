#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};

use super::spec_support::Fixture;

fn object_keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<_> = value
        .as_object()
        .expect("metadata values must be JSON objects")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

fn assert_unknown_projection(snapshot: &Value, expected_hosts: &[&str]) {
    assert_eq!(
        object_keys(snapshot),
        ["generated_at", "max_age_seconds", "nodes", "schema"]
    );
    assert_eq!(snapshot["schema"], json!(1));
    assert!(
        snapshot["generated_at"].as_u64().is_some(),
        "generated_at must be a Unix timestamp"
    );
    assert_eq!(snapshot["max_age_seconds"], json!(1320));

    let nodes = snapshot["nodes"]
        .as_array()
        .expect("nodes must be a JSON array");
    let mut actual_hosts = Vec::with_capacity(nodes.len());
    for node in nodes {
        assert_eq!(
            object_keys(node),
            [
                "activity_level",
                "age_seconds",
                "country_iso",
                "endpoint_host",
                "freshness",
                "load_1min_x100",
                "memory_available_mib",
                "memory_total_mib",
                "observed_at",
            ]
        );
        actual_hosts.push(
            node["endpoint_host"]
                .as_str()
                .expect("endpoint_host must be a string"),
        );
        for field in [
            "country_iso",
            "memory_total_mib",
            "memory_available_mib",
            "load_1min_x100",
            "observed_at",
            "age_seconds",
        ] {
            assert!(node[field].is_null(), "absent {field} must be JSON null");
        }
        assert_eq!(node["freshness"], json!("unknown"));
    }
    actual_hosts.sort_unstable();
    let mut expected_hosts = expected_hosts.to_vec();
    expected_hosts.sort_unstable();
    assert_eq!(actual_hosts, expected_hosts);
}

async fn same_node_alias_snapshot(
    primary_host: &str,
    protocol_id: &str,
    alias_host: &str,
) -> Value {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture.node(primary_host, true, "vpn-exit").await;
    fixture.grant(&user, &node).await;
    fixture.protocol_alias(&node, protocol_id, alias_host).await;

    let (status, _, snapshot) = fixture
        .request(&format!(
            "/api/v1/app/node-status/device/{}",
            user.device_id
        ))
        .await;
    assert_eq!(status.as_u16(), 200);
    snapshot
}

#[tokio::test]
async fn reality_and_naive_dns_case_variants_have_one_canonical_host() {
    let snapshot =
        same_node_alias_snapshot("node.example.invalid", "naive", "NODE.EXAMPLE.INVALID").await;
    assert_unknown_projection(&snapshot, &["node.example.invalid"]);
}

#[tokio::test]
async fn reality_and_vless_ws_dns_case_variants_have_one_canonical_host() {
    let snapshot =
        same_node_alias_snapshot("NODE.EXAMPLE.INVALID", "vless-ws", "node.example.invalid").await;
    assert_unknown_projection(&snapshot, &["node.example.invalid"]);
}

#[tokio::test]
async fn reality_and_naive_root_dot_variants_have_one_canonical_host() {
    let snapshot =
        same_node_alias_snapshot("node.example.invalid", "naive", "node.example.invalid.").await;
    assert_unknown_projection(&snapshot, &["node.example.invalid"]);
}

#[tokio::test]
async fn reality_and_vless_ws_root_dot_variants_have_one_canonical_host() {
    let snapshot =
        same_node_alias_snapshot("NODE.EXAMPLE.INVALID.", "vless-ws", "node.example.invalid").await;
    assert_unknown_projection(&snapshot, &["node.example.invalid"]);
}

#[tokio::test]
async fn reality_and_naive_ipv6_spellings_have_one_canonical_host() {
    let snapshot = same_node_alias_snapshot(
        "2001:0db8:0000:0000:0000:0000:0000:0053",
        "naive",
        "2001:DB8::53",
    )
    .await;
    assert_unknown_projection(&snapshot, &["2001:db8::53"]);
}

#[tokio::test]
async fn reality_and_vless_ws_ipv6_spellings_have_one_canonical_host() {
    let snapshot = same_node_alias_snapshot(
        "2001:DB8::53",
        "vless-ws",
        "2001:0db8:0000:0000:0000:0000:0000:0053",
    )
    .await;
    assert_unknown_projection(&snapshot, &["2001:db8::53"]);
}

#[tokio::test]
async fn different_aliases_on_one_physical_node_remain_separate_hosts() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture
        .node("primary.example.invalid", true, "vpn-exit")
        .await;
    fixture.grant(&user, &node).await;
    fixture
        .protocol_alias(&node, "naive", "NAIVE.EXAMPLE.INVALID.")
        .await;
    fixture
        .protocol_alias(&node, "vless-ws", "ws.example.invalid")
        .await;

    let (status, _, snapshot) = fixture
        .request(&format!(
            "/api/v1/app/node-status/device/{}",
            user.device_id
        ))
        .await;
    assert_eq!(status.as_u16(), 200);
    assert_unknown_projection(
        &snapshot,
        &[
            "primary.example.invalid",
            "naive.example.invalid",
            "ws.example.invalid",
        ],
    );
}

#[tokio::test]
async fn shared_alias_on_two_granted_physical_nodes_preserves_both_rows() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let first = fixture
        .node("first.example.invalid", true, "vpn-exit")
        .await;
    let second = fixture
        .node("second.example.invalid", true, "vpn-exit")
        .await;
    fixture.grant(&user, &first).await;
    fixture.grant(&user, &second).await;
    fixture
        .protocol_alias(&first, "naive", "shared.example.invalid")
        .await;
    fixture
        .protocol_alias(&second, "vless-ws", "shared.example.invalid")
        .await;

    let (status, _, snapshot) = fixture
        .request(&format!(
            "/api/v1/app/node-status/device/{}",
            user.device_id
        ))
        .await;
    assert_eq!(status.as_u16(), 200);
    assert_unknown_projection(
        &snapshot,
        &[
            "first.example.invalid",
            "second.example.invalid",
            "shared.example.invalid",
            "shared.example.invalid",
        ],
    );
}

#[tokio::test]
async fn equivalent_aliases_on_two_physical_nodes_preserve_ambiguity() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let first = fixture
        .node("first.example.invalid", true, "vpn-exit")
        .await;
    let second = fixture
        .node("second.example.invalid", true, "vpn-exit")
        .await;
    fixture.grant(&user, &first).await;
    fixture.grant(&user, &second).await;
    fixture
        .protocol_alias(&first, "naive", "SHARED.EXAMPLE.INVALID.")
        .await;
    fixture
        .protocol_alias(&second, "vless-ws", "shared.example.invalid")
        .await;

    let (status, _, snapshot) = fixture
        .request(&format!(
            "/api/v1/app/node-status/device/{}",
            user.device_id
        ))
        .await;
    assert_eq!(status.as_u16(), 200);
    assert_unknown_projection(
        &snapshot,
        &[
            "first.example.invalid",
            "second.example.invalid",
            "shared.example.invalid",
            "shared.example.invalid",
        ],
    );
}

#[tokio::test]
async fn different_users_keep_their_granted_node_when_aliases_are_shared() {
    let fixture = Fixture::new().await;
    let first_user = fixture.user(false).await;
    let second_user = fixture.user(false).await;
    let first = fixture
        .node("first.example.invalid", true, "vpn-exit")
        .await;
    let second = fixture
        .node("second.example.invalid", true, "vpn-exit")
        .await;
    fixture.grant(&first_user, &first).await;
    fixture.grant(&second_user, &second).await;
    fixture
        .protocol_alias(&first, "naive", "shared.example.invalid")
        .await;
    fixture
        .protocol_alias(&second, "vless-ws", "SHARED.EXAMPLE.INVALID.")
        .await;

    for (device_id, primary_host) in [
        (&first_user.device_id, "first.example.invalid"),
        (&second_user.device_id, "second.example.invalid"),
        (&first_user.device_id, "first.example.invalid"),
    ] {
        let (status, _, snapshot) = fixture
            .request(&format!("/api/v1/app/node-status/device/{device_id}"))
            .await;
        assert_eq!(status.as_u16(), 200);
        assert_unknown_projection(&snapshot, &[primary_host, "shared.example.invalid"]);
    }
}

#[tokio::test]
async fn canonical_endpoint_response_matches_the_shared_consumer_snapshot() {
    let fixture = Fixture::new().await;
    let user = fixture.user(false).await;
    let node = fixture
        .node("NODE.EXAMPLE.INVALID.", true, "vpn-exit")
        .await;
    fixture.grant(&user, &node).await;
    fixture
        .protocol_alias(&node, "naive", "node.example.invalid")
        .await;
    fixture
        .protocol_alias(&node, "vless-ws", "NoDe.ExAmPlE.InVaLiD.")
        .await;

    let (status, _, mut actual) = fixture
        .request(&format!(
            "/api/v1/app/node-status/device/{}",
            user.device_id
        ))
        .await;
    assert_eq!(status.as_u16(), 200);
    assert_unknown_projection(&actual, &["node.example.invalid"]);

    let expected: Value = serde_json::from_str(include_str!("canonical_endpoint_snapshot.json"))
        .expect("the shared consumer snapshot must be valid JSON");
    actual["generated_at"] = json!(2000);
    assert_eq!(actual, expected);
}
