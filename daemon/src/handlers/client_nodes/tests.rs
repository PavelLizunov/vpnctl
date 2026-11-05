#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::projection::{NodeMetadata, country_for_ips, country_for_node, ttl_for_interval};

#[test]
fn canonical_endpoint_hosts_reject_malformed_aliases_without_affecting_valid_ip_literals() {
    for host in [
        "",
        ".",
        "node..example.invalid",
        "-node.example.invalid",
        "node-.example.invalid",
        "[node.example.invalid]",
        "[192.0.2.1]",
        "[[2001:db8::1]]",
        "node.example.invalid:443",
        "https://node.example.invalid",
        "999.999.999.999",
        "node.example.invalid..",
    ] {
        assert_eq!(super::canonical_endpoint_host(host), None, "{host}");
    }
    assert_eq!(
        super::canonical_endpoint_host("[2001:0db8::1]"),
        Some("2001:db8::1".into())
    );
    assert_eq!(
        super::canonical_endpoint_host("192.0.2.1"),
        Some("192.0.2.1".into())
    );
}

#[test]
fn hostname_country_uses_only_cached_node_addresses_and_requires_consensus() {
    let a = "192.0.2.1".parse().unwrap();
    let b = "2001:db8::1".parse().unwrap();
    assert_eq!(
        country_for_node("node.example.test", &[a, b], |_| Some("SE".into())),
        Some("SE".into())
    );
    assert_eq!(
        country_for_node("node.example.test", &[], |_| Some("SE".into())),
        None
    );
    assert_eq!(
        country_for_node("node.example.test", &[a, b], |ip| Some(
            if ip == a { "CH" } else { "IS" }.into()
        )),
        None
    );
    assert_eq!(
        country_for_node("192.0.2.1", &[b], |ip| {
            assert_eq!(ip, a);
            Some("NL".into())
        }),
        Some("NL".into())
    );
}

#[test]
fn local_country_lookup_accepts_consensus_and_rejects_missing_or_ambiguous_results() {
    let a = "192.0.2.1".parse().unwrap();
    let b = "2001:db8::1".parse().unwrap();
    let mut looked_up = Vec::new();
    assert_eq!(
        country_for_ips(&[a, b], |ip| {
            looked_up.push(ip);
            Some("ch".into())
        }),
        Some("CH".into())
    );
    assert_eq!(looked_up, [a, b]);
    assert_eq!(country_for_ips(&[], |_| Some("CH".into())), None);
    assert_eq!(country_for_ips(&[a], |_| None), None);
    assert_eq!(country_for_ips(&[a], |_| Some("provider".into())), None);
    assert_eq!(
        country_for_ips(&[a, b], |ip| if ip == a {
            Some("CH".into())
        } else {
            Some("IS".into())
        }),
        None
    );
    assert_eq!(
        country_for_ips(&[a, b], |ip| if ip == a { Some("CH".into()) } else { None }),
        None
    );
}

#[test]
fn ttl_caps_extreme_intervals_without_overflowing() {
    assert_eq!(ttl_for_interval(600), 1320);
    assert_eq!(ttl_for_interval(43_139), 86_398);
    assert_eq!(ttl_for_interval(43_140), 86_400);
    assert_eq!(ttl_for_interval(43_141), 86_400);
    assert_eq!(ttl_for_interval(u64::MAX), 86_400);
}

#[test]
fn missing_health_does_not_suppress_a_locally_known_country() {
    let node = NodeMetadata::new(
        "node.example.test".into(),
        Some("NL".into()),
        None,
        1000,
        1320,
    );
    let json = serde_json::to_value(node).unwrap();
    assert_eq!(json["endpoint_host"], "node.example.test");
    assert_eq!(json["country_iso"], "NL");
    assert!(json["observed_at"].is_null());
    assert!(json["memory_total_mib"].is_null());
    assert!(json["load_1min_x100"].is_null());
    assert_eq!(json["freshness"], "unknown");
}
