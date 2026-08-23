//! Admin UI legacy handlers — facade over thematic submodules.

mod dashboard;
mod deploy_sse;
mod server_detail;
mod settings;
mod shell;
mod user_sections;

pub(crate) use self::dashboard::*;
pub(crate) use self::deploy_sse::*;
pub(crate) use self::server_detail::*;
pub(crate) use self::settings::*;
pub(crate) use self::user_sections::*;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod helper_tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn format_msk_shifts_utc_by_plus_three_hours_and_marks_timezone() {
        // Noon UTC = 15:00 MSK. The MSK literal is part of the
        // contract — see the user-detail Sessions table where the
        // operator needs the timezone to be unambiguous.
        let utc = chrono::Utc.with_ymd_and_hms(2026, 5, 21, 12, 0, 0).unwrap();
        assert_eq!(format_msk(utc), "05-21 15:00 MSK");
    }

    #[test]
    fn format_msk_wraps_across_midnight_when_adding_offset() {
        // 22:30 UTC on 2026-05-21 = 01:30 MSK on 2026-05-22.
        // Date column has to advance too — otherwise the late-night
        // ticks would all look like they happened "yesterday" in MSK.
        let utc = chrono::Utc
            .with_ymd_and_hms(2026, 5, 21, 22, 30, 0)
            .unwrap();
        assert_eq!(format_msk(utc), "05-22 01:30 MSK");
    }

    #[test]
    fn extract_ip_from_label_returns_ip_for_bare_ipv4_port_form() {
        assert_eq!(extract_ip_from_label("1.2.3.4:443"), Some("1.2.3.4"));
        assert_eq!(extract_ip_from_label("10.0.0.1:80"), Some("10.0.0.1"));
    }

    #[test]
    fn dashboard_heavy_users_renders_three_columns_upload_download_total() {
        // 2026-06-16 — the tile must show upload / download / total as
        // three separate aligned columns (was a single "— total" suffix).
        let window = VpnSparklineWindow {
            slug: "24h",
            label_en: "24h",
            label_ru: "24ч",
            cells: 24,
            bucket_hours: 1,
            per_bucket_en: "per hour",
            per_bucket_ru: "в час",
        };
        let rows = vec![vpnctl_inventory::HeavyUser {
            user_id: vpnctl_core::UserId("alice".into()),
            upload_bytes: 1_500_000_000,
            download_bytes: 3_000_000_000,
            total_bytes: 4_500_000_000,
        }];
        let html = dashboard_heavy_users(&rows, window, crate::i18n::Locale::En).into_string();
        // Three distinct column headers.
        assert!(html.contains("Upload"), "missing Upload header: {html}");
        assert!(html.contains("Download"), "missing Download header");
        assert!(html.contains("Total"), "missing Total header");
        // All three figures rendered (distinct humanized values).
        assert!(
            html.contains(&humanize_bytes(1_500_000_000)),
            "missing upload value"
        );
        assert!(
            html.contains(&humanize_bytes(3_000_000_000)),
            "missing download value"
        );
        assert!(
            html.contains(&humanize_bytes(4_500_000_000)),
            "missing total value"
        );
        // User still links through to the detail page.
        assert!(html.contains("/admin/users/alice"), "missing user link");
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_hostname_form() {
        // Hostname segment contains non-digit, non-dot chars (letters,
        // hyphens) — we leave these as-is because the poller already
        // had a DNS name from sing-box metadata; enriching would just
        // duplicate the host.
        assert!(extract_ip_from_label("www.microsoft.com:443").is_none());
        assert!(extract_ip_from_label("api-v2.example.io:8443").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_already_enriched_label() {
        // `hostname:port (ip)` shape produced by Phase 5d enrichment
        // and the server-detail aggregator. The `(ip)` suffix breaks
        // the all-digits port check — the helper should refuse,
        // preventing a second enrichment round (which would render
        // garbage like `hostname:port (ip) (ip)`).
        assert!(extract_ip_from_label("example.com:443 (1.2.3.4)").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_ipv6_form() {
        // IPv6 has internal colons. The rsplit_once peels off only
        // the last `:`-segment, and the remainder contains colons
        // which fail the `digit-or-dot` check. Skipping IPv6 is
        // acceptable for Phase 5d — VPN destinations are overwhelmingly
        // v4; v6 support can be added when the cache learns it.
        assert!(extract_ip_from_label("2001:db8::1:8080").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_malformed_input() {
        assert!(extract_ip_from_label("no-colon-at-all").is_none());
        assert!(extract_ip_from_label(":443").is_none()); // empty IP
        assert!(extract_ip_from_label("1.2.3.4:").is_none()); // empty port
        assert!(extract_ip_from_label("1.2.3.4:notaport").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_ip_for_portless_bare_ipv4() {
        // The clash-poller writes the destination_label as just the IP
        // (no colon, no port) when `destination_port` is empty — see
        // `daemon::clash_poller::poll_one_server` portless branch.
        // Those rows must enrich too, otherwise the most opaque ones
        // (UDP / ICMP-style flows with no port metadata) stay as raw IPs.
        assert_eq!(extract_ip_from_label("1.2.3.4"), Some("1.2.3.4"));
        assert_eq!(extract_ip_from_label("10.0.0.1"), Some("10.0.0.1"));
    }

    #[test]
    fn classify_reserved_ip_labels_private_and_special_ranges() {
        // RFC1918 private.
        assert_eq!(classify_reserved_ip("192.168.0.207"), Some("private/LAN"));
        assert_eq!(classify_reserved_ip("10.1.2.3"), Some("private/LAN"));
        assert_eq!(classify_reserved_ip("172.16.5.5"), Some("private/LAN"));
        // Loopback.
        assert_eq!(classify_reserved_ip("127.0.0.1"), Some("loopback"));
        assert_eq!(classify_reserved_ip("::1"), Some("loopback"));
        // RFC6598 carrier-grade NAT (100.64/10) — the 100.120.2.214
        // case from the real main-brat origins table.
        assert_eq!(classify_reserved_ip("100.64.0.1"), Some("CGNAT"));
        assert_eq!(classify_reserved_ip("100.120.2.214"), Some("CGNAT"));
        assert_eq!(classify_reserved_ip("100.127.255.255"), Some("CGNAT"));
        // 100.128.x is OUTSIDE 100.64/10 → public, not CGNAT.
        assert_eq!(classify_reserved_ip("100.128.0.1"), None);
        // Link-local.
        assert_eq!(classify_reserved_ip("169.254.1.1"), Some("link-local"));
        assert_eq!(classify_reserved_ip("fe80::1"), Some("link-local"));
        // IPv6 ULA.
        assert_eq!(classify_reserved_ip("fc00::1"), Some("private/ULA"));
        assert_eq!(classify_reserved_ip("fd12:3456::1"), Some("private/ULA"));
    }

    #[test]
    fn classify_reserved_ip_returns_none_for_public_and_garbage() {
        // Ordinary routable public IPs → None (genuine "(unknown)"
        // when GeoIP has no record).
        assert_eq!(classify_reserved_ip("8.8.8.8"), None);
        assert_eq!(classify_reserved_ip("83.97.108.34"), None);
        assert_eq!(classify_reserved_ip("2606:4700:4700::1111"), None);
        // Unparseable strings must never panic — just None.
        assert_eq!(classify_reserved_ip(""), None);
        assert_eq!(classify_reserved_ip("not-an-ip"), None);
        assert_eq!(classify_reserved_ip("999.999.999.999"), None);
    }

    #[test]
    fn format_msk_iso_emits_full_date_with_msk_marker() {
        // Used on the user-detail «last fetch» tile where the value
        // can be many days old; dropping the year would be ambiguous.
        let utc = chrono::Utc.with_ymd_and_hms(2026, 5, 21, 12, 0, 0).unwrap();
        assert_eq!(format_msk_iso(utc), "2026-05-21 15:00 MSK");
    }

    #[test]
    fn enrich_destination_label_inserts_hostname_for_cache_hit_with_port() {
        let mut cache = std::collections::HashMap::new();
        cache.insert("1.2.3.4".to_string(), Some("example.com".to_string()));
        // Shape parity with `snapshot_cache::aggregate_by_destination`:
        // `host:port (ip)`. Pins the assembly order — would catch any
        // future swap to `ip:port (host)` or dropped port suffix.
        assert_eq!(
            enrich_destination_label("1.2.3.4:443", &cache),
            "example.com:443 (1.2.3.4)"
        );
    }

    #[test]
    fn enrich_destination_label_inserts_hostname_for_cache_hit_portless() {
        let mut cache = std::collections::HashMap::new();
        cache.insert("1.2.3.4".to_string(), Some("example.com".to_string()));
        // Portless variant — when the original label had no `:port`,
        // the enriched form must not invent one.
        assert_eq!(
            enrich_destination_label("1.2.3.4", &cache),
            "example.com (1.2.3.4)"
        );
    }

    #[test]
    fn enrich_destination_label_passes_through_when_cache_misses() {
        let cache = std::collections::HashMap::new();
        // Untouched bare-IP label when the resolver hasn't visited
        // this IP yet — operator still sees the raw IP, not a panic
        // or a "(unknown)" sentinel.
        assert_eq!(
            enrich_destination_label("1.2.3.4:443", &cache),
            "1.2.3.4:443"
        );
    }

    #[test]
    fn enrich_destination_label_passes_through_for_negative_cache_entry() {
        let mut cache = std::collections::HashMap::new();
        cache.insert("1.2.3.4".to_string(), None);
        // Some(None) = resolver tried, got no PTR. The label stays
        // bare-IP rather than emitting `None:port (ip)`.
        assert_eq!(
            enrich_destination_label("1.2.3.4:443", &cache),
            "1.2.3.4:443"
        );
    }

    #[test]
    fn enrich_destination_label_passes_through_for_hostname_label() {
        let mut cache = std::collections::HashMap::new();
        // Even if a hostname accidentally exists in the cache (it
        // shouldn't — keys are IPs), the label is not bare-IP form
        // so extract_ip_from_label refuses and enrichment skips.
        cache.insert(
            "www.microsoft.com".to_string(),
            Some("ms.example".to_string()),
        );
        assert_eq!(
            enrich_destination_label("www.microsoft.com:443", &cache),
            "www.microsoft.com:443"
        );
    }

    // ── server#1 (PR-Server) drift-detail orphan diff ───────────────
    fn user(id: &str, uuid: &str) -> vpnctl_core::User {
        vpnctl_core::User {
            id: vpnctl_core::UserId(id.into()),
            uuid: uuid.into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn uuid_set(uuids: &[&str]) -> std::collections::BTreeSet<String> {
        uuids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn compute_orphan_uuids_flags_on_node_uuid_absent_from_inventory() {
        // Node serves alice's + a stray UUID; inventory grants only
        // alice. The stray is the orphan; alice is accounted-for.
        let alice = user("alice", "uuid-alice");
        let granted = vec![alice.clone()];
        let all = vec![alice];
        let node = uuid_set(&["uuid-alice", "uuid-stray"]);
        let orphans = compute_orphan_uuids(&node, &granted, &all);
        assert_eq!(orphans.len(), 1, "exactly one orphan expected");
        assert_eq!(orphans[0].uuid, "uuid-stray");
        assert_eq!(
            orphans[0].name, None,
            "a UUID in no known user must be unresolved"
        );
    }

    #[test]
    fn compute_orphan_uuids_names_a_revoked_user_still_on_node() {
        // bob lost his grant (not in `granted`) but is still a known
        // user AND his UUID lingers on the node → orphan, NAMED bob.
        let alice = user("alice", "uuid-alice");
        let bob = user("bob", "uuid-bob");
        let granted = vec![alice.clone()];
        let all = vec![alice, bob];
        let node = uuid_set(&["uuid-alice", "uuid-bob"]);
        let orphans = compute_orphan_uuids(&node, &granted, &all);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].uuid, "uuid-bob");
        assert_eq!(
            orphans[0].name.as_deref(),
            Some("bob"),
            "a revoked-but-known user must resolve to their id"
        );
    }

    #[test]
    fn compute_orphan_uuids_empty_when_node_matches_inventory() {
        let alice = user("alice", "uuid-alice");
        let granted = vec![alice.clone()];
        let all = vec![alice];
        let node = uuid_set(&["uuid-alice"]);
        assert!(
            compute_orphan_uuids(&node, &granted, &all).is_empty(),
            "no orphan when every on-node UUID is granted"
        );
    }

    #[test]
    fn compute_orphan_uuids_ignores_inventory_uuid_not_on_node() {
        // A granted user whose UUID is NOT on the node is NOT an orphan
        // (orphan = on-node-not-in-inventory, the one-directional diff).
        let alice = user("alice", "uuid-alice");
        let granted = vec![alice.clone()];
        let all = vec![alice];
        let node = uuid_set(&[]); // node serves nothing
        assert!(
            compute_orphan_uuids(&node, &granted, &all).is_empty(),
            "inventory-only UUIDs must never count as orphans"
        );
    }
}
