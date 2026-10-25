mod dashboard;
mod deploy_sse;
mod kernel_update_sse;
mod server_detail;
mod settings;
mod settings_geoip_sse;
mod shell;
mod sse_ticket;
mod user_sections;
mod wizard_ui;

pub(crate) use self::dashboard::*;
pub(crate) use self::deploy_sse::*;
pub(crate) use self::kernel_update_sse::*;
pub(crate) use self::server_detail::*;
pub(crate) use self::settings::*;
pub(crate) use self::settings_geoip_sse::*;
pub(crate) use self::sse_ticket::sse_ticket;
pub(crate) use self::user_sections::*;
pub(crate) use self::wizard_ui::*;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod helper_tests {
    use super::dashboard::dashboard_heavy_users;
    use super::server_detail::compute_orphan_uuids;
    use super::user_sections::{VpnSparklineWindow, classify_reserved_ip};
    use crate::handlers::admin::helpers::{
        enrich_destination_label, extract_ip_from_label, format_msk, format_msk_iso, humanize_bytes,
    };
    use chrono::TimeZone;

    #[test]
    fn format_msk_shifts_utc_by_plus_three_hours_and_marks_timezone() {
        let utc = chrono::Utc.with_ymd_and_hms(2026, 5, 21, 12, 0, 0).unwrap();
        assert_eq!(format_msk(utc), "05-21 15:00 MSK");
    }

    #[test]
    fn format_msk_wraps_across_midnight_when_adding_offset() {
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
        assert!(html.contains("Upload"), "missing Upload header: {html}");
        assert!(html.contains("Download"), "missing Download header");
        assert!(html.contains("Total"), "missing Total header");
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
        assert!(html.contains("/admin/users/alice"), "missing user link");
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_hostname_form() {
        assert!(extract_ip_from_label("www.microsoft.com:443").is_none());
        assert!(extract_ip_from_label("api-v2.example.io:8443").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_already_enriched_label() {
        assert!(extract_ip_from_label("example.com:443 (1.2.3.4)").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_ipv6_form() {
        assert!(extract_ip_from_label("2001:db8::1:8080").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_malformed_input() {
        assert!(extract_ip_from_label("no-colon-at-all").is_none());
        assert!(extract_ip_from_label(":443").is_none());
        assert!(extract_ip_from_label("1.2.3.4:").is_none());
        assert!(extract_ip_from_label("1.2.3.4:notaport").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_ip_for_portless_bare_ipv4() {
        assert_eq!(extract_ip_from_label("1.2.3.4"), Some("1.2.3.4"));
        assert_eq!(extract_ip_from_label("10.0.0.1"), Some("10.0.0.1"));
    }

    #[test]
    fn classify_reserved_ip_labels_private_and_special_ranges() {
        assert_eq!(classify_reserved_ip("192.168.0.207"), Some("private/LAN"));
        assert_eq!(classify_reserved_ip("10.1.2.3"), Some("private/LAN"));
        assert_eq!(classify_reserved_ip("172.16.5.5"), Some("private/LAN"));
        assert_eq!(classify_reserved_ip("127.0.0.1"), Some("loopback"));
        assert_eq!(classify_reserved_ip("::1"), Some("loopback"));
        assert_eq!(classify_reserved_ip("100.64.0.1"), Some("CGNAT"));
        assert_eq!(classify_reserved_ip("100.120.2.214"), Some("CGNAT"));
        assert_eq!(classify_reserved_ip("100.127.255.255"), Some("CGNAT"));
        assert_eq!(classify_reserved_ip("100.128.0.1"), None);
        assert_eq!(classify_reserved_ip("169.254.1.1"), Some("link-local"));
        assert_eq!(classify_reserved_ip("fe80::1"), Some("link-local"));
        assert_eq!(classify_reserved_ip("fc00::1"), Some("private/ULA"));
        assert_eq!(classify_reserved_ip("fd12:3456::1"), Some("private/ULA"));
    }

    #[test]
    fn classify_reserved_ip_returns_none_for_public_and_garbage() {
        assert_eq!(classify_reserved_ip("8.8.8.8"), None);
        assert_eq!(classify_reserved_ip("83.97.108.34"), None);
        assert_eq!(classify_reserved_ip("2606:4700:4700::1111"), None);
        assert_eq!(classify_reserved_ip(""), None);
        assert_eq!(classify_reserved_ip("not-an-ip"), None);
        assert_eq!(classify_reserved_ip("999.999.999.999"), None);
    }

    #[test]
    fn format_msk_iso_emits_full_date_with_msk_marker() {
        let utc = chrono::Utc.with_ymd_and_hms(2026, 5, 21, 12, 0, 0).unwrap();
        assert_eq!(format_msk_iso(utc), "2026-05-21 15:00 MSK");
    }

    #[test]
    fn enrich_destination_label_inserts_hostname_for_cache_hit_with_port() {
        let mut cache = std::collections::HashMap::new();
        cache.insert("1.2.3.4".to_string(), Some("example.com".to_string()));
        assert_eq!(
            enrich_destination_label("1.2.3.4:443", &cache),
            "example.com:443 (1.2.3.4)"
        );
    }

    #[test]
    fn enrich_destination_label_inserts_hostname_for_cache_hit_portless() {
        let mut cache = std::collections::HashMap::new();
        cache.insert("1.2.3.4".to_string(), Some("example.com".to_string()));
        assert_eq!(
            enrich_destination_label("1.2.3.4", &cache),
            "example.com (1.2.3.4)"
        );
    }

    #[test]
    fn enrich_destination_label_passes_through_when_cache_misses() {
        let cache = std::collections::HashMap::new();
        assert_eq!(
            enrich_destination_label("1.2.3.4:443", &cache),
            "1.2.3.4:443"
        );
    }

    #[test]
    fn enrich_destination_label_passes_through_for_negative_cache_entry() {
        let mut cache = std::collections::HashMap::new();
        cache.insert("1.2.3.4".to_string(), None);
        assert_eq!(
            enrich_destination_label("1.2.3.4:443", &cache),
            "1.2.3.4:443"
        );
    }

    #[test]
    fn enrich_destination_label_passes_through_for_hostname_label() {
        let mut cache = std::collections::HashMap::new();
        cache.insert(
            "www.microsoft.com".to_string(),
            Some("ms.example".to_string()),
        );
        assert_eq!(
            enrich_destination_label("www.microsoft.com:443", &cache),
            "www.microsoft.com:443"
        );
    }

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
        let alice = user("alice", "uuid-alice");
        let granted = vec![alice.clone()];
        let all = vec![alice];
        let node = uuid_set(&[]);
        assert!(
            compute_orphan_uuids(&node, &granted, &all).is_empty(),
            "inventory-only UUIDs must never count as orphans"
        );
    }
}
