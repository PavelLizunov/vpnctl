# Codebase Inventory & Project Map

<!-- Generated deterministically by scripts/project-map.py. Do not edit directly. -->

## Overview

- **Workspace Crates:** 10
- **Tracked Rust Files:** 264 (196 prod / 68 test)
- **Total Rust LOC:** 114,783 (72,567 prod / 42,216 test)
- **Database Migrations:** 48
- **`daemon/src/app.rs` `.route(...)` Registrations:** 0

## Workspace Crates & Targets

| Crate | Path | Version | Targets | Prod LOC (Files) | Test LOC (Files) | Total LOC |
|---|---|---|---|---|---|---|
| `vpnctl` | `cli` | 0.9.0 | bin | 5,024 (19) | 0 (0) | **5,024** |
| `vpnctl-boosty-bridge` | `crates/boosty-bridge` | 0.9.0 | lib, 2 tests | 1,339 (6) | 870 (2) | **2,209** |
| `vpnctl-core` | `crates/core` | 0.9.0 | lib | 1,836 (5) | 0 (0) | **1,836** |
| `vpnctl-crypto` | `crates/crypto` | 0.9.0 | lib | 426 (1) | 0 (0) | **426** |
| `vpnctl-host-fingerprint` | `crates/host-fingerprint` | 0.9.0 | lib, 2 tests | 331 (1) | 400 (2) | **731** |
| `vpnctl-inventory` | `crates/inventory` | 0.9.0 | lib, 30 tests | 5,375 (20) | 11,488 (30) | **16,863** |
| `vpnctl-kernels` | `crates/kernels` | 0.9.0 | lib, 2 tests | 6,620 (7) | 605 (2) | **7,225** |
| `vpnctl-protocols` | `crates/protocols` | 0.9.0 | lib, 11 tests | 5,620 (14) | 4,186 (11) | **9,806** |
| `vpnctl-ssh` | `crates/ssh` | 0.9.0 | lib, 3 tests | 520 (3) | 558 (3) | **1,078** |
| `vpnctld` | `daemon` | 0.9.0 | lib, bin, 7 tests | 45,476 (120) | 24,109 (18) | **69,585** |
| **Total** | | | | **72,567 (196)** | **42,216 (68)** | **114,783** |

## Largest Rust Modules (Top 25)

| File | LOC | Crate | Role |
|---|---|---|---|
| `daemon/tests/admin_smoke/user_detail.rs` | 3,445 | `daemon` | Test |
| `daemon/tests/admin_smoke/server_detail.rs` | 3,224 | `daemon` | Test |
| `daemon/tests/admin_smoke/grants.rs` | 2,677 | `daemon` | Test |
| `daemon/tests/admin_smoke/shell_nav.rs` | 2,409 | `daemon` | Test |
| `daemon/tests/vpn_router_endpoint.rs` | 1,969 | `daemon` | Test |
| `daemon/src/handlers/admin/user_detail/render.rs` | 1,954 | `daemon` | Prod |
| `daemon/tests/admin_smoke/alerts_health.rs` | 1,680 | `daemon` | Test |
| `daemon/tests/admin_smoke/settings_integrations.rs` | 1,576 | `daemon` | Test |
| `crates/inventory/tests/spec_vpn_stats.rs` | 1,544 | `crates/inventory` | Test |
| `daemon/tests/sub_endpoint.rs` | 1,409 | `daemon` | Test |
| `crates/kernels/src/sing_box.rs` | 1,403 | `crates/kernels` | Prod |
| `crates/kernels/src/caddy.rs` | 1,401 | `crates/kernels` | Prod |
| `crates/core/src/lib.rs` | 1,272 | `crates/core` | Prod |
| `daemon/src/health_monitor/tests.rs` | 1,227 | `daemon` | Prod |
| `daemon/src/handlers/admin/legacy/server_detail/config.rs` | 1,225 | `daemon` | Prod |
| `daemon/tests/admin_smoke/dashboard.rs` | 1,179 | `daemon` | Test |
| `daemon/src/alert_text.rs` | 1,163 | `daemon` | Prod |
| `crates/protocols/src/wireguard.rs` | 1,162 | `crates/protocols` | Prod |
| `crates/inventory/src/sqlite/tests.rs` | 1,129 | `crates/inventory` | Prod |
| `crates/kernels/src/dns_tunnel.rs` | 1,116 | `crates/kernels` | Prod |
| `crates/kernels/src/wgturn.rs` | 1,096 | `crates/kernels` | Prod |
| `daemon/src/handlers/admin/legacy/server_detail/render.rs` | 1,058 | `daemon` | Prod |
| `crates/inventory/tests/spec_sub_access.rs` | 1,050 | `crates/inventory` | Test |
| `daemon/tests/admin_smoke/users.rs` | 991 | `daemon` | Test |
| `crates/kernels/src/amnezia_wg.rs` | 954 | `crates/kernels` | Prod |

## Database Migrations (48)

| Version | Migration Name | File | Lines |
|---|---|---|---|
| `0001` | init | `crates/inventory/migrations/0001_init.sql` | 64 |
| `0002` | sub token | `crates/inventory/migrations/0002_sub_token.sql` | 17 |
| `0003` | sub access log | `crates/inventory/migrations/0003_sub_access_log.sql` | 46 |
| `0004` | sub access keep after user delete | `crates/inventory/migrations/0004_sub_access_keep_after_user_delete.sql` | 54 |
| `0005` | sub rate bans | `crates/inventory/migrations/0005_sub_rate_bans.sql` | 44 |
| `0006` | vpn connection stats | `crates/inventory/migrations/0006_vpn_connection_stats.sql` | 62 |
| `0007` | node health | `crates/inventory/migrations/0007_node_health.sql` | 67 |
| `0008` | users wireguard private | `crates/inventory/migrations/0008_users_wireguard_private.sql` | 29 |
| `0009` | server kernels | `crates/inventory/migrations/0009_server_kernels.sql` | 49 |
| `0010` | user traffic limits | `crates/inventory/migrations/0010_user_traffic_limits.sql` | 43 |
| `0011` | admin alerts | `crates/inventory/migrations/0011_admin_alerts.sql` | 108 |
| `0012` | admin alerts unacked index | `crates/inventory/migrations/0012_admin_alerts_unacked_index.sql` | 19 |
| `0013` | admin alerts unique unacked | `crates/inventory/migrations/0013_admin_alerts_unique_unacked.sql` | 60 |
| `0014` | notification settings | `crates/inventory/migrations/0014_notification_settings.sql` | 48 |
| `0015` | notification proxy via server | `crates/inventory/migrations/0015_notification_proxy_via_server.sql` | 37 |
| `0016` | grants per server uuid | `crates/inventory/migrations/0016_grants_per_server_uuid.sql` | 64 |
| `0017` | users vpn router device id | `crates/inventory/migrations/0017_users_vpn_router_device_id.sql` | 31 |
| `0018` | protocol visibility | `crates/inventory/migrations/0018_protocol_visibility.sql` | 72 |
| `0019` | sub access log richer metadata | `crates/inventory/migrations/0019_sub_access_log_richer_metadata.sql` | 47 |
| `0020` | sub access log tls fingerprint | `crates/inventory/migrations/0020_sub_access_log_tls_fingerprint.sql` | 42 |
| `0021` | sub access log vpn egress | `crates/inventory/migrations/0021_sub_access_log_vpn_egress.sql` | 84 |
| `0022` | vpn user daily | `crates/inventory/migrations/0022_vpn_user_daily.sql` | 72 |
| `0023` | dns ptr cache | `crates/inventory/migrations/0023_dns_ptr_cache.sql` | 45 |
| `0024` | vpn user destinations | `crates/inventory/migrations/0024_vpn_user_destinations.sql` | 54 |
| `0025` | vpn user sessions | `crates/inventory/migrations/0025_vpn_user_sessions.sql` | 50 |
| `0026` | users disabled | `crates/inventory/migrations/0026_users_disabled.sql` | 31 |
| `0027` | display settings | `crates/inventory/migrations/0027_display_settings.sql` | 30 |
| `0028` | servers reserved ports | `crates/inventory/migrations/0028_servers_reserved_ports.sql` | 28 |
| `0029` | servers display name | `crates/inventory/migrations/0029_servers_display_name.sql` | 15 |
| `0030` | servers auto suppress | `crates/inventory/migrations/0030_servers_auto_suppress.sql` | 22 |
| `0031` | servers udp pair enabled | `crates/inventory/migrations/0031_servers_udp_pair_enabled.sql` | 9 |
| `0032` | vpn connection stats ts index | `crates/inventory/migrations/0032_vpn_connection_stats_ts_index.sql` | 25 |
| `0033` | node health kernel versions | `crates/inventory/migrations/0033_node_health_kernel_versions.sql` | 56 |
| `0034` | vpn user source ips | `crates/inventory/migrations/0034_vpn_user_source_ips.sql` | 58 |
| `0035` | vpn user ip concurrency | `crates/inventory/migrations/0035_vpn_user_ip_concurrency.sql` | 39 |
| `0036` | notification language | `crates/inventory/migrations/0036_notification_language.sql` | 8 |
| `0037` | admin alerts telegram message id | `crates/inventory/migrations/0037_admin_alerts_telegram_message_id.sql` | 6 |
| `0038` | node health nic bytes | `crates/inventory/migrations/0038_node_health_nic_bytes.sql` | 13 |
| `0039` | grants granted at | `crates/inventory/migrations/0039_grants_granted_at.sql` | 5 |
| `0040` | boosty bridge | `crates/inventory/migrations/0040_boosty_bridge.sql` | 60 |
| `0041` | boosty multi user | `crates/inventory/migrations/0041_boosty_multi_user.sql` | 22 |
| `0042` | node health nrestarts | `crates/inventory/migrations/0042_node_health_nrestarts.sql` | 12 |
| `0043` | vpn server hourly | `crates/inventory/migrations/0043_vpn_server_hourly.sql` | 52 |
| `0044` | boosty automation | `crates/inventory/migrations/0044_boosty_automation.sql` | 11 |
| `0045` | reset sharing network peaks | `crates/inventory/migrations/0045_reset_sharing_network_peaks.sql` | 5 |
| `0046` | server resolved addresses | `crates/inventory/migrations/0046_server_resolved_addresses.sql` | 23 |
| `0047` | boosty sync lease | `crates/inventory/migrations/0047_boosty_sync_lease.sql` | 2 |
| `0048` | server quality samples | `crates/inventory/migrations/0048_server_quality_samples.sql` | 30 |

## `daemon/src/app.rs` `.route(...)` Registrations (0)

| Method | Path | Handler |
|---|---|---|
