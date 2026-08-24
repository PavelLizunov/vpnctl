# Codebase Inventory & Project Map

<!-- Generated deterministically by scripts/project-map.py. Do not edit directly. -->

## Overview

- **Workspace Crates:** 10
- **Tracked Rust Files:** 328 (231 prod / 97 test)
- **Total Rust LOC:** 122,095 (79,431 prod / 42,664 test)
- **Database Migrations:** 51
- **`daemon/src/app/routes.rs` `.route(...)` Registrations:** 117

## Workspace Crates & Targets

| Crate | Path | Version | Targets | Prod LOC (Files) | Test LOC (Files) | Total LOC |
|---|---|---|---|---|---|---|
| `vpnctl` | `cli` | 0.9.0 | bin | 5,019 (20) | 0 (0) | **5,019** |
| `vpnctl-boosty-bridge` | `crates/boosty-bridge` | 0.9.0 | lib, 2 tests | 1,339 (6) | 870 (2) | **2,209** |
| `vpnctl-core` | `crates/core` | 0.9.0 | lib | 1,830 (5) | 0 (0) | **1,830** |
| `vpnctl-crypto` | `crates/crypto` | 0.9.0 | lib | 426 (1) | 0 (0) | **426** |
| `vpnctl-host-fingerprint` | `crates/host-fingerprint` | 0.9.0 | lib, 2 tests | 376 (1) | 526 (2) | **902** |
| `vpnctl-inventory` | `crates/inventory` | 0.9.0 | lib, 32 tests | 13,038 (46) | 13,425 (36) | **26,463** |
| `vpnctl-kernels` | `crates/kernels` | 0.9.0 | lib, 1 test | 6,183 (8) | 113 (1) | **6,296** |
| `vpnctl-protocols` | `crates/protocols` | 0.9.0 | lib, 10 tests | 4,114 (17) | 3,773 (10) | **7,887** |
| `vpnctl-ssh` | `crates/ssh` | 0.9.0 | lib, 3 tests | 1,018 (3) | 558 (3) | **1,576** |
| `vpnctld` | `daemon` | 0.9.0 | lib, bin, 7 tests | 46,088 (124) | 23,399 (43) | **69,487** |
| **Total** | | | | **79,431 (231)** | **42,664 (97)** | **122,095** |

## Largest Rust Modules (Top 25)

| File | LOC | Crate | Role |
|---|---|---|---|
| `crates/kernels/src/sing_box.rs` | 1,968 | `crates/kernels` | Prod |
| `daemon/src/handlers/admin/user_detail/render.rs` | 1,785 | `daemon` | Prod |
| `daemon/tests/admin_smoke/alerts_health.rs` | 1,680 | `daemon` | Test |
| `daemon/src/health_monitor/tests.rs` | 1,629 | `daemon` | Prod |
| `daemon/tests/admin_smoke/settings_integrations.rs` | 1,576 | `daemon` | Test |
| `crates/kernels/src/caddy/tests.rs` | 1,519 | `crates/kernels` | Prod |
| `crates/inventory/src/sqlite/tests.rs` | 1,374 | `crates/inventory` | Prod |
| `daemon/tests/admin_smoke/grants/protocol_overrides.rs` | 1,306 | `daemon` | Test |
| `crates/core/src/lib.rs` | 1,266 | `crates/core` | Prod |
| `daemon/tests/admin_smoke/dashboard.rs` | 1,179 | `daemon` | Test |
| `daemon/src/handlers/admin/legacy/server_detail/config.rs` | 1,177 | `daemon` | Prod |
| `daemon/src/handlers/admin/legacy/server_detail/render.rs` | 1,056 | `daemon` | Prod |
| `crates/inventory/tests/spec_sub_access.rs` | 1,050 | `crates/inventory` | Test |
| `crates/inventory/tests/spec_node_health.rs` | 1,033 | `crates/inventory` | Test |
| `daemon/tests/admin_smoke/users.rs` | 991 | `daemon` | Test |
| `daemon/tests/admin_smoke/user_detail/traffic_activity.rs` | 965 | `daemon` | Test |
| `crates/kernels/src/amnezia_wg.rs` | 954 | `crates/kernels` | Prod |
| `daemon/src/handlers/admin/legacy/deploy_sse.rs` | 945 | `daemon` | Prod |
| `daemon/src/node_probe.rs` | 944 | `daemon` | Prod |
| `daemon/tests/admin_smoke/user_detail/subscription_share_links.rs` | 929 | `daemon` | Test |
| `crates/ssh/src/russh_transport.rs` | 918 | `crates/ssh` | Prod |
| `daemon/src/ssh_subprocess.rs` | 890 | `daemon` | Prod |
| `daemon/src/handlers/admin/user_actions.rs` | 883 | `daemon` | Prod |
| `daemon/tests/admin_smoke/server_detail/drift_traffic.rs` | 877 | `daemon` | Test |
| `daemon/tests/admin_smoke/servers.rs` | 876 | `daemon` | Test |

## Database Migrations (51)

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
| `0049` | remove wgturn | `crates/inventory/migrations/0049_remove_wgturn.sql` | 45 |
| `0050` | remove dns tunnel | `crates/inventory/migrations/0050_remove_dns_tunnel.sql` | 46 |
| `0051` | node health sample id | `crates/inventory/migrations/0051_node_health_sample_id.sql` | 79 |

## `daemon/src/app/routes.rs` `.route(...)` Registrations (117)

| Method | Path | Handler |
|---|---|---|
| `GET` | `/admin` | `admin::dashboard` |
| `GET` | `/admin/` | `admin::dashboard` |
| `GET` | `/admin/activity` | `admin::dashboard_activity` |
| `GET` | `/admin/alerts` | `admin::alerts` |
| `GET` | `/admin/alerts/` | `admin::alerts` |
| `POST` | `/admin/alerts/ack-all` | `admin::alert_ack_all` |
| `POST` | `/admin/alerts/ack-family/{prefix}` | `admin::alert_ack_family` |
| `POST` | `/admin/alerts/{id}/ack` | `admin::alert_ack` |
| `GET` | `/admin/audit` | `admin::audit` |
| `GET` | `/admin/audit.csv` | `admin::audit_csv` |
| `GET` | `/admin/audit/` | `admin::audit` |
| `GET` | `/admin/backup/download/{name}` | `admin::backup_download` |
| `POST` | `/admin/backup/self-test` | `admin::backup_self_test` |
| `POST` | `/admin/backup/snapshot` | `admin::backup_snapshot_now` |
| `GET` | `/admin/boosty` | `admin::boosty_page` |
| `POST` | `/admin/boosty/disable/{user}` | `admin::boosty_disable` |
| `POST` | `/admin/boosty/link` | `admin::boosty_link` |
| `POST` | `/admin/boosty/settings` | `admin::boosty_settings_save` |
| `POST` | `/admin/boosty/sync` | `admin::boosty_sync_now` |
| `POST` | `/admin/boosty/unlink/{user}` | `admin::boosty_unlink` |
| `POST` | `/admin/logout` | `admin::logout` |
| `GET` | `/admin/monitoring` | `admin::monitoring` |
| `GET` | `/admin/monitoring/` | `admin::monitoring` |
| `POST` | `/admin/monitoring/probe-all` | `admin::monitoring_probe_all` |
| `GET` | `/admin/overview` | `admin::dashboard` |
| `GET` | `/admin/search` | `admin::search` |
| `GET` | `/admin/servers` | `admin::servers` |
| `GET` | `/admin/servers/` | `admin::servers` |
| `GET` | `/admin/servers/deploy-all/sse` | `admin::servers_deploy_all_sse` |
| `GET` | `/admin/servers/new` | `admin::wizard_new` |
| `POST` | `/admin/servers/new` | `admin::wizard_new_submit` |
| `GET` | `/admin/servers/new/` | `admin::wizard_new` |
| `POST` | `/admin/servers/new/` | `admin::wizard_new_submit` |
| `GET` | `/admin/servers/new/step-2` | `admin::wizard_step2_stub` |
| `GET` | `/admin/servers/new/step-2/` | `admin::wizard_step2_stub` |
| `GET` | `/admin/servers/new/step-2/sse` | `admin::wizard_step2_sse` |
| `POST` | `/admin/servers/quick-add` | `admin::server_quick_add` |
| `GET` | `/admin/servers/update-kernels-all/sse` | `admin::servers_update_kernels_all_sse` |
| `GET` | `/admin/servers/{id}` | `admin::server_detail` |
| `GET` | `/admin/servers/{id}/` | `admin::server_detail` |
| `GET` | `/admin/servers/{id}/activity` | `admin::server_detail_activity` |
| `POST` | `/admin/servers/{id}/auto-suppress` | `admin::server_set_auto_suppress` |
| `POST` | `/admin/servers/{id}/delete` | `admin::server_delete` |
| `GET` | `/admin/servers/{id}/delete-confirm` | `admin::server_delete_confirm` |
| `POST` | `/admin/servers/{id}/deploy` | `admin::server_deploy` |
| `GET` | `/admin/servers/{id}/deploy/sse` | `admin::server_deploy_sse` |
| `POST` | `/admin/servers/{id}/display-name` | `admin::server_set_display_name` |
| `GET` | `/admin/servers/{id}/grants` | `admin::server_detail_grants_tab` |
| `POST` | `/admin/servers/{id}/grants` | `admin::server_grant_user_form` |
| `POST` | `/admin/servers/{id}/grants/_grant-all` | `admin::server_grant_all_users` |
| `POST` | `/admin/servers/{id}/grants/_revoke-all` | `admin::server_revoke_all_users` |
| `POST` | `/admin/servers/{id}/kernels/{kernel}/disable` | `admin::server_disable_kernel` |
| `POST` | `/admin/servers/{id}/kernels/{kernel}/enable` | `admin::server_enable_kernel` |
| `POST` | `/admin/servers/{id}/naive-config` | `admin::server_set_naive_config` |
| `GET` | `/admin/servers/{id}/protocols` | `admin::server_detail_protocols_tab` |
| `POST` | `/admin/servers/{id}/protocols/{proto}/disable` | `admin::server_disable_protocol` |
| `POST` | `/admin/servers/{id}/protocols/{proto}/enable` | `admin::server_enable_protocol` |
| `POST` | `/admin/servers/{id}/push-deploy-key` | `admin::server_push_deploy_key` |
| `POST` | `/admin/servers/{id}/reality-config` | `admin::server_set_reality_config` |
| `POST` | `/admin/servers/{id}/reserved-ports` | `admin::server_set_reserved_ports` |
| `POST` | `/admin/servers/{id}/set-fingerprint` | `admin::server_set_fingerprint` |
| `GET` | `/admin/servers/{id}/setup` | `admin::server_detail_setup` |
| `GET` | `/admin/servers/{id}/status` | `admin::server_detail` |
| `POST` | `/admin/servers/{id}/udp-pair` | `admin::server_set_udp_pair` |
| `GET` | `/admin/servers/{id}/update-kernels/sse` | `admin::server_update_kernels_sse` |
| `POST` | `/admin/servers/{id}/vlessws-config` | `admin::server_set_vlessws_config` |
| `POST` | `/admin/servers/{sid}/grants/{uid}` | `admin::server_grant_user` |
| `POST` | `/admin/servers/{sid}/grants/{uid}/revoke` | `admin::server_revoke_user` |
| `POST` | `/admin/servers/{sid}/protocols/{pid}/hide` | `admin::server_protocol_hide` |
| `POST` | `/admin/servers/{sid}/protocols/{pid}/unhide` | `admin::server_protocol_unhide` |
| `GET` | `/admin/settings` | `admin::settings` |
| `GET` | `/admin/settings/` | `admin::settings` |
| `GET` | `/admin/settings/appearance` | `admin::settings` |
| `GET` | `/admin/settings/backups` | `admin::settings_backups` |
| `POST` | `/admin/settings/digest-now` | `admin::settings_digest_now` |
| `GET` | `/admin/settings/geoip/update-now` | `admin::settings_geoip_update_now_sse` |
| `POST` | `/admin/settings/notification-language` | `admin::settings_notification_language` |
| `GET` | `/admin/settings/notifications` | `admin::settings_notifications` |
| `GET` | `/admin/settings/system` | `admin::settings_system` |
| `POST` | `/admin/settings/telegram` | `admin::settings_telegram` |
| `POST` | `/admin/settings/telegram/test` | `admin::settings_telegram_test` |
| `POST` | `/admin/settings/timezone` | `admin::settings_timezone_set` |
| `GET` | `/admin/sharing` | `admin::sharing` |
| `GET` | `/admin/sharing/` | `admin::sharing` |
| `POST` | `/admin/tweak/{kind}` | `admin::set_tweak` |
| `GET` | `/admin/users` | `admin::users` |
| `POST` | `/admin/users` | `admin::user_create` |
| `GET` | `/admin/users/` | `admin::users` |
| `POST` | `/admin/users/` | `admin::user_create` |
| `GET` | `/admin/users/{id}` | `admin::user_detail` |
| `GET` | `/admin/users/{id}/` | `admin::user_detail` |
| `GET` | `/admin/users/{id}/access` | `admin::user_detail_access` |
| `GET` | `/admin/users/{id}/access.csv` | `admin::user_access_csv` |
| `GET` | `/admin/users/{id}/activity` | `admin::user_detail_activity` |
| `POST` | `/admin/users/{id}/delete` | `admin::user_delete` |
| `GET` | `/admin/users/{id}/delete-confirm` | `admin::user_delete_confirm` |
| `GET` | `/admin/users/{id}/delivery` | `admin::user_detail_delivery` |
| `GET` | `/admin/users/{id}/deploy-pending/sse` | `admin::user_deploy_pending_sse` |
| `POST` | `/admin/users/{id}/disable` | `admin::user_set_disabled_true` |
| `POST` | `/admin/users/{id}/enable` | `admin::user_set_disabled_false` |
| `POST` | `/admin/users/{id}/grants/{server_id}` | `admin::user_grant_server` |
| `POST` | `/admin/users/{id}/grants/{server_id}/revoke` | `admin::user_revoke_server` |
| `GET` | `/admin/users/{id}/overview` | `admin::user_detail` |
| `POST` | `/admin/users/{id}/sub-token/regenerate` | `admin::user_regen_sub_token` |
| `GET` | `/admin/users/{id}/traffic` | `admin::user_detail_traffic` |
| `POST` | `/admin/users/{id}/traffic-limit` | `admin::user_set_traffic_limit` |
| `POST` | `/admin/users/{id}/tuic-password/mint` | `admin::user_mint_tuic_password` |
| `GET` | `/admin/users/{id}/wireguard/conf/{server_id}` | `admin::user_wireguard_conf_download` |
| `POST` | `/admin/users/{id}/wireguard/regenerate` | `admin::user_regen_wireguard` |
| `POST` | `/admin/users/{uid}/grants/{sid}/protocols/{pid}/disable` | `admin::grant_protocol_disable` |
| `POST` | `/admin/users/{uid}/grants/{sid}/protocols/{pid}/enable` | `admin::grant_protocol_enable` |
| `GET` | `/api/v1/app/config` | `handlers::vpn_router::get_config_root_catchall` |
| `GET` | `/api/v1/app/config/` | `handlers::vpn_router::get_config_root_catchall` |
| `GET` | `/api/v1/app/config/{*tail}` | `handlers::vpn_router::get_config` |
| `GET` | `/api/v1/health` | `handlers::health::get` |
| `GET` | `/api/v1/stats/sub-access` | `handlers::stats::sub_access` |
| `GET` | `/sub/{token}` | `handlers::sub::get` |
