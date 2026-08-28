use std::collections::{BTreeSet, HashMap, HashSet};

use axum::http::HeaderMap;
use axum::response::Response;
use maud::{Markup, html};

use super::activity::*;
use super::config::*;
use super::drift::*;
use super::telemetry::*;
use super::types::*;
use crate::AppState;
use crate::handlers::admin::helpers::ordered_kernel_ids;
use crate::handlers::admin::helpers::{
    format_msk_iso, humanize_bytes, internal_error, not_found, render_page, theme_accent_lang,
};
use crate::handlers::admin::legacy::dashboard::{
    humanize_age, kernel_floor_rollup, server_detail_assurance_section,
    server_detail_kernel_inventory_section, server_detail_quality_section,
};
use crate::handlers::admin::legacy::user_sections::pick_vpn_sparkline_window;
use crate::handlers::admin::servers::fp_short;
use crate::http_util::path_segment_encode;

pub(super) async fn server_detail_render(
    headers: HeaderMap,
    state: AppState,
    server_id_str: String,
    query: ServerDetailQuery,
    tab: ServerTab,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(not_found(&format!("no such server '{server_id_str}'")));
        }
        Err(e) => return Err(internal_error(anyhow::Error::new(e))),
    };

    let users = state
        .inv
        .users_for_server(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let user_count = users.len();
    // Pavel iter B: centralised grants — also load the full user list
    // so the operator can grant access to non-granted users without
    // navigating to each user's page.
    let all_users = state
        .inv
        .list_users()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let granted_user_ids: HashSet<vpnctl_core::UserId> =
        users.iter().map(|u| u.id.clone()).collect();

    let latest = state
        .inv
        .latest_node_health(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Server-side pending-deploy flag (audit 2026-06-10 follow-up):
    // «grant membership changed since the last deploy». Crucially this
    // covers the REVOKE case the per-user banner can't — the revoked
    // server leaves the user's granted list, so THIS page is the only
    // surface that can warn that the node still runs the revoked UUID.
    // Best-effort: a detector error renders no banner, not a 500.
    let pending_deploy = state.inv.server_pending_deploy(&sid).await.unwrap_or(false);

    // Design v2 3e — is the clash-api poller currently holding a LIVE
    // snapshot for this node (checklist row «clash api reachable»).
    // `get_live`: a stale snapshot (polling stopped) must read as
    // NOT reachable, not keep a green «reachable» row from a frozen tick.
    let clash_ok = state.snapshot_cache.get_live(&sid).is_some();

    // Design v2 3d — Grants-tab-only data: grant dates (migration
    // 0039), WHICH granted users still await a deploy, per-user live
    // conns on THIS node (clash snapshot), and per-user 24h traffic.
    let (grant_dates, pending_users, grants_presence, grants_traffic) = if tab == ServerTab::Grants
    {
        let dates: HashMap<vpnctl_core::UserId, Option<chrono::DateTime<chrono::Utc>>> = state
            .inv
            .grant_dates_for_server(&sid)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        let pending: HashSet<vpnctl_core::UserId> = state
            .inv
            .users_pending_deploy_for_server(&sid)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut presence: HashMap<String, u32> = HashMap::new();
        // `get_live`: per-user live conns on this node must drop out once
        // the snapshot goes stale (polling stopped).
        if let Some(snap) = state.snapshot_cache.get_live(&sid) {
            for c in &snap.snapshot.connections {
                if let Some(uid) = c.metadata.user.as_deref() {
                    *presence.entry(uid.to_string()).or_default() += 1;
                }
            }
        }
        let traffic: HashMap<vpnctl_core::UserId, u64> = state
            .inv
            .top_users_by_traffic_for_server(&sid, 24, 1000)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        (dates, pending, presence, traffic)
    } else {
        Default::default()
    };

    // Phase H+ — rolling uptime windows for the per-server SLO chip
    // section. Three independent SQL aggregates (24h / 7d / 30d) —
    // each is one indexed scan against `(server_id, ts)`. Failure
    // → render an empty-state block, not 500: the rest of the page
    // is still valuable when uptime is the broken part. Bonus: the
    // 30d query is the only one whose denominator might be empty
    // for a new server, which `UptimeStat.uptime_pct: Option<u8>`
    // already encodes («None = no data» vs «Some(0) = was down»).
    let uptime_24h = state.inv.uptime_for_server(&sid, 24).await.ok();
    let uptime_7d = state.inv.uptime_for_server(&sid, 24 * 7).await.ok();
    let uptime_30d = state.inv.uptime_for_server(&sid, 24 * 30).await.ok();
    let quality_24h = state
        .inv
        .service_quality_for_server(&sid, 24, vpnctl_inventory::QUALITY_MIN_SAMPLES)
        .await
        .ok();
    let quality_7d = state
        .inv
        .service_quality_for_server(&sid, 24 * 7, vpnctl_inventory::QUALITY_MIN_SAMPLES)
        .await
        .ok();
    let quality_history = state
        .inv
        .service_quality_samples_for_server(&sid, 24)
        .await
        .unwrap_or_default();
    let assurance_rows = state
        .inv
        .latest_protocol_assurance_for_server(&sid)
        .await
        .unwrap_or_default();

    // A3 (audit 2026-05-22, shipped 2026-05-23) — 24h resource-trend
    // sparklines (disk %, mem-used %, sing-box log MiB). The hero
    // tile shows «right now»; the sparkline tile shows «is the
    // right-now value typical or a spike?». Helps the operator
    // distinguish a slow leak (climbing trendline) from a transient
    // burst (flat trend with one tall bar). Loaded best-effort —
    // a probe-fetch failure shouldn't break the rest of the page.
    let trend_rows = state
        .inv
        .recent_node_health_for_server(&sid, 24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %sid,
                error = %e,
                "recent_node_health_for_server (24h sparkline) failed"
            );
            Vec::new()
        });

    // Phase 4b — server-wide live activity rollup (active conns
    // now, bytes up/down over the last 24h, last poll ts). Failure
    // → zero-default; the section still renders so the operator
    // sees the diagnostic in journalctl + a clean «no data yet»
    // tile instead of a 500.
    let live_activity = state
        .inv
        .server_live_activity(&sid, 24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "server_live_activity failed");
            vpnctl_inventory::ServerLiveActivity::default()
        });

    // Traffic accounting — NIC ground-truth (ALL protocols) vs the
    // sing-box part clash-api attributed vs the GAP between them. The
    // gap is the operator's headline: real traffic vpnctl can't yet
    // break down per-user (naive/Caddy + overhead).
    let traffic = state
        .inv
        .server_traffic_breakdown(&sid, 24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "server_traffic_breakdown failed");
            vpnctl_inventory::TrafficBreakdown {
                nic_total_bytes: 0,
                nic_rx_bytes: 0,
                nic_tx_bytes: 0,
                attributed_bytes: 0,
                gap_bytes: 0,
                nic_samples: 0,
                nic_iface: None,
            }
        });

    // Phase 4c+4d — last clash-api snapshot + log-derived
    // attribution for the «Live connections» drill-down. None
    // when the poller has never reached this server (fresh
    // daemon start / no key / etc) OR the last snapshot went stale
    // (`get_live`: polling stopped → the live connection tables must
    // collapse to their empty state, not render a frozen tick as live).
    let last_server_snap = state.snapshot_cache.get_live(&sid);
    // Phase 5a-2 — bulk-fetch cached PTR hostnames for unique
    // destination IPs in the snapshot. Used to enrich the «top
    // destinations» table — `35.217.1.178:50005` becomes
    // `r3.googlevideo.com:50005` when cached. Misses fall back
    // to bare IP. Resolver task fills the cache asynchronously
    // every 5 minutes.
    let dns_ptr_map = if let Some(s) = last_server_snap.as_ref() {
        let mut dst_ips: HashSet<String> = HashSet::new();
        for c in &s.snapshot.connections {
            if c.metadata.host.is_empty() && !c.metadata.destination_ip.is_empty() {
                dst_ips.insert(c.metadata.destination_ip.clone());
            }
        }
        let ips_vec: Vec<String> = dst_ips.into_iter().collect();
        state
            .inv
            .lookup_dns_ptr_bulk(&ips_vec)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "lookup_dns_ptr_bulk failed");
                HashMap::new()
            })
    } else {
        HashMap::new()
    };

    // Phase 4c — sub_access correlation as the FALLBACK. We
    // extract unique sourceIPs from the snapshot, then ask
    // inventory which users have hit subscription URL from those
    // IPs in the last 7 days. Used when the Phase 4d log scrape
    // has no entry for a given (IP, port) pair (e.g. connection
    // older than the log tail window).
    let source_user_map = if let Some(s) = last_server_snap.as_ref() {
        let mut ips: HashSet<String> = HashSet::new();
        for c in &s.snapshot.connections {
            if !c.metadata.source_ip.is_empty() {
                ips.insert(c.metadata.source_ip.clone());
            }
        }
        let ips_vec: Vec<String> = ips.into_iter().collect();
        state
            .inv
            .users_for_source_ips(&ips_vec, 7)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "users_for_source_ips failed");
                HashMap::new()
            })
    } else {
        HashMap::new()
    };

    // Per-server secrets — only read here so kernel-specific sections
    // can display their current state.
    // Fetched even when no such kernel is enabled because the cost is
    // one indexed SELECT; conditional load would complicate the section
    // helper without measurable savings).
    let server_secrets = state
        .inv
        .list_server_secrets(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Per-(server, protocol) hidden state (migration 0018 / NM-10).
    // One bulk SELECT keyed on server_id → HashMap<ProtocolId, bool>
    // so the Enabled-protocols section can render the hide/unhide
    // chip without N+1 calls into `is_server_protocol_hidden`.
    let hidden_map = state
        .inv
        .list_server_protocols_with_hidden(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let routing_error = state
        .inv
        .resolve_jump_host(&server)
        .await
        .err()
        .map(|e| e.to_string());
    let server_role = state
        .inv
        .get_server_role(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let routing_candidates = state
        .inv
        .list_servers()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let client_detour_candidates = state
        .inv
        .list_fleet_servers()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let client_detour_via = state
        .inv
        .client_detour_via(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Per-server reserved-ports list (migration 0028). Empty for
    // every server in the fleet by default; this load is one
    // indexed SELECT so the section helper always has data without
    // a conditional fetch.
    let reserved_ports = state
        .inv
        .get_reserved_ports(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Operator-set subscription label (servers.display_name, migration
    // 0029). One indexed SELECT; None → the section shows the auto
    // (country-map) fallback.
    let display_name = state
        .inv
        .server_display_name(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Auto-suppress state (migration 0030): (opt-in, suppressed_at).
    let (auto_suppress_optin, suppressed_at) = state
        .inv
        .server_auto_suppress_state(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // naive↔HY2 UDP-pairing opt-in (migration 0031, UX-3).
    let udp_pair_enabled = state
        .inv
        .is_server_udp_pair_enabled(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // ── PR-Server informativeness cards ─────────────────────────────
    // All three SQL-backed loads are best-effort: a query error logs +
    // empty-states the relevant card rather than 500-ing the whole
    // page (the rest of the server detail stays useful). Each is one
    // indexed scan — no new N+1 (the drift-LIVE SSH read, the only
    // expensive path, is gated behind `?drift=live` below).

    // server#3 — top users by 24h traffic on THIS server (Q top-users).
    // Currently empty in prod (NM-11: clash-api drops the per-user
    // field upstream), so the section carries an explicit NM-11
    // empty-state rather than rendering a blank card.
    let top_users = state
        .inv
        .top_users_by_traffic_for_server(&sid, 24, 10)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "top_users_by_traffic_for_server failed");
            Vec::new()
        });

    // server#4 — per-server traffic sparkline. Reuse the fleet's compact
    // hourly rollup and retain only this server.
    let traffic_window = pick_vpn_sparkline_window(query.vpn_window.as_deref());
    let traffic_since_hours = traffic_window.cells * traffic_window.bucket_hours;
    let traffic_rows = state
        .inv
        .recent_vpn_stats_fleet(traffic_since_hours, traffic_window.bucket_hours)
        .await
        .map(|rows| {
            rows.into_iter()
                .filter(|row| row.server_id == sid)
                .collect()
        })
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "server traffic rollup query failed");
            Vec::new()
        });

    // server#7 — server-scoped audit timeline (Q audit-for-server).
    let server_audit = state
        .inv
        .audit_for_server(&sid.0, 20)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "audit_for_server failed");
            Vec::new()
        });

    // server#2 — kernel-floor rollup scoped to THIS server. Reuses the
    // SHARED `kernel_floor_rollup` (PR-Dash) with a single-element
    // slice — `latest` already carries this node's newest
    // `kernel_versions_json` (no extra query).
    let server_kernel_versions: Vec<(vpnctl_core::ServerId, Option<String>)> = vec![(
        sid.clone(),
        latest.as_ref().and_then(|h| h.kernel_versions_json.clone()),
    )];

    // server#1 — drift-detail (live on-node UUIDs). HIGHEST RISK: the
    // ONLY card that reaches out over SSH, so it's gated behind the
    // explicit `?drift=live` opt-in. Without the flag the default page
    // load does ZERO SSH and renders a «[check live drift →]» link.
    //
    // When armed, the live read is best-effort with a hard ≤6s
    // timeout: any failure (node down, key not authorised, parse
    // error) collapses to `None` → the section renders a policy-safe
    // empty-state, NEVER a 500. The inventory UUID set comes from
    // `users` (already loaded; `.uuid` resolves COALESCE(client_uuid,
    // users.uuid)) so an orphan = a UUID the node serves that no
    // granted user accounts for.
    // Gate on the tab too, not just the query flag: the drift-detail
    // card (with its `?drift=live` arm link) only renders on the
    // protocols tab, so `/status?drift=live` (bookmark / hand-typed /
    // crawler) must NOT trigger the 6s SSH read and throw the result
    // away. review-agent Phase 1.
    let drift_live: Option<DriftLiveResult> = if tab == ServerTab::Protocols && query.drift_live() {
        match state.inv.resolve_jump_host(&server).await {
            Ok(jump) => Some(load_drift_live(&server, &users, &all_users, jump).await),
            Err(error) => {
                tracing::warn!(server = %server.id, %error, "live drift skipped: jump validation failed");
                None
            }
        }
    } else {
        None
    };

    // Compute drift: declared vs observed ports.
    let observed: BTreeSet<(String, u16)> = latest
        .as_ref()
        .and_then(|h| h.listening_ports_json.as_deref())
        .and_then(|j| serde_json::from_str::<Vec<String>>(j).ok())
        .map(|v| {
            v.into_iter()
                .filter_map(|s| {
                    let mut p = s.splitn(2, '/');
                    let proto = p.next()?.to_string();
                    let port: u16 = p.next()?.parse().ok()?;
                    Some((proto, port))
                })
                .collect()
        })
        .unwrap_or_default();

    let expected: BTreeSet<(String, u16)> = server
        .enabled_protocols
        .iter()
        .flat_map(|pid| expected_ports_for_protocol(&state.registry, pid, &server_secrets))
        .collect();

    let missing: Vec<_> = expected.difference(&observed).cloned().collect();
    // SSH is always listening — never "extra drift". Use the
    // server's CONFIGURED port (Cloudzy is on 2222, DO sticks on 22,
    // future hosters could be anything). Hardcoded 22 was caught by
    // review-agent: false-positive drift on Cloudzy nodes.
    let ssh_port = server.ssh_port;
    let extra: Vec<_> = observed
        .difference(&expected)
        .filter(|(proto, port)| !(proto == "tcp" && *port == ssh_port))
        .cloned()
        .collect();

    let body = html! {
        nav.ed-crumb {
            a href="/admin/servers" style="color: var(--mute); text-decoration: none;" {
                "← " (crate::i18n::tr(lang, "all servers", "все серверы"))
            }
        }
        div.ed-headrow {
            h1.ed-sumbar__h { (server.id.0) }
            @if let Some(h) = latest.as_ref() {
                @if h.sing_box_active == Some(true) {
                    span.ed-stat.ed-stat--active {
                        span.ed-stat__dot {}
                        (crate::i18n::tr(lang, "up", "работает"))
                        " · " (crate::i18n::tr(lang, "probe ", "проба "))
                        (humanize_age(chrono::Utc::now() - h.ts, lang))
                    }
                } @else if h.sing_box_active == Some(false) {
                    span.ed-stat.ed-stat--failed {
                        span.ed-stat__dot {}
                        (crate::i18n::tr(lang, "down", "не работает"))
                        " · " (crate::i18n::tr(lang, "probe ", "проба "))
                        (humanize_age(chrono::Utc::now() - h.ts, lang))
                    }
                } @else {
                    span.ed-stat.ed-stat--unknown {
                        span.ed-stat__dot {}
                        (crate::i18n::tr(lang, "unknown", "неизвестно"))
                    }
                }
            }
            div.ed-headrow__actions {
                button type="button"
                       data-sse-url=(format!("/admin/servers/{}/update-kernels/sse", path_segment_encode(&server.id.0)))
                       data-log="update-kernels-log"
                       data-busy-label=(crate::i18n::tr(lang, "updating kernels… (watch the log)", "обновляю ядра… (смотри лог)"))
                       data-retry-label=(crate::i18n::tr(lang, "retry update", "повторить обновление"))
                       title=(crate::i18n::tr(
                           lang,
                           "Upgrade the kernel binaries only: streamed live, this probes each declared kernel's version, upgrades the package (apt upgrade), restarts the service, then probes the version again. The running config is left untouched, so this is safe on an inventory-drift node.",
                           "Обновить только бинарники ядер: с живым логом — снять версию каждого ядра, обновить пакет (apt upgrade), перезапустить сервис и снять версию снова. Рабочий конфиг не меняется, поэтому действие безопасно при дрейфе инвентаря.",
                       ))
                       class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                    (crate::i18n::tr(lang, "update kernels", "обновить ядра"))
                }
                button id="deploy-button" type="button"
                       data-sse-url=(format!("/admin/servers/{}/deploy/sse", path_segment_encode(&server.id.0)))
                       data-busy-label=(crate::i18n::tr(lang, "deploying… (watch the log)", "деплою… (смотри лог)"))
                       data-retry-label=(crate::i18n::tr(lang, "retry deploy", "повторить деплой"))
                       title=(crate::i18n::tr(
                           lang,
                           "Full deploy: streamed live — mint missing per-protocol secrets, SSH into the node, run ensure_installed + apply_config for every enabled kernel, and restart services. Each step and the final status appear in the log below. Re-clicking is safe.",
                           "Полный деплой с живым логом: дораздать недостающие секреты, подключиться к ноде по SSH, выполнить ensure_installed + apply_config для каждого включённого ядра и перезапустить сервисы. Каждый шаг и итог появятся в логе ниже. Повторный клик безопасен.",
                       ))
                       class="ed-abtn ed-abtn--recovery ed-abtn--sm" {
                    (crate::i18n::t(lang, crate::i18n::K::BtnDeploy))
                }
                noscript {
                    form method="post"
                         action=(format!("/admin/servers/{}/deploy", path_segment_encode(&server.id.0)))
                         style="display: inline;" {
                        button type="submit" class="ed-abtn ed-abtn--recovery ed-abtn--sm" {
                            (crate::i18n::t(lang, crate::i18n::K::BtnDeploy))
                        }
                    }
                }
            }
        }
        div.ed-detail-meta {
            (server.address) ":" (server.ssh_port)
            " · " (crate::i18n::tr(lang, "ssh as ", "ssh как ")) (server.ssh_user)
            " · "
            @if server.kernels.len() == 1 { (crate::i18n::tr(lang, "kernel ", "ядро ")) }
            @else { (crate::i18n::tr(lang, "kernels ", "ядра ")) }
            (ordered_kernel_ids(&server).iter().map(|k| k.0.clone()).collect::<Vec<_>>().join("+"))
            " · " (crate::i18n::tr(lang, "hoster ", "хостер ")) (server.hoster)
        }

        // Operator-facing Deploy button. Per CLAUDE.md "Web is the
        // ONLY operator surface" — Pavel must never need to open
        // a terminal. One click does the FULL deploy cycle:
        //   1. mint any missing per-protocol server secrets (REALITY
        //      keypair, WG server keypair, Hy2 obfs password) via
        //      `bootstrap_server_secrets` — idempotent,
        //   2. for each enabled kernel: SSH-push install
        //      (`ensure_installed`: apt-get + start) + render config +
        //      `apply_config` (systemctl restart),
        //   3. write an `admin / server.deploy` audit row with the
        //      bootstrapped secrets + per-kernel push result.
        //
        // Re-clicking is safe — already-minted secrets are left
        // untouched; already-installed kernels skip apt-get; config
        // render is deterministic so a redeploy with no changes is a
        // no-op systemctl restart.
        // Pending-deploy banner — grant/revoke happened after the last
        // deploy, so the node's running config doesn't match inventory.
        // The revoke case is the dangerous one: the revoked user's UUID
        // is STILL ACCEPTED by the node until the deploy below runs.
        @if pending_deploy {
            div id="pending-deploy-banner"
                style="margin: 12px 0 0; padding: 10px 14px; border: 1px solid var(--warm); border-left-width: 3px; background: var(--paper-tint); font-family: var(--mono); font-size: 11px; color: var(--ink);" {
                b style="color: var(--warm);" { "⚠ " (crate::i18n::tr(lang, "config not yet deployed", "конфиг ещё не задеплоен")) }
                " — "
                (crate::i18n::tr(
                    lang,
                    "grants changed since the last deploy. Until you click deploy, the node keeps running the OLD user set — a revoked user can still connect.",
                    "гранты менялись после последнего деплоя. Пока не нажат deploy, нода работает со СТАРЫМ списком юзеров — отозванный юзер всё ещё может подключиться.",
                ))
            }
        }
        pre id="deploy-log" hidden
            style="margin: 0 0 12px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}
        pre id="update-kernels-log" hidden
            style="margin: 0 0 12px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}

        // Hero: current state (live or empty-state)
        (server_detail_hero(&latest, &server, lang))

        // ── in-page tabs (ui-audit §3-§4). Chrome above (nav / hero /
        // deploy / update-kernels / pending-deploy banner) shows on
        // EVERY tab so the daily deploy action never hides behind one;
        // each group below renders only on its own tab. Bare
        // /admin/servers/{id} == the `status` tab.
        @let tab_base = format!("/admin/servers/{}", path_segment_encode(&server.id.0));
        @let protocols_tab_label = if latest.is_none() || (missing.is_empty() && extra.is_empty()) {
            crate::i18n::tr(lang, "Protocols", "Протоколы").to_string()
        } else {
            format!("{} ⚠", crate::i18n::tr(lang, "Protocols", "Протоколы"))
        };
        @let grants_tab_label = format!("{} · {}", crate::i18n::tr(lang, "Grants", "Гранты"), user_count);
        (detail_tabs(&tab_base, tab.slug(), &[
            ("status", crate::i18n::tr(lang, "Status", "Статус")),
            ("activity", crate::i18n::tr(lang, "Activity", "Активность")),
            ("protocols", protocols_tab_label.as_str()),
            ("grants", grants_tab_label.as_str()),
            ("setup", crate::i18n::tr(lang, "Setup", "Настройка")),
        ]))

        // ── STATUS (default) — "is the node healthy, what changed".
        @if tab == ServerTab::Status {
            div.ed-detail-grid {
                div {
                    // Rolling uptime SLO (24h/7d/30d) + compact drift
                    // verdict form the left scan column.
                    (server_detail_uptime_section(
                        uptime_24h.as_ref(),
                        uptime_7d.as_ref(),
                        uptime_30d.as_ref(),
                        lang,
                    ))
                    (server_detail_drift_summary(&missing, &extra, latest.is_some(), &tab_base, lang))
                }
                div {
                    // The three 24h resource sparklines own the wider
                    // right column so trend shape stays legible.
                    (server_detail_resource_trend_section(&trend_rows, lang))
                }
            }
            (server_detail_kernel_inventory_section(&server, &state.registry, latest.as_ref(), lang))
            (server_detail_quality_section(
                quality_24h.as_ref(),
                quality_7d.as_ref(),
                &quality_history,
                lang,
            ))
            (server_detail_assurance_section(&assurance_rows, lang))
        }

        // ── ACTIVITY — clash-api-snapshot-derived + the audit trail
        // (design v2 3b moved events here from Status: «what happened»
        // belongs with «what's happening»).
        @if tab == ServerTab::Activity {
            // v2 3b — last-deploy summary line above the events. The
            // page-level #deploy-log pane (headrow deploy button)
            // streams live runs; this line recalls the newest archived
            // deploy from the audit trail.
            @if let Some(last_deploy) = server_audit.iter().find(|e| e.action == "server.deploy") {
                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 0 0 10px;" {
                    (crate::i18n::tr(lang, "last deploy ", "последний деплой "))
                    b { (format_msk_iso(last_deploy.ts)) }
                    " · " (crate::i18n::tr(lang, "by ", "запустил ")) (last_deploy.actor)
                    " · "
                    a href="/admin/audit" style="color: var(--acc);" {
                        (crate::i18n::tr(lang, "audit with this filter →", "аудит с этим фильтром →"))
                    }
                }
            }
            // server#7 — server-scoped audit timeline (last 20),
            // moved from Status (v2 3b).
            (server_detail_audit_section(&server_audit, lang))
            // Phase 4b — live activity tile (server-wide clash-api totals).
            (server_detail_live_activity_section(&live_activity, lang))
            // Traffic accounting — NIC ground-truth vs clash-attributed vs gap.
            (server_detail_gap_section(&traffic, lang))
            // Phase 4c/4d/5a-2 — per-connection drill-down (top dests +
            // reverse-DNS, source IPs with user correlation, TCP/UDP split).
            (server_detail_live_connections_section(last_server_snap.as_deref(), &source_user_map, &dns_ptr_map, lang))
            // server#4 — per-server traffic 24h/7d sparkline (?vpn_window=).
            (server_detail_traffic_section(&traffic_rows, traffic_window, &server.id, lang))
            // server#3 — top users on this server (24h); NM-11 empty-state.
            (server_detail_top_users_section(&top_users, lang))
            // server#5 — TCP/UDP split from the live clash-api snapshot.
            (server_detail_network_split_section(last_server_snap.as_deref(), lang))
        }

        // ── PROTOCOLS — "what does this node serve, on which ports".
        @if tab == ServerTab::Protocols {
            // Kernels — multi-kernel runtime selection + version-floor rollup.
            // Enable amneziawg kernel here → enable wireguard protocol
            // below → deploy. The `update kernels →` button lives in the
            // chrome above (adjacent to Deploy).
            (kernel_floor_rollup(&server_kernel_versions, lang))
            // Declared vs observed drift FIRST (R2 2026-07-10) — the ⚠
            // on this tab's label is about drift, but the grid used to
            // sit at the very bottom below four config forms: the tab
            // opened without answering its own warning.
            (server_detail_drift_section(&server, &state.registry, &server_secrets, &observed, &missing, &extra, latest.is_some(), lang))
            (server_detail_kernels_section(&server, &state.registry, lang))
            // Enabled protocols — enable/disable/hide (NM-10 hidden_map:
            // hidden=1 keeps the inbound running but stops emitting the
            // protocol from /sub + /api/v1/app/config). Changes take
            // effect on the NEXT deploy.
            (server_detail_protocols_section(&server, &state.registry, &hidden_map, lang))
            // Naive (Caddy) + vless-ws per-server config (domain + ACME).
            (server_detail_naive_config_section(&server, &server_secrets, lang))
            (server_detail_vlessws_config_section(&server, &server_secrets, lang))
            // REALITY per-server listen port (co-tenant 443 override).
            (server_detail_reality_config_section(&server, &server_secrets, lang))
            // naive↔HY2 UDP pairing opt-in (UX-3) — shared `pair=` so a
            // client routes UDP over the co-located HY2.
            (server_detail_udp_pair_section(&server, udp_pair_enabled, lang))
            // Reserved ports — operator port allowlist the apply-guard skips.
            (server_detail_reserved_ports_section(&server, &reserved_ports, lang))
            // Drift DETAIL — on-node orphan UUIDs; `?drift=live` arms a
            // best-effort 6s SSH read of the node's sing-box config.
            // Stays at the bottom: it's the on-demand deep dive, not
            // the at-a-glance verdict.
            (server_detail_drift_detail_section(&server, drift_live.as_ref(), query.drift_live(), lang))
        }

        // ── GRANTS — 2nd-most-frequent action; its own uncluttered page.
        @if tab == ServerTab::Grants {
            // Design v2 3d — dense grants table: presence, per-node 24h
            // traffic, key-state (pending deploy vs on node), grant date.
            @let deployed_count = user_count.saturating_sub(pending_users.len());
            div.ed-headrow {
                div.ed-art-eyebrow style="margin: 0;" {
                    (crate::i18n::tr(lang, "Grants", "Выданные доступы")) " "
                    span.ed-tip title=(crate::i18n::tr(
                        lang,
                        "Grant writes the pair into the inventory; keys are minted per protocol on the next deploy. «on node» means the deployed config actually contains the user — grant + forget-to-deploy is the #1 silent failure, the banner below tracks it.",
                        "Грант записывает пару в инвентарь; ключи чеканятся по протоколам на следующем деплое. «на ноде» значит, что задеплоенный конфиг реально содержит юзера — грант без деплоя это тихий сбой №1, баннер ниже его отслеживает.",
                    )) { "ⓘ" }
                }
                span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (user_count) (crate::i18n::tr(lang, " of ", " из ")) (all_users.len())
                    " "
                    // RU forms are GENITIVE (after «из»): из 41
                    // пользователя / из 42 пользователей — not the
                    // nominative counting forms.
                    (crate::i18n::noun_for(lang, all_users.len() as u64, "user granted", "users granted", "пользователя с доступом", "пользователей с доступом", "пользователей с доступом"))
                    " · " (crate::i18n::tr(lang, "deployed config covers ", "задеплоенный конфиг покрывает "))
                    (deployed_count)
                }
            }
            @if !pending_users.is_empty() {
                div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap; border: 1px solid var(--warm); border-left-width: 3px; background: color-mix(in oklab, var(--warm) 9%, var(--paper)); padding: 9px 12px; margin: 10px 0;" {
                    span style="font-family: var(--mono); font-size: 11px; color: var(--warm);" {
                        "⚠ " b {
                            (pending_users.len())
                            (crate::i18n::tr(lang, " grant(s) not yet deployed: ", " грант(ов) ещё не задеплоено: "))
                        }
                        (pending_users.iter().map(|u| u.0.as_str()).collect::<Vec<_>>().join(", "))
                    }
                    div style="margin-left: auto;" {
                        button type="button"
                                data-sse-url=(format!("/admin/servers/{}/deploy/sse", path_segment_encode(&server.id.0)))
                                data-busy-label=(crate::i18n::tr(lang, "deploying… (watch the log)", "деплою… (смотри лог)"))
                                data-retry-label=(crate::i18n::tr(lang, "retry deploy", "повторить деплой"))
                                class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                            (crate::i18n::tr(lang, "deploy now →", "задеплоить сейчас →"))
                        }
                    }
                }
            }
        @if server_role == vpnctl_inventory::ServerRole::WorkloadOnly {
            div class="ed-alert ed-alert--warn" {
                (crate::i18n::tr(lang, "This server is workload-only. User grants are disabled by policy.", "Этот сервер workload-only. Пользовательские grants запрещены политикой."))
            }
        } @else if all_users.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
                (crate::i18n::tr(lang, "No users in the inventory yet. Create one on ", "В инвентаре ещё нет пользователей. Создай на "))
                a href="/admin/users" style="color: var(--ink);" { "/admin/users" }
                (crate::i18n::tr(lang, " — then come back to grant access.", " — затем вернись сюда чтобы выдать доступ."))
            }
        } @else {
            @let sid_enc_b = path_segment_encode(&server.id.0);
            @let ungranted = all_users.iter().filter(|u| !granted_user_ids.contains(&u.id)).collect::<Vec<_>>();
            @let granted_count = granted_user_ids.len();
            // Grant bar (v2 3d) + the B2 bulk actions on one row.
            div.ed-inbar {
                span.ed-inbar__label { (crate::i18n::tr(lang, "grant access", "выдать доступ")) }
                form method="post" action=(format!("/admin/servers/{sid_enc_b}/grants"))
                     style="display: flex; gap: 6px; align-items: center;" {
                    input type="text" name="user_id" required="required"
                          placeholder=(crate::i18n::tr(lang, "user id…", "id пользователя…"))
                          style="width: 150px;";
                    button type="submit" class="ed-abtn ed-abtn--primary ed-abtn--sm" {
                        (crate::i18n::tr(lang, "grant", "выдать"))
                    }
                }
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "Grant writes the pair into the inventory; keys are minted per protocol on the next deploy (auto-deploy runs after).",
                    "Грант пишет пару в инвентарь; ключи чеканятся на следующем деплое (авто-деплой запускается сам).",
                )) { "ⓘ" }
                div style="margin-left: auto; display: flex; gap: 8px;" {
                    @if !ungranted.is_empty() {
                        form method="post"
                             action=(format!("/admin/servers/{sid_enc_b}/grants/_grant-all"))
                             style="margin: 0; padding: 0;" {
                            button type="submit"
                                   title=(crate::i18n::tr(
                                       lang,
                                       "Grant access to every user currently in the inventory who doesn't have it yet. Idempotent.",
                                       "Выдать доступ всем юзерам инвентаря, у кого его сейчас нет. Идемпотентно.",
                                   ))
                                   class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                                (crate::i18n::tr(lang, "grant all ", "выдать всем "))
                                "(" (ungranted.len()) ")"
                            }
                        }
                    }
                    @if granted_count > 0 {
                        @let sid_clean = server.id.0.clone();
                        @let confirm_msg = match lang {
                            crate::i18n::Locale::En => format!(
                                "Revoke access for all {granted_count} granted users on server '{sid_clean}'? Type the server id to confirm:"
                            ),
                            crate::i18n::Locale::Ru => format!(
                                "Отозвать доступ у всех {granted_count} юзеров с грантом на сервере '{sid_clean}'? Введи id сервера для подтверждения:"
                            ),
                        };
                        form method="post"
                             action=(format!("/admin/servers/{sid_enc_b}/grants/_revoke-all"))
                             data-confirm-prompt=(confirm_msg)
                             data-confirm-match=(sid_clean)
                             style="margin: 0; padding: 0;" {
                            input type="hidden" name="confirm" value="";
                            button type="submit"
                                   title=(crate::i18n::tr(
                                       lang,
                                       "Revoke access for every currently-granted user on this server. Destructive — requires confirm.",
                                       "Отозвать доступ у всех юзеров с текущим грантом. Деструктивно — нужно подтверждение.",
                                   ))
                                   class="ed-abtn ed-abtn--danger ed-abtn--sm" {
                                (crate::i18n::tr(lang, "revoke all ", "отозвать все "))
                                "(" (granted_count) ")…"
                            }
                        }
                    }
                }
            }
            // v2 3d — sort links. `presence`/`traffic` sort desc by their
            // metric; `id` (default) is A→Z. Pending-deploy rows always
            // float to the top of any sort so the silent-failure set stays
            // visible. The link row lives just under the grant bar.
            @let grant_sort = query.grant_sort.as_deref().unwrap_or("id");
            @let sort_href = |kind: &str| -> String {
                format!("/admin/servers/{}/grants?grant_sort={kind}", path_segment_encode(&server.id.0))
            };
            div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin: 2px 0 6px;" {
                (crate::i18n::tr(lang, "sort: ", "сортировка: "))
                @for (kind, label) in [("id", "id ↑"), ("presence", crate::i18n::tr(lang, "online ↓", "онлайн ↓")), ("traffic", crate::i18n::tr(lang, "traffic ↓", "трафик ↓"))] {
                    @if grant_sort == kind {
                        span style="color: var(--ink); text-decoration: underline; margin-right: 8px;" { (label) }
                    } @else {
                        a href=(sort_href(kind)) style="color: var(--mute); margin-right: 8px;" { (label) }
                    }
                }
            }
            @let granted_rows = {
                let mut v = all_users.iter().filter(|u| granted_user_ids.contains(&u.id)).collect::<Vec<_>>();
                v.sort_by(|a, b| {
                    // Pending-deploy first in every sort (silent-failure set).
                    let pa = pending_users.contains(&a.id);
                    let pb = pending_users.contains(&b.id);
                    let ca = grants_presence.get(&a.id.0).copied().unwrap_or(0);
                    let cb = grants_presence.get(&b.id.0).copied().unwrap_or(0);
                    let ta = grants_traffic.get(&a.id).copied().unwrap_or(0);
                    let tb = grants_traffic.get(&b.id).copied().unwrap_or(0);
                    let by_metric = match grant_sort {
                        "presence" => cb.cmp(&ca).then(tb.cmp(&ta)),
                        "traffic" => tb.cmp(&ta).then(cb.cmp(&ca)),
                        _ => std::cmp::Ordering::Equal, // id → fall through to id cmp
                    };
                    pb.cmp(&pa).then(by_metric).then(a.id.0.cmp(&b.id.0))
                });
                v
            };
            table.ed-grid style="margin-top: 4px;" {
                thead {
                    tr {
                        th style="width: 34px;" { "№" }
                        th { (crate::i18n::tr(lang, "user", "пользователь")) }
                        th { (crate::i18n::tr(lang, "presence", "присутствие")) }
                        th.num { (crate::i18n::tr(lang, "traffic 24h", "трафик 24ч")) }
                        th { (crate::i18n::tr(lang, "keys on node", "ключи на ноде")) }
                        th style="width: 130px;" { (crate::i18n::tr(lang, "granted", "выдан")) }
                        th style="width: 110px;" {}
                    }
                }
                tbody {
                    @for (idx, u) in granted_rows.iter().enumerate() {
                        @let uid_enc = path_segment_encode(&u.id.0);
                        @let conns = grants_presence.get(&u.id.0).copied().unwrap_or(0);
                        @let bytes = grants_traffic.get(&u.id).copied().unwrap_or(0);
                        @let is_pending = pending_users.contains(&u.id);
                        tr class=(if is_pending { "on-warn" } else if conns > 0 { "on-green" } else { "" }) {
                            td.ed-grid__mut { (format!("{:02}", idx + 1)) }
                            td { a.ed-grid__id href=(format!("/admin/users/{uid_enc}")) { (u.id.0) } }
                            td.ed-grid__sm {
                                @if conns > 0 {
                                    span.ed-stat.ed-stat--active {
                                        span.ed-stat__dot {}
                                        (crate::i18n::tr(lang, "online", "онлайн")) " · " (conns)
                                    }
                                } @else {
                                    span.ed-grid__mut { "— " (crate::i18n::tr(lang, "offline", "офлайн")) }
                                }
                            }
                            td.num {
                                @if bytes > 0 { (humanize_bytes(bytes)) }
                                @else { span.ed-grid__mut { "—" } }
                            }
                            td.ed-grid__sm {
                                @if is_pending {
                                    span.ed-grid__flag { "⚠ " (crate::i18n::tr(lang, "pending deploy", "ждёт деплоя")) }
                                } @else {
                                    span style="color: var(--green);" { "✓ " (crate::i18n::tr(lang, "on node", "на ноде")) }
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm {
                                @match grant_dates.get(&u.id).copied().flatten() {
                                    Some(ts) => (format_msk_iso(ts)),
                                    None => span title=(crate::i18n::tr(
                                        lang,
                                        "Grant predates migration 0039 (2026-07-10) — the date wasn't recorded back then.",
                                        "Грант старше миграции 0039 (2026-07-10) — дата тогда не записывалась.",
                                    )) { "—" },
                                }
                            }
                            td.num {
                                form method="post"
                                     action=(format!("/admin/servers/{sid_enc_b}/grants/{uid_enc}/revoke"))
                                     style="margin: 0; padding: 0; display: inline;" {
                                    button type="submit"
                                           title=(match lang {
                                               crate::i18n::Locale::En => format!("Revoke {}'s access on {}", u.id.0, server.id.0),
                                               crate::i18n::Locale::Ru => format!("Отозвать доступ {} на {}", u.id.0, server.id.0),
                                           })
                                           class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                                        (crate::i18n::tr(lang, "revoke →", "отозвать →"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Not-granted footnote — each id carries its own inline
            // grant form so the operator never leaves the page.
            @if !ungranted.is_empty() {
                div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; font-family: var(--mono); font-size: 10px; color: var(--mute); margin-top: 8px;" {
                    (crate::i18n::tr(lang, "not granted: ", "без доступа: "))
                    b style="color: var(--ink);" { (ungranted.len()) }
                    @for u in &ungranted {
                        form method="post"
                             action=(format!("/admin/servers/{sid_enc_b}/grants/{}", path_segment_encode(&u.id.0)))
                             style="margin: 0; padding: 0; display: inline;" {
                            button type="submit"
                                   title=(match lang {
                                       crate::i18n::Locale::En => format!("Grant {} access on {}", u.id.0, server.id.0),
                                       crate::i18n::Locale::Ru => format!("Выдать {} доступ на {}", u.id.0, server.id.0),
                                   })
                                   class="ed-grant-chip off" style="cursor: pointer;" {
                                (u.id.0) " — " (crate::i18n::tr(lang, "grant →", "выдать →"))
                            }
                        }
                    }
                }
            }
        }
        }


        // ── SETUP — the 0-2-uses/month config tail (ui-audit §4),
        // deliberately last.
        @if tab == ServerTab::Setup {
            // Design v2 3e — node-setup checklist, re-verified from the
            // latest probe (not just at bootstrap): a manually broken
            // node surfaces here without a redeploy. Honest subset —
            // only facts the probe/inventory actually carry today
            // (bbr/ntp/logrotate-config checks need probe extensions).
            div.ed-art-eyebrow {
                (crate::i18n::tr(lang, "Node setup · verified at last probe", "Настройка ноды · сверено последней пробой")) " "
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "Each row is re-checked on every probe. A ⚠ here means the node drifted from its bootstrapped state.",
                    "Каждая строка перепроверяется каждой пробой. ⚠ значит, что нода уехала от состояния после bootstrap.",
                )) { "ⓘ" }
            }
            @let ok = |b: bool| -> Markup {
                if b { html! { span style="color: var(--green);" { "✓" } } }
                else { html! { span style="color: var(--warm);" { "⚠" } } }
            };
            @let kernels_reported = latest.as_ref()
                .and_then(|h| h.kernel_versions_json.as_deref())
                .and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok())
                .and_then(|v| v.as_object().map(|o| {
                    let mut parts: Vec<String> = o.iter()
                        .map(|(k, ver)| format!("{k} {}", ver.as_str().unwrap_or("?")))
                        .collect();
                    parts.sort();
                    parts.join(" · ")
                }));
            table.ed-feed style="margin: 8px 0 16px;" {
                tbody {
                    tr {
                        td style="width: 20px;" { (ok(latest.is_some())) }
                        td { b { (crate::i18n::tr(lang, "deploy key installed", "деплой-ключ установлен")) } }
                        td.num.ed-grid__mut.ed-grid__sm {
                            @if latest.is_some() { (crate::i18n::tr(lang, "probe reaches the node over it", "проба ходит на ноду по нему")) }
                            @else { (crate::i18n::tr(lang, "no probe yet — key unverified", "проб ещё нет — ключ не проверен")) }
                        }
                    }
                    tr {
                        td { (ok(kernels_reported.is_some())) }
                        td { b { (crate::i18n::tr(lang, "kernels installed", "ядра установлены")) } }
                        td.num.ed-grid__mut.ed-grid__sm {
                            @match &kernels_reported {
                                Some(k) => (k),
                                None => (crate::i18n::tr(lang, "no version report yet", "версий ещё нет")),
                            }
                        }
                    }
                    tr {
                        td { (ok(latest.as_ref().and_then(|h| h.sing_box_active) == Some(true))) }
                        td { b { "sing-box " (crate::i18n::tr(lang, "service active", "сервис активен")) } }
                        td.num.ed-grid__mut.ed-grid__sm { "service active" }
                    }
                    tr {
                        td { (ok(latest.as_ref().and_then(|h| h.fail2ban_active) == Some(true))) }
                        td { b { "fail2ban " (crate::i18n::tr(lang, "active · sshd jail", "активен · sshd jail")) } }
                        td.num.ed-grid__mut.ed-grid__sm { "service active" }
                    }
                    tr {
                        td { (ok(server.trusted_host_fingerprint.is_some())) }
                        td { b { (crate::i18n::tr(lang, "host fingerprint pinned", "отпечаток хоста запинен")) } }
                        td.num.ed-grid__mut.ed-grid__sm title=(server.trusted_host_fingerprint.as_deref().unwrap_or("")) {
                            @match server.trusted_host_fingerprint.as_deref() {
                                Some(fp) => (fp_short(fp)),
                                None => (crate::i18n::tr(lang, "pin below", "запинь ниже")),
                            }
                        }
                    }
                    tr {
                        td { (ok(clash_ok)) }
                        td { b { "clash api " (crate::i18n::tr(lang, "reachable · traffic attribution", "доступен · атрибуция трафика")) } }
                        td.num.ed-grid__mut.ed-grid__sm {
                            @if clash_ok { (crate::i18n::tr(lang, "snapshot in cache", "снимок в кеше")) }
                            @else { (crate::i18n::tr(lang, "no snapshot — poller can't reach it", "нет снимка — поллер не достучался")) }
                        }
                    }
                    tr {
                        @let log_ok = latest.as_ref().and_then(|h| h.sing_box_log_bytes).is_none_or(|b| b <= 500 * 1024 * 1024);
                        td { (ok(log_ok)) }
                        td { b { "sing-box.log " (crate::i18n::tr(lang, "under the 500 MiB alert", "меньше алертных 500 MiB")) } }
                        td.num.ed-grid__mut.ed-grid__sm {
                            @match latest.as_ref().and_then(|h| h.sing_box_log_bytes) {
                                Some(b) => { (humanize_bytes(b)) @if !log_ok { " — " (crate::i18n::tr(lang, "check logrotate on the node", "проверь logrotate на ноде")) } },
                                None => "—",
                            }
                        }
                    }
                }
            }
            // v2 3e — bootstrap record from the audit trail (best
            // effort; nodes imported outside the wizard have none).
            @let bootstrap_row = server_audit.iter().find(|e| e.action.starts_with("server.bootstrap") || e.action == "bootstrap");
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 0 0 16px;" {
                (crate::i18n::tr(lang, "bootstrap record: ", "запись bootstrap: "))
                @match bootstrap_row {
                    Some(e) => { b { (format_msk_iso(e.ts)) } " · " (crate::i18n::tr(lang, "by ", "запустил ")) (e.actor) },
                    None => (crate::i18n::tr(lang, "none in the audit window (imported or pre-wizard node)", "нет в окне аудита (импорт или до-мастерная нода)")),
                }
            }

            // Trusted host fingerprint — TOFU pin for the SSH probe +
            // clash-api poller + deploy (web action + the
            // `vpnctl server set-fingerprint <id>` CLI, one source of truth).
            (server_detail_fingerprint_section(&server, lang))
            (server_detail_routing_policy_section(&server, server_role, &routing_candidates, routing_error.as_deref(), lang))
            (server_detail_client_detour_section(&server, client_detour_via.as_ref(), &client_detour_candidates, lang))
            // Display name — operator subscription label (migration 0029).
            (server_detail_display_name_section(&server, display_name.as_deref(), lang))
            // Auto-suppress from subscription when unreachable (migration 0030).
            (server_detail_auto_suppress_section(&server, auto_suppress_optin, suppressed_at.as_deref(), lang))
            // Push deploy key — recovery for quick-add/migrate nodes whose
            // wizard step-3 pubkey push never ran.
            (server_detail_push_deploy_key_section(&server, lang))

            // Danger zone — remove this server from inventory entirely.
            // Retype-to-confirm page (mirrors user delete). Grants, secrets,
            // protocols, probe history + alerts cascade-delete; if another
            // server uses this as a ProxyJump host that link clears. The
            // node's own sing-box is NOT touched.
            div.ed-rule {}
            div style="margin: 18px 0 8px;" {
                a href=(format!("/admin/servers/{}/delete-confirm", path_segment_encode(&server.id.0)))
                  title=(crate::i18n::tr(
                      lang,
                      "Remove this server from the inventory (grants + secrets + protocols cascade). Opens a retype-to-confirm page.",
                      "Удалить этот сервер из инвентаря (гранты + секреты + протоколы каскадом). Откроется страница с подтверждением по перепечатке id.",
                  ))
                  class="ed-abtn ed-abtn--danger" {
                    (crate::i18n::tr(lang, "delete this server…", "удалить этот сервер…"))
                }
            }
        }
    };
    Ok(render_page(&state, "servers", &theme, &accent, lang, body).await)
}
