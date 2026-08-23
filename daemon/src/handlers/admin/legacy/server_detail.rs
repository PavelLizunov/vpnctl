use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

use super::super::audit::{action_kind, summarize_audit_payload};
use super::super::helpers::*;
use super::super::servers::*;
use super::super::users::mask_secret;
use super::*;
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};
use vpnctl_core::humanize::format_size_bytes;
// ────────────────────────────────────────────────────────────────────────
//  Phase H chunk 3 — server detail page with live telemetry surface.
//
//  Reads:
//    * `inv.get_server(id)` — declared state
//    * `inv.users_for_server(id)` — grants count
//    * `inv.latest_node_health(id)` — most recent probe (live)
//    * `inv.recent_node_health_for_server(id, 24)` — 24h window
//
//  Drift detection: parses the latest probe's `listening_ports_json`,
//  cross-references against `server.enabled_protocols` (mapping protocol
//  → expected ports), highlights mismatch in orange (--acc).
// ────────────────────────────────────────────────────────────────────────

/// Map a protocol id → set of (proto, port) we EXPECT it to be
/// listening on. Single source of truth for the drift check —
/// matches what each `Protocol::server_inbound` emits.
/// Look up expected `(proto, port)` tuples for a given protocol via
/// the registry. **Single source of truth** — each protocol owns its
/// own port declaration (see `vpnctl_core::Protocol`), so adding a
/// new protocol doesn't require touching this function. (Refactored
/// 2026-05-16 per review-agent finding — previous hand-maintained
/// map violated kernel/protocol orthogonality.)
///
/// `secrets` = this server's secret map: `effective_listen_ports`
/// resolves runtime-configurable ports (vless.listen_port override),
/// so the table shows the port the node ACTUALLY binds — not the
/// compile-time default (cdn incident 2026-08-05: reality on 8443
/// rendered as «no fixed port» while 443 stayed firewalled).
fn expected_ports_for_protocol(
    registry: &vpnctl_core::Registry,
    pid: &vpnctl_core::ProtocolId,
    secrets: &std::collections::HashMap<String, String>,
) -> Vec<(String, u16)> {
    match registry.protocol(pid) {
        Some(p) => p
            .effective_listen_ports(secrets)
            .into_iter()
            .map(|(s, n)| (s.to_string(), n))
            .collect(),
        None => Vec::new(),
    }
}

/// Query string for the server-detail page (PR-Server).
///
/// * `drift=live` — opt-in flag that arms the highest-risk card
///   (server#1 drift-detail): a best-effort live SSH read of the
///   node's `/etc/sing-box/config.json` to diff the on-node UUIDs
///   against inventory. GATED so the DEFAULT page load stays fast —
///   no SSH happens unless the operator clicks «check live drift».
/// * `vpn_window` — shared window slug (`24h|7d|30d|all`) consumed by
///   the per-server traffic sparkline's `window_picker_section`, same
///   shape as the dashboard + user-detail pages.
#[derive(serde::Deserialize, Default)]
pub(crate) struct ServerDetailQuery {
    #[serde(default)]
    drift: Option<String>,
    #[serde(default)]
    vpn_window: Option<String>,
    /// v2 3d — grants-tab sort: `id` (default) · `presence` · `traffic`.
    #[serde(default)]
    grant_sort: Option<String>,
}

impl ServerDetailQuery {
    /// True only for the explicit `?drift=live` opt-in. Any other
    /// value (absent, `?drift=`, `?drift=foo`) keeps the live SSH
    /// read disarmed — the default fast path.
    fn drift_live(&self) -> bool {
        matches!(self.drift.as_deref(), Some("live"))
    }
}

/// server_detail's in-page tabs (ui-audit §3-§4). Each is a real
/// sub-route (`/admin/servers/{id}/{slug}`) so navigation is plain
/// `<a href>` — zero JS, back-button-correct, deep-linkable — and each
/// tab renders only its own sections. `Status` is the default (bare
/// `/admin/servers/{id}`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerTab {
    Status,
    Activity,
    Protocols,
    Grants,
    Setup,
}

impl ServerTab {
    fn slug(self) -> &'static str {
        match self {
            ServerTab::Status => "status",
            ServerTab::Activity => "activity",
            ServerTab::Protocols => "protocols",
            ServerTab::Grants => "grants",
            ServerTab::Setup => "setup",
        }
    }
}

/// The `.ed-tabs` bar — dead CSS since Phase A (admin.css:608), worn
/// here for the first time. `base` must already be path-segment-encoded;
/// `active` is the current tab's slug (its link gets `.ed-tab--on`).
/// `cursor`/`text-decoration` are set inline because the dead CSS was
/// authored for JS toggles (cursor:default, no link reset).
pub(crate) fn detail_tabs(base: &str, active: &str, tabs: &[(&str, &str)]) -> Markup {
    html! {
        div.ed-tabs {
            @for (slug, label) in tabs {
                a class=(if *slug == active { "ed-tab ed-tab--on" } else { "ed-tab" })
                  href=(format!("{base}/{slug}"))
                  style="cursor: pointer; text-decoration: none;" {
                    (label)
                }
            }
        }
    }
}

// Thin axum handlers — one per tab route in app.rs. Bare
// `/admin/servers/{id}` (+ trailing slash) + `/status` both land here.
pub(crate) async fn server_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Status).await
}

pub(crate) async fn server_detail_activity(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Activity).await
}

pub(crate) async fn server_detail_protocols_tab(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Protocols).await
}

pub(crate) async fn server_detail_grants_tab(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Grants).await
}

pub(crate) async fn server_detail_setup(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Setup).await
}

async fn server_detail_render(
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
    let granted_user_ids: std::collections::HashSet<vpnctl_core::UserId> =
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
        let dates: std::collections::HashMap<
            vpnctl_core::UserId,
            Option<chrono::DateTime<chrono::Utc>>,
        > = state
            .inv
            .grant_dates_for_server(&sid)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        let pending: std::collections::HashSet<vpnctl_core::UserId> = state
            .inv
            .users_pending_deploy_for_server(&sid)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut presence: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        // `get_live`: per-user live conns on this node must drop out once
        // the snapshot goes stale (polling stopped).
        if let Some(snap) = state.snapshot_cache.get_live(&sid) {
            for c in &snap.snapshot.connections {
                if let Some(uid) = c.metadata.user.as_deref() {
                    *presence.entry(uid.to_string()).or_default() += 1;
                }
            }
        }
        let traffic: std::collections::HashMap<vpnctl_core::UserId, u64> = state
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
    // break down per-user (naive/Caddy, dns-tunnel, wgturn + overhead).
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
        let mut dst_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
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
                std::collections::HashMap::new()
            })
    } else {
        std::collections::HashMap::new()
    };

    // Phase 4c — sub_access correlation as the FALLBACK. We
    // extract unique sourceIPs from the snapshot, then ask
    // inventory which users have hit subscription URL from those
    // IPs in the last 7 days. Used when the Phase 4d log scrape
    // has no entry for a given (IP, port) pair (e.g. connection
    // older than the log tail window).
    let source_user_map = if let Some(s) = last_server_snap.as_ref() {
        let mut ips: std::collections::HashSet<String> = std::collections::HashSet::new();
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
                std::collections::HashMap::new()
            })
    } else {
        std::collections::HashMap::new()
    };

    // Per-server secrets — only read here so kernel-specific sections
    // (currently wgturn's VK-link form) can display their current state.
    // Fetched even when no such kernel is enabled because the cost is
    // one indexed SELECT; conditional load would complicate the section
    // helper without measurable savings.
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
        Some(load_drift_live(&server, &users, &all_users).await)
    } else {
        None
    };

    // Compute drift: declared vs observed ports.
    let observed: std::collections::BTreeSet<(String, u16)> = latest
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

    let expected: std::collections::BTreeSet<(String, u16)> = server
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
                        (super::dashboard::humanize_age(chrono::Utc::now() - h.ts, lang))
                    }
                } @else if h.sing_box_active == Some(false) {
                    span.ed-stat.ed-stat--failed {
                        span.ed-stat__dot {}
                        (crate::i18n::tr(lang, "down", "не работает"))
                        " · " (crate::i18n::tr(lang, "probe ", "проба "))
                        (super::dashboard::humanize_age(chrono::Utc::now() - h.ts, lang))
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
            // wgturn VK-link — only when the wgturn kernel is enabled.
            (server_detail_wgturn_section(&server, &server_secrets, lang))
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
        @if all_users.is_empty() {
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

/// Phase H+ — rolling uptime SLO section. Three chips (24h / 7d /
/// 30d) under the live-status hero. Reads `UptimeStat` values
/// fetched in the handler (uptime_for_server SQL aggregate, one
/// indexed range scan per window).
///
/// Renders NOTHING when all three windows have None — the hero
/// already shows the «no probes yet» empty state and stacking
/// another empty block would be UI noise.
///
/// Chip colour rules (per chip, independent of the others):
///   * `Some(100)`          → green «100%» — perfect, no outages
///   * `Some(>= 99)`        → green
///   * `Some(>= 95)`        → amber
///   * `Some(< 95)`         → red
///   * `Some(0)`            → red «0%» (was DOWN for the entire
///     window — distinct from None!)
///   * `None`               → grey «— no data» (no decidable rows)
///
/// Display precision is **integer %** (formatted via `{p}%` on `u8`)
/// — not one-decimal. `Option<u8>` carries enough resolution for the
/// «pick a colour bucket» purpose without false-precision in the
/// rendered chip («99%» vs «98.7%» — the latter implies precision
/// the 10-min poll cadence simply doesn't deliver).
///
/// Last-outage display: shows ISO timestamp of the most recent
/// `sing_box_active=0` row across ALL THREE windows (the widest is
/// 30d so it captures any). Renders only if found.
///
/// Last-probe staleness: if the most recent probe across all three
/// windows is older than 1200s (= 2× the DEFAULT 600s probe
/// interval), render an amber «poller may be stale» footer. The
/// threshold is hardcoded rather than reading
/// `VPNCTLD_NODE_PROBE_INTERVAL_SECS` from env — the env override
/// is daemon-startup only and the UI would have to observe its
/// own process to read it. **Caveat:** if the operator has set
/// `VPNCTLD_NODE_PROBE_INTERVAL_SECS=1800` or higher, this 1200s
/// threshold will false-positive the «stale» chip after the first
/// natural-interval tick. Acceptable today (production runs with
/// the default 600s) — file a follow-up if Pavel ever raises the
/// interval persistently.
pub(super) fn server_detail_uptime_section(
    u24h: Option<&vpnctl_inventory::UptimeStat>,
    u7d: Option<&vpnctl_inventory::UptimeStat>,
    u30d: Option<&vpnctl_inventory::UptimeStat>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;

    // Don't render the section when there's literally no data:
    //   * All three queries failed → suppress (DB error path).
    //   * All three returned `total_rows == 0` → suppress (the
    //     hero already shows «no probes yet» — stacking another
    //     empty block would be UI noise).
    //
    // Subtlety: `uptime_for_server` returns `Ok(UptimeStat { 0,
    // 0, 0, ... })` for an empty window — it does NOT return
    // `Err`. So an `is_none()` check on the Option would always
    // be false in practice (only Err → None via `.ok()`). The
    // load-bearing check is on `total_rows`.
    let any_data = u24h.is_some_and(|s| s.total_rows > 0)
        || u7d.is_some_and(|s| s.total_rows > 0)
        || u30d.is_some_and(|s| s.total_rows > 0);
    if !any_data {
        return html! {};
    }

    let row = |label: &str, stat: Option<&vpnctl_inventory::UptimeStat>| -> Markup {
        let pct = stat.and_then(|s| s.uptime_pct);
        let color = super::dashboard::pct_color(pct);
        let pct_text = pct_label(pct, lang);
        let row_count: u64 = stat.map(|s| s.total_rows).unwrap_or(0);
        let down_count: u64 = stat.map(|s| s.down_rows).unwrap_or(0);
        // `data-uptime-pct` is a stable scrape-target for admin_smoke
        // tests + a future operator tool that wants to extract SLOs
        // without parsing the CSS. The value is the raw u8 or the
        // literal string "none" for the no-data branch. Choosing the
        // attribute over inline-text means the test can't false-pass
        // on unrelated `100%` substrings elsewhere on the page (e.g.
        // disk-pressure tile at 100%).
        let pct_attr = pct.map(|p| p.to_string()).unwrap_or_else(|| "none".into());
        html! {
            tr data-uptime-pct=(pct_attr) {
                th { (label) }
                td.num style=(format!("font-family: var(--serif); font-weight: 600; color: {color};")) {
                    (pct_text)
                }
                td.num.ed-grid__mut.ed-grid__sm {
                    (row_count) " " (crate::i18n::noun_for(lang, row_count, "probe", "probes", "проба", "пробы", "проб"))
                    @if down_count > 0 { " · " (down_count) " " (tr(lang, "down", "падений")) }
                }
            }
        }
    };

    // Pick the most recent outage across all three windows (30d is
    // widest, so if it has one, that's our answer; fall through if
    // somehow the wider window missed but a narrower didn't).
    let last_outage = u30d
        .and_then(|s| s.last_outage_at)
        .or_else(|| u7d.and_then(|s| s.last_outage_at))
        .or_else(|| u24h.and_then(|s| s.last_outage_at));

    // Most recent probe (any state). For staleness chip.
    let last_probe = u24h
        .and_then(|s| s.last_probe_at)
        .or_else(|| u7d.and_then(|s| s.last_probe_at))
        .or_else(|| u30d.and_then(|s| s.last_probe_at));

    let stale = last_probe
        .map(|ts| (chrono::Utc::now() - ts).num_seconds() > 1200)
        .unwrap_or(false);

    html! {
        section #uptime-section style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Uptime · sing-box service", "Uptime · сервис sing-box"))
                " "
                span.ed-tip title=(tr(
                    lang,
                    "Rolling-window aggregate over sing_box_active from the node_probe poller (10-min default tick). Up means the service reported active at probe time; unknown probes are excluded from the denominator.",
                    "Скользящие окна sing_box_active от node_probe-поллера (тик по умолчанию 10 минут). Up означает, что сервис показал active; неопределённые пробы не входят в знаменатель.",
                )) { "ⓘ" }
            }
            table.ed-grid style="margin-top: 8px;" {
                tbody {
                    (row(tr(lang, "last 24h", "24 часа"), u24h))
                    (row(tr(lang, "last 7d",  "7 дней"),  u7d))
                    (row(tr(lang, "last 30d", "30 дней"), u30d))
                }
            }
            @if last_outage.is_some() || stale {
                div style="margin-top: 12px; font-family: var(--mono); font-size: 11px; color: var(--mute); display: flex; flex-direction: column; gap: 4px;" {
                    @if let Some(ts) = last_outage {
                        @let mins = chrono::Utc::now().signed_duration_since(ts).num_minutes().max(0);
                        div {
                            (tr(lang, "Last outage observed: ", "Последнее падение: "))
                            span style="color: var(--ink);" { (format_msk_iso(ts)) }
                            " ("
                            @if mins < 60 {
                                (mins) " " (tr(lang, "min ago", "мин назад"))
                            } @else if mins < 24 * 60 {
                                (mins / 60) " " (tr(lang, "h ago", "ч назад"))
                            } @else {
                                (mins / (24 * 60)) " " (tr(lang, "d ago", "д назад"))
                            }
                            ")"
                        }
                    }
                    @if stale {
                        div style="color: #e6a23c;" {
                            (tr(
                                lang,
                                "Most recent probe is >20 min old — the poller may be stalled. Use the manual sweep button on this page to refresh.",
                                "Последняя проба старше 20 минут — поллер может быть остановлен. Нажми кнопку ручного сканирования на этой странице, чтобы обновить.",
                            ))
                        }
                    }
                }
            }
        }
    }
}

/// Hero block — most-recent probe at-a-glance KPIs, OR an empty state
/// describing why the box is empty (no probe data yet — either fresh
/// server, deploy key not pushed, or poller not running).
fn server_detail_hero(
    latest: &Option<vpnctl_inventory::NodeHealthRow>,
    server: &vpnctl_core::Server,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let Some(h) = latest else {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { (tr(lang, "Live status", "Живой статус")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                // Honest copy (audit 2026-06-10): the poller is LIVE
                // (spawn_node_probe_poller, 10-min cadence) and probes
                // sing-box servers only — blank means «not probed yet»
                // or «not probeable», not «feature unshipped».
                (tr(
                    lang,
                    "No probes yet. The node-telemetry poller SSHes ",
                    "Probe-ов пока нет. Поллер телеметрии SSH-ит ",
                ))
                span.ed-mono { (server.address) }
                (tr(
                    lang,
                    " every 10 min for disk/mem/load + listening ports. Blank here means the first probe hasn't landed (fresh server / daemon restart), the node is unreachable over SSH, or this server has no sing-box kernel (only sing-box nodes are probed).",
                    " каждые 10 минут за disk/mem/load + слушающими портами. Пусто значит: первый probe ещё не прошёл (новый сервер / рестарт демона), нода недоступна по SSH, либо у сервера нет ядра sing-box (probe-ятся только sing-box ноды).",
                ))
            }
        };
    };
    let sb = h
        .sing_box_active
        .map(|b| {
            if b {
                tr(lang, "active", "активен")
            } else {
                tr(lang, "down", "не работает")
            }
        })
        .unwrap_or("?");
    let f2b = h
        .fail2ban_active
        .map(|b| {
            if b {
                tr(lang, "active", "активен")
            } else {
                tr(lang, "down", "не работает")
            }
        })
        .unwrap_or("?");
    let disk_used_pct = h
        .disk_used_mib
        .zip(h.disk_total_mib)
        .filter(|(_, t)| *t > 0)
        .map(|(u, t)| (u * 100 / t).min(100));
    let disk_pct = disk_used_pct
        .map(|pct| format!("{pct}%"))
        .unwrap_or("?".into());
    let mem_used_pct = h
        .mem_available_mib
        .zip(h.mem_total_mib)
        .filter(|(_, t)| *t > 0)
        .map(|(a, t)| 100u64.saturating_sub(a * 100 / t));
    let mem_pct = mem_used_pct
        .map(|pct| format!("{pct}%"))
        .unwrap_or("?".into());
    let load = h
        .load_1min_x100
        .map(|l| format!("{:.2}", f64::from(l) / 100.0))
        .unwrap_or("?".into());
    let log_size = h
        .sing_box_log_bytes
        .map(humanize_bytes)
        .unwrap_or("?".into());

    let sb_color = match h.sing_box_active {
        Some(true) => "var(--soft)",
        Some(false) => "var(--acc)",
        None => "var(--mute)",
    };
    let f2b_color = match h.fail2ban_active {
        Some(true) => "var(--soft)",
        Some(false) => "var(--acc)",
        None => "var(--mute)",
    };
    let log_alert_color = match h.sing_box_log_bytes {
        Some(b) if b > 500 * 1024 * 1024 => "var(--acc)",
        _ => "var(--ink)",
    };

    html! {
        div.ed-status-strip title=(format!("{} · {}", tr(lang, "last probe", "последняя проба"), format_msk_iso(h.ts))) {
            (status_tile_with_warn("sing-box", sb, sb_color, h.sing_box_active == Some(false)))
            (status_tile_with_warn("fail2ban", f2b, f2b_color, h.fail2ban_active == Some(false)))
            (status_tile_with_warn(tr(lang, "disk used", "диск занят"), &disk_pct, "var(--ink)", disk_used_pct.is_some_and(|v| v > 70)))
            (status_tile_with_warn(tr(lang, "memory used", "память занята"), &mem_pct, "var(--ink)", mem_used_pct.is_some_and(|v| v > 70)))
            (status_tile_with_warn(tr(lang, "1-min load", "load 1мин"), &load, "var(--ink)", false))
            (status_tile_with_warn(tr(lang, "sing-box log", "лог sing-box"), &log_size, log_alert_color, h.sing_box_log_bytes.is_some_and(|b| b > 500 * 1024 * 1024)))
        }
    }
}

pub(super) fn status_tile(label: &str, value: &str, value_color: &str) -> Markup {
    status_tile_with_warn(label, value, value_color, false)
}

pub(super) fn status_tile_with_warn(
    label: &str,
    value: &str,
    value_color: &str,
    warn: bool,
) -> Markup {
    html! {
        div class=(if warn { "ed-status-tile warn" } else { "ed-status-tile" }) {
            div.ed-status-tile__k { (label) }
            div.ed-status-tile__v style=(format!("color: {value_color};")) {
                (value)
                @if warn { " ⚠" }
            }
        }
    }
}

/// Phase 4b — server-wide live activity tile (active conns now +
/// 24h bytes up/down + last poll ts + attributed-users counter).
/// Companion to the per-user «Live VPN stats» section on
/// /admin/users/<id>; that one shows ONE user across all servers,
/// this one shows ALL traffic on ONE server.
///
/// NM-11 caveat surfaced in the empty-state copy: per-user
/// attribution from clash-api is blocked by a sing-box upstream
/// bug (TrackerMetadata.MarshalJSON omits the User field). Server-
/// wide totals work, per-user counts always read 0 until upstream
/// PR lands or operator adopts a forked sing-box build.
/// A3 (audit 2026-05-22) — 24h resource-trend sparklines for the
/// per-server detail page. Three small SVG charts: disk %, mem-used %,
/// sing-box log MiB. Each uses the existing reusable `sparkline_svg`
/// helper (so styling stays consistent with the dashboard + monitoring
/// page; accent-toggle in Tweaks panel recolours everything).
///
/// **Renders only when there's at least one node_health row in the
/// 24h window.** Fresh server (no probes yet) gets nothing — the hero
/// section already says «no data yet» for that case; we don't need to
/// repeat it.
///
/// Each row in `trend_rows` came from `recent_node_health_for_server`
/// which sorts DESC (newest first). For the sparkline we reverse so
/// time flows left-to-right.
fn server_detail_resource_trend_section(
    trend_rows: &[vpnctl_inventory::NodeHealthRow],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if trend_rows.is_empty() {
        return html! {};
    }
    // Iterate oldest→newest so the sparkline reads chronologically.
    let mut chronological: Vec<&vpnctl_inventory::NodeHealthRow> = trend_rows.iter().collect();
    chronological.reverse();

    // Disk usage % per row. Skip rows missing either side of the
    // ratio (None → no point added; sparkline tolerates a shorter
    // series gracefully).
    let disk_pct_series: Vec<f64> = chronological
        .iter()
        .filter_map(|r| {
            let used = r.disk_used_mib?;
            let total = r.disk_total_mib?;
            if total == 0 {
                return None;
            }
            Some(((used as f64) / (total as f64)) * 100.0)
        })
        .collect();

    // Memory-used % per row (probe stores AVAILABLE, hence 100 - avail/total).
    let mem_used_pct_series: Vec<f64> = chronological
        .iter()
        .filter_map(|r| {
            let avail = r.mem_available_mib?;
            let total = r.mem_total_mib?;
            if total == 0 {
                return None;
            }
            Some(100.0 - ((avail as f64) / (total as f64)) * 100.0)
        })
        .collect();

    // sing-box log size in MiB. The threshold alert
    // (server.singbox.log.too_big) fires at 500 MiB; sparkline shows
    // the climb so operator can predict «when will we hit 500».
    let log_mib_series: Vec<f64> = chronological
        .iter()
        .filter_map(|r| r.sing_box_log_bytes.map(|b| (b as f64) / (1024.0 * 1024.0)))
        .collect();

    let n_samples = chronological.len();
    let max_value = |series: &[f64]| series.iter().copied().reduce(f64::max).unwrap_or_default();
    let disk_max = max_value(&disk_pct_series);
    let mem_max = max_value(&mem_used_pct_series);
    let log_max = max_value(&log_mib_series);
    html! {
        section id="resource-trend" style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Resource trend · last 24h", "Тренд ресурсов · последние 24ч"))
                " "
                span.ed-tip title=(tr(
                    lang,
                    "10-min probe snapshots over the last 24h. Sparkline reads left-to-right (oldest → newest); the «max» label on each chart is the peak in the window. Use these to tell a slow leak (climbing line) from a transient burst (flat line, one spike).",
                    "10-минутные снимки probe за последние 24 часа. Sparkline читается слева-направо (старое → новое); метка «max» в каждом графике — пик за окно. Помогает отличить медленную утечку (растущая линия) от кратковременного всплеска (плоская линия с одним пиком).",
                )) { "ⓘ" }
            }
            div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-top: 8px;" {
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "Disk %", "Диск %"))
                    }
                    (super::dashboard::sparkline_svg_scaled(&disk_pct_series, 280, 60, Some(100.0), false))
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                        (tr(lang, "max ", "макс ")) (format!("{disk_max:.0}%"))
                        " · " (disk_pct_series.len()) " " (tr(lang, "samples", "точек"))
                    }
                }
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "Mem used %", "Память исп. %"))
                    }
                    (super::dashboard::sparkline_svg_scaled(&mem_used_pct_series, 280, 60, Some(100.0), false))
                    div style=(if mem_max > 70.0 { "font-family: var(--mono); font-size: 10px; color: var(--warm); font-weight: 600;" } else { "font-family: var(--mono); font-size: 10px; color: var(--mute);" }) {
                        (tr(lang, "max ", "макс ")) (format!("{mem_max:.0}%"))
                        @if mem_max > 70.0 { " ⚠" }
                        " · " (mem_used_pct_series.len()) " " (tr(lang, "samples", "точек"))
                    }
                }
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "sing-box log MiB", "sing-box лог MiB"))
                    }
                    (super::dashboard::sparkline_svg_scaled(&log_mib_series, 280, 60, None, false))
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                        (tr(lang, "max ", "макс ")) (format!("{log_max:.0} MiB"))
                        " · " (log_mib_series.len()) " " (tr(lang, "samples", "точек"))
                    }
                }
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin-top: 6px;" {
                "(" (n_samples) " " (tr(lang, "probe ticks in the window", "тиков probe в окне"))  ")"
            }
        }
    }
}

fn server_detail_live_activity_section(
    activity: &vpnctl_inventory::ServerLiveActivity,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let last_seen_str = activity
        .last_sample_ts
        .map(format_msk_iso)
        .unwrap_or_else(|| tr(lang, "never", "никогда").to_string());
    let total_bytes = activity
        .bytes_up_window
        .saturating_add(activity.bytes_dn_window);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Live activity · last 24h", "Живая активность · 24 часа"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Server-wide totals from this node's clash-api (5-minute tick). Numbers reflect actual VPN traffic — VLESS, TUIC, Trojan auth all summed. AmneziaWG / wgturn are kernel-level and not visible to clash-api, so they're NOT counted here. ",
                "Сервер-агрегатные показатели из clash-api ноды (тик 5 минут). Числа отражают реальный VPN-трафик — VLESS, TUIC, Trojan сложены вместе. AmneziaWG / wgturn — kernel-уровень, не видны clash-api, поэтому НЕ учитываются.",
            ))
        }
        div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 12px 0 8px;" {
            div title=(tr(lang, "Active connections from the freshest clash-api snapshot (5-min tick). Includes all auth-bearing connections sing-box currently holds open.", "Активные соединения из самого свежего snapshot clash-api (тик 5 минут). Включает все авторизованные соединения, которые sing-box сейчас держит открытыми.")) {
                (status_tile(tr(lang, "active now", "активных сейчас"), &activity.active_now.to_string(), "var(--ink)"))
            }
            div title=(tr(lang, "Total bytes (upload + download) summed across every clash-api tick in the last 24 hours.", "Всего байт (upload + download), сумма по всем тикам clash-api за последние 24 часа.")) {
                (status_tile(tr(lang, "total 24h", "всего 24ч"), &humanize_bytes(total_bytes), "var(--ink)"))
            }
            div title=(tr(lang, "Upload bytes (client → server) over the last 24 hours.", "Upload-байт (клиент → сервер) за последние 24 часа.")) {
                (status_tile(tr(lang, "upload 24h", "upload 24ч"), &humanize_bytes(activity.bytes_up_window), "var(--ink)"))
            }
            div title=(tr(lang, "Download bytes (server → client) over the last 24 hours.", "Download-байт (сервер → клиент) за последние 24 часа.")) {
                (status_tile(tr(lang, "download 24h", "download 24ч"), &humanize_bytes(activity.bytes_dn_window), "var(--ink)"))
            }
        }
        // Last-sample line + NM-11 attribution badge — making the
        // upstream limit explicit instead of silently absent.
        p style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 4px 0 14px;" {
            (tr(lang, "last poll: ", "последний поллинг: "))
            b style="color: var(--ink);" { (last_seen_str) }
            " · "
            (activity.distinct_users_attributed)
            (tr(lang, " users attributed (NM-11: sing-box upstream strips per-user from clash-api; server-wide totals work)", " юзеров attributed (NM-11: sing-box upstream удаляет per-user из clash-api; сервер-агрегатные totals работают)"))
        }
    }
}

/// Traffic accounting — NIC ground-truth vs clash-attributed vs the GAP.
/// The NIC total catches ALL protocols (the operator's reconciliation
/// with the hoster's billing); the gap is the slice vpnctl can't yet
/// break down per-user (non-sing-box protocols + protocol overhead).
/// Empty-state until ≥2 NIC probe samples exist (a delta needs two).
fn server_detail_gap_section(
    t: &vpnctl_inventory::TrafficBreakdown,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if t.nic_samples < 2 {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { (tr(lang, "Traffic accounting · last 24h", "Учёт трафика · 24 часа")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "No NIC ground-truth yet — the node probe captures interface byte counters every ~10 minutes; come back after a couple of probes.",
                    "Пока нет данных NIC — probe ноды снимает байт-счётчики интерфейса каждые ~10 минут; вернись через пару проверок.",
                ))
            }
        };
    }
    // Gap as a share of real traffic — how much vpnctl can't attribute.
    let gap_pct = t
        .gap_bytes
        .saturating_mul(100)
        .checked_div(t.nic_total_bytes)
        .unwrap_or(0)
        .min(100);
    // A big gap (≥50%) is a real blind spot → accent it.
    let gap_colour = if gap_pct >= 50 {
        "var(--acc)"
    } else {
        "var(--ink)"
    };
    let iface = t.nic_iface.as_deref().unwrap_or("?").to_string();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Traffic accounting · last 24h", "Учёт трафика · 24 часа")) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Real interface traffic (NIC ground-truth — catches ALL protocols, reconciles with the hoster) vs the sing-box part clash-api could attribute. The GAP is everything clash-api can't see: non-sing-box protocols (naive/Caddy, dns-tunnel, wgturn) plus TLS/QUIC overhead.",
                "Реальный трафик интерфейса (NIC — ловит ВСЕ протоколы, сходится с хостером) против sing-box-части, которую смог атрибутировать clash-api. ГЭП — всё, что clash-api не видит: не-sing-box протоколы (naive/Caddy, dns-tunnel, wgturn) плюс оверхед TLS/QUIC.",
            ))
        }
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 8px;" {
            div title=(tr(lang, "Total bytes (rx+tx) on the node's default-route interface over 24h, summed from the probe's cumulative counters. This is the real traffic — every protocol, plus overhead.", "Всего байт (rx+tx) на default-route интерфейсе ноды за 24ч, сумма дельт кумулятивных счётчиков probe. Это реальный трафик — все протоколы плюс оверхед.")) {
                (status_tile(tr(lang, "NIC total", "NIC всего"), &humanize_bytes(t.nic_total_bytes), "var(--ink)"))
            }
            div title=(tr(lang, "Bytes clash-api attributed to sing-box protocols (VLESS/REALITY, TUIC, hy2, Trojan, …) over 24h — the part vpnctl can break down per-user.", "Байт, которые clash-api атрибутировал sing-box-протоколам (VLESS/REALITY, TUIC, hy2, Trojan…) за 24ч — часть, которую vpnctl раскладывает по юзерам.")) {
                (status_tile(tr(lang, "sing-box (attributed)", "sing-box (атриб.)"), &humanize_bytes(t.attributed_bytes), "var(--ink)"))
            }
            div title=(tr(lang, "NIC total minus the attributed part: non-sing-box protocols (naive/Caddy, dns-tunnel, wgturn) + protocol/OS overhead. This is what vpnctl currently can't see per-user.", "NIC всего минус атрибутированное: не-sing-box протоколы (naive/Caddy, dns-tunnel, wgturn) + оверхед протокола/ОС. Это то, что vpnctl сейчас не видит по юзерам.")) {
                (status_tile(tr(lang, "GAP (unattributed)", "ГЭП (неатриб.)"), &humanize_bytes(t.gap_bytes), gap_colour))
            }
        }
        p style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 4px 0 14px;" {
            (tr(lang, "interface ", "интерфейс "))
            b style="color: var(--ink);" { (iface) }
            " · "
            (tr(lang, "gap ", "гэп "))
            b style=(format!("color: {gap_colour};")) { (gap_pct) "%" }
            (tr(lang, " of real traffic not attributed per-user", " реального трафика не разложено по юзерам"))
            " · rx " (humanize_bytes(t.nic_rx_bytes))
            " · tx " (humanize_bytes(t.nic_tx_bytes))
        }
    }
}

/// Phase 4c — per-connection drill-down for the server-detail page.
/// Renders three views from the last clash-api snapshot:
///   1. Top destinations by bytes (host or IP:port)
///   2. Top source IPs (= per-device proxy) with user_id
///      correlation from sub_access_log
///   3. TCP / UDP / other network split
///
/// Empty-state (no snapshot yet) explains that the poller fires
/// every 5 minutes and tells the operator to come back. No
/// «restart vpnctld» / SSH instructions per operator-action policy.
fn server_detail_live_connections_section(
    server_snap: Option<&crate::snapshot_cache::ServerSnapshot>,
    source_user_map: &std::collections::HashMap<String, Vec<(vpnctl_core::UserId, u64)>>,
    dns_ptr_map: &std::collections::HashMap<String, Option<String>>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use crate::snapshot_cache::{aggregate_by_destination, aggregate_by_source, network_breakdown};
    const TOP_N: usize = 10;

    let Some(server_snap) = server_snap else {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { (tr(lang, "Live connections", "Активные соединения")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "No clash-api snapshot for this server yet. The poller fires every 5 minutes; refresh after the next tick. Empty also if the deploy key isn't authorised on this node (see Settings → Deploy SSH key).",
                    "Снимка clash-api по этому серверу ещё нет. Поллер запускается каждые 5 минут; обнови после следующего тика. Также пусто если deploy-ключ ещё не авторизован на этой ноде (см. Settings → Deploy SSH key).",
                ))
            }
        };
    };

    let snap = &server_snap.snapshot;
    let nb = network_breakdown(snap);
    let top_dests = aggregate_by_destination(snap, TOP_N, dns_ptr_map);
    let top_sources = aggregate_by_source(snap, TOP_N);
    let total_conns = snap.connections.len();

    // For each top-source aggregate, surface the user_id behind that
    // source IP, taken from the connections' `metadata.user` (emitted by
    // our patched sing-box clash-api). If several users share one IP (NAT
    // collision), pick the one with the most connections — the
    // most-active device behind the NAT.
    use std::collections::HashMap as StdHashMap;
    let mut ip_to_log_user: StdHashMap<&str, StdHashMap<&str, u32>> = StdHashMap::new();
    for c in &snap.connections {
        if let Some(user) = c.metadata.user.as_deref() {
            if !c.metadata.source_ip.is_empty() {
                *ip_to_log_user
                    .entry(c.metadata.source_ip.as_str())
                    .or_default()
                    .entry(user)
                    .or_insert(0) += 1;
            }
        }
    }
    // Resolve each IP → top user_id (highest port count).
    let log_ip_winner: StdHashMap<&str, &str> = ip_to_log_user
        .iter()
        .filter_map(|(ip, users)| {
            users
                .iter()
                .max_by_key(|(_, cnt)| **cnt)
                .map(|(user, _)| (*ip, *user))
        })
        .collect();

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Live connections", "Активные соединения"))
            span style="color: var(--mute); margin-left: 12px; font-family: var(--mono); font-size: 11px; letter-spacing: 0;" {
                "· " (total_conns) " "
                (tr(lang, "connections in the last 5-min snapshot", "соединений в последнем 5-минутном снимке"))
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Per-connection detail from clash-api. NM-11 (sing-box upstream) drops the `user` field on the wire, so we attribute connections to users via the source-IP ↔ subscription-fetch IP correlation (last 7 days). Best-effort — accuracy drops for NAT collisions.",
                "Деталь per-connection из clash-api. NM-11 (sing-box upstream) убирает поле `user` из wire-формата, поэтому атрибуция идёт через корреляцию source IP ↔ IP запроса подписки (последние 7 дней). Best-effort — точность падает при коллизии NAT.",
            ))
        }
        // Network breakdown row.
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 18px;" {
            (status_tile(
                tr(lang, "tcp", "tcp"),
                &format!("{} · {}", nb.tcp_conns, humanize_bytes(nb.tcp_bytes)),
                "var(--ink)",
            ))
            (status_tile(
                tr(lang, "udp", "udp"),
                &format!("{} · {}", nb.udp_conns, humanize_bytes(nb.udp_bytes)),
                "var(--ink)",
            ))
            (status_tile(
                tr(lang, "other", "иные"),
                &format!("{} · {}", nb.other_conns, humanize_bytes(nb.other_bytes)),
                "var(--ink)",
            ))
        }

        // Top destinations table.
        h4 style="font-family: var(--mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin: 16px 0 6px;" {
            (tr(lang, "top destinations · this snapshot", "топ destinations · этот снимок"))
        }
        @if top_dests.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(lang, "no active connections", "активных соединений нет"))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; margin-bottom: 18px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "host / ip", "host / ip"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "conns", "соед."))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "upload", "upload"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "download", "download"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "total", "всего"))
                        }
                    }
                }
                tbody {
                    @for d in &top_dests {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 4px 8px; overflow-wrap: anywhere;" { (d.label) }
                            td style="padding: 4px 8px; text-align: right;" { (d.conns) }
                            td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(d.upload)) }
                            td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(d.download)) }
                            td style="padding: 4px 8px; text-align: right; font-weight: 500;" { (humanize_bytes(d.upload.saturating_add(d.download))) }
                        }
                    }
                }
            }
        }

        // Top source IPs table — with user correlation.
        h4 style="font-family: var(--mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin: 16px 0 6px;" {
            (tr(lang, "top sources · this snapshot · likely user", "топ source IP · этот снимок · вероятный юзер"))
        }
        @if top_sources.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(lang, "no active source IPs", "активных source IP нет"))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "source ip", "source ip"))
                        }
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;"
                           title=(tr(lang, "Most-likely user_id based on which user has hit subscription URL from this IP in the last 7 days (sub_access_log JOIN). «—» = no match.", "Наиболее вероятный user_id на основе того, какой юзер за последние 7 дней дёргал subscription URL с этого IP (JOIN на sub_access_log). «—» = совпадений нет.")) {
                            (tr(lang, "likely user", "вероятный юзер"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "conns", "соед."))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "upload", "upload"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "download", "download"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "total", "всего"))
                        }
                    }
                }
                tbody {
                    @for s in &top_sources {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 4px 8px;" { (s.label) }
                            td style="padding: 4px 8px;" {
                                // Phase 4d — log-derived attribution
                                // wins (exact match from sing-box
                                // accept logs). Phase 4c sub_access
                                // correlation is the fallback for
                                // connections older than the log tail.
                                @if let Some(log_user) = log_ip_winner.get(s.label.as_str()) {
                                    a href=(format!("/admin/users/{}", crate::http_util::path_segment_encode(log_user)))
                                      style="color: var(--ink); text-decoration: none; border-bottom: 1px solid var(--ink);"
                                      title=(tr(
                                          lang,
                                          "Matched from VPN server log — this user authenticated from that IP.",
                                          "Совпадение из лога VPN-сервера — этот юзер аутентифицировался с этого IP.",
                                      )) {
                                        (*log_user)
                                    }
                                    span style="color: var(--mute); margin-left: 6px; font-size: 10px;"
                                         title=(tr(lang, "Source: VPN server log. Direct, high-confidence match.", "Источник: лог VPN-сервера. Прямое сопоставление с высокой точностью.")) {
                                        (tr(lang, "log", "лог"))
                                    }
                                } @else if let Some(users) = source_user_map.get(&s.label) {
                                    @if !users.is_empty() {
                                        @let (top_uid, top_hits) = &users[0];
                                        a href=(format!("/admin/users/{}", crate::http_util::path_segment_encode(&top_uid.0)))
                                          style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--rule);"
                                          title=(tr(
                                              lang,
                                              "Best-guess match — this user fetched their subscription URL from this IP in the last 7 days.",
                                              "Предположительное совпадение — этот юзер запрашивал свою подписку с этого IP за последние 7 дней.",
                                          )) {
                                            (top_uid.0)
                                        }
                                        span style="color: var(--mute); margin-left: 6px; font-size: 10px;"
                                             title=(format!(
                                                "{} ({} {})",
                                                tr(lang, "Source: subscription fetches over the last 7 days. Best-guess (NAT can collide).", "Источник: запросы подписки за 7 дней. Эвристика (NAT может коллидировать)."),
                                                top_hits,
                                                tr(lang, "fetches from this IP", "запросов с этого IP"),
                                             )) {
                                            (tr(lang, "sub", "подп"))
                                        }
                                        @if users.len() > 1 {
                                            span style="color: var(--mute); margin-left: 6px;" {
                                                "+" (users.len() - 1) " "
                                                (tr(lang, "more", "ещё"))
                                            }
                                        }
                                    } @else {
                                        span style="color: var(--mute);"
                                             title=(tr(lang, "No match in VPN server log and no recent subscription fetch from this IP.", "Нет совпадения в логе VPN-сервера и нет недавних запросов подписки с этого IP.")) {
                                            "—"
                                        }
                                    }
                                } @else {
                                    span style="color: var(--mute);"
                                         title=(tr(lang, "No match in VPN server log and no recent subscription fetch from this IP.", "Нет совпадения в логе VPN-сервера и нет недавних запросов подписки с этого IP.")) {
                                        "—"
                                    }
                                }
                            }
                            td style="padding: 4px 8px; text-align: right;" { (s.conns) }
                            td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(s.upload)) }
                            td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(s.download)) }
                            td style="padding: 4px 8px; text-align: right; font-weight: 500;" { (humanize_bytes(s.upload.saturating_add(s.download))) }
                        }
                    }
                }
            }
        }
    }
}

/// Drift section — what does inventory THINK is listening vs what
/// IS listening. Orange highlights when sets disagree.
/// Kernels editor — one row per kernel registered in the registry,
/// with enable/disable form. Mirrors the protocols section directly
/// below it. Per CLAUDE.md architectural principle (Kernel ×
/// Protocol orthogonality), adding a new kernel here is the first
/// step before enabling protocols that only that kernel supports
/// (e.g. amneziawg → then wireguard).
fn server_detail_kernels_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let enabled: std::collections::HashSet<&vpnctl_core::KernelId> =
        server.kernels.iter().collect();
    let mut all_kernels = registry.kernel_ids();
    all_kernels.sort_by(|left, right| {
        kernel_priority(&left.0)
            .cmp(&kernel_priority(&right.0))
            .then_with(|| left.0.cmp(&right.0))
    });
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Kernels", "Ядра")) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 8px;" {
            (tr(
                lang,
                "Daemons running on this node. One physical VPS can host multiple (sing-box on 443/TCP + amneziawg on 51820/UDP cohabit cleanly).",
                "Демоны, работающие на этой ноде. Один физический VPS может держать несколько (sing-box на 443/TCP + amneziawg на 51820/UDP уживаются нормально).",
            ))
        }
        div style="padding: 8px 12px; margin: 0 0 12px; background: var(--paper); border-left: 3px solid var(--accent); font-family: var(--serif); font-size: 12px; line-height: 1.5;" {
            b style="color: var(--accent); font-family: var(--mono); letter-spacing: 0.1em; text-transform: uppercase; font-size: 11px;" {
                (tr(
                    lang,
                    "⚠ toggle here = inventory only",
                    "⚠ тогл здесь = только инвентарь",
                ))
            }
            (tr(
                lang,
                " — the live node sees the change only after you click ",
                " — живая нода увидит изменение только после клика по ",
            ))
            a href="#deploy-button"
              style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none; font-weight: 500;" {
                span.ed-mono { (tr(lang, "deploy →", "деплой →")) }
            }
            (tr(
                lang,
                " at the top of this page. We never SSH-push a config without an explicit operator click (no surprise redeploys).",
                " вверху страницы. Мы никогда не пушим конфиг через SSH без явного клика оператора (без сюрпризов-redeploy).",
            ))
        }
        ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.8;" {
            @for kid in &all_kernels {
                @let is_on = enabled.contains(kid);
                @let supported = registry.kernel(kid)
                    .map(|k| k.supported_protocols()
                        .into_iter()
                        .map(|p| p.0)
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_default();
                li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                    span style="flex: 1;" {
                        (kid.0)
                        " "
                        span style="font-size: 10px; color: var(--mute); font-style: italic; font-family: var(--serif);" {
                            (tr(lang, "(runs: ", "(крутит: ")) (supported) ")"
                        }
                    }
                    @if is_on {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                            (tr(lang, "✓ on", "✓ вкл"))
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/kernels/{}/disable", sid_enc, path_segment_encode(&kid.0)))
                             style="margin: 0; padding: 0;" {
                            @let dis_title = match lang {
                                crate::i18n::Locale::En => format!("Remove {} from {}.kernels. Takes effect on next deploy.", kid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Убрать {} из {}.kernels. Применится при следующем деплое.", kid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(dis_title)
                                   class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                                (crate::i18n::t(lang, crate::i18n::K::BtnDisable))
                            }
                        }
                    } @else {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-right: 4px;" {
                            "—"
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/kernels/{}/enable", sid_enc, path_segment_encode(&kid.0)))
                             style="margin: 0; padding: 0;" {
                            @let en_title = match lang {
                                crate::i18n::Locale::En => format!("Add {} to {}.kernels. Takes effect on next deploy.", kid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Добавить {} в {}.kernels. Применится при следующем деплое.", kid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(en_title)
                                   class="ed-abtn ed-abtn--sm" {
                                (crate::i18n::t(lang, crate::i18n::K::BtnEnable))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Enabled-protocols editor — one row per protocol registered in the
/// registry, each with a `[on|off]` form that toggles the (server,
/// Trusted host SSH fingerprint section — shows current pinned
/// fingerprint (if any) plus a form for the operator to set / replace
/// it. Two paths:
///   * paste a `SHA256:…` literal (when the operator already has it),
///   * "Auto-detect" button → POST that runs `ssh-keyscan +
///     ssh-keygen -lf -` server-side, pins the resulting fingerprint.
///
/// Both go to the same `POST /admin/servers/{id}/set-fingerprint`
/// route; the form's hidden `mode=keyscan` differentiates.
/// Phase G chunk 3.5 follow-up — «Push deploy key» recovery action.
///
/// The Phase E wizard at `/admin/servers/new` does this automatically
/// as step 3 of bootstrap (sshpass + `mkdir -p ~/.ssh && grep -qxF ||
/// echo ... >>`). But three operator paths leave a server in
/// inventory WITHOUT the daemon's pubkey on it:
///
///   * **migrate-from-bash** — imported pre-existing servers that
///     have their own SSH key infra, daemon's key never pushed
///   * **quick-add** (`POST /admin/servers`) — minimal form, only
///     id + address + port; no password field, no push
///   * **wizard failure mid-flow** — bootstrap got past step 1-2
///     but failed before step 3 completed (rare)
///
/// All three leave Pavel with the «open a terminal + ssh root@…
/// + paste the pubkey» chore. This section makes it a single click
/// + paste-password instead.
///
/// Reuses `wizard_bootstrap::ssh_password_run` so the actual remote
/// command is byte-identical to what the wizard runs (idempotent
/// `grep -qxF || echo >>` — re-clicking after success is safe).
fn server_detail_push_deploy_key_section(
    server: &vpnctl_core::Server,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let reference_key = std::env::var("VPNCTLD_REFERENCE_SSH_KEY").ok();
    let reference_ok = reference_key
        .as_ref()
        .is_some_and(|p| std::path::Path::new(p).exists());
    html! {
        div.ed-rule {}
        div #push-deploy-key.ed-art-eyebrow {
            (tr(lang, "Deploy SSH key — push to this server", "Deploy SSH-ключ — запушить на этот сервер"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px; max-width: 760px;" {
            (tr(lang, "Daemon needs its pubkey on this server's ", "Демону нужен его pubkey в "))
            span.ed-mono { "~/.ssh/authorized_keys" }
            (tr(
                lang,
                " before probes, deploys, or the Telegram via-server proxy can work. The Phase E wizard at ",
                " этого сервера, иначе не работают probe-ы, деплои и Telegram via-server прокси. Мастер Phase E на ",
            ))
            span.ed-mono { "/admin/servers/new" }
            (tr(lang, " does this automatically. For servers added via ", " делает это автоматически. Для серверов добавленных через "))
            span.ed-mono { "quick-add" } " / " span.ed-mono { "migrate-from-bash" }
            (tr(
                lang,
                " (or when the wizard's push step failed), use this form. Idempotent — re-clicking after success is a no-op.",
                " (или если шаг push мастера упал), используй эту форму. Идемпотентно — повторный клик после успеха ничего не делает.",
            ))
        }

        @if reference_ok {
            p style="font-family: var(--mono); font-size: 11px; color: var(--ink); margin: 0 0 12px; padding: 8px 12px; background: var(--paper); border-left: 3px solid var(--acc); max-width: 760px;" {
                "✓ " b { (tr(lang, "reference SSH key configured", "reference SSH-ключ настроен")) }
                " (" span.ed-mono { (reference_key.as_deref().unwrap_or("")) } "). "
                (tr(lang, "Click ", "Клик "))
                b { (tr(lang, "push deploy key", "запушить deploy-ключ")) }
                (tr(
                    lang,
                    " with password EMPTY — daemon will use the reference key for a silent push. If that key isn't authorised on this specific server, fill in the password to fall back to sshpass.",
                    " с ПУСТЫМ паролем — демон использует reference-key для тихого push. Если этот ключ не авторизован на конкретно этом сервере — заполни пароль для fallback через sshpass.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 12px; max-width: 760px;" {
                (tr(lang, "Tip: set ", "Подсказка: задай ")) span.ed-mono { "VPNCTLD_REFERENCE_SSH_KEY=/path/to/operator_key" }
                (tr(lang, " in the daemon's ", " в "))
                span.ed-mono { "/etc/vpnctl/vpnctld.env" }
                (tr(
                    lang,
                    " (then restart vpnctld) to skip the password input on future pushes — useful when an operator key (claude-dev, etc) is already authorised on every server.",
                    " демона (затем перезапусти vpnctld) — это позволит обходить ввод пароля на будущих push'ах, удобно когда operator-ключ (claude-dev и т.п.) уже авторизован на каждом сервере.",
                ))
            }
        }

        form method="post"
             action=(format!("/admin/servers/{sid_enc}/push-deploy-key"))
             style="margin: 0 0 14px;" {
            div style="display: grid; grid-template-columns: 140px 1fr; gap: 10px 14px; align-items: center; max-width: 560px;" {
                label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (tr(lang, "root password", "root-пароль"))
                }
                // R2: short placeholder (the old sentence truncated
                // mid-word in the 400px field); full rules in `title`.
                input type="password"
                      name="root_password"
                      autocomplete="off"
                      placeholder=(if reference_ok {
                          tr(lang, "blank = reference key", "пусто = reference-key")
                      } else {
                          tr(lang, "never stored", "не сохраняется")
                      })
                      title=(if reference_ok {
                          tr(
                              lang,
                              "Leave blank to authenticate with the reference key; fill in to force the sshpass fallback. Used once for the SSH connect, then discarded — never stored, never logged.",
                              "Пусто — аутентификация reference-ключом; заполни, чтобы форсировать sshpass-fallback. Используется один раз для SSH-коннекта и отбрасывается — не хранится и не логируется.",
                          )
                      } else {
                          tr(
                              lang,
                              "Used once for the SSH connect, then discarded — never stored, never logged.",
                              "Используется один раз для SSH-коннекта и отбрасывается — не хранится и не логируется.",
                          )
                      })
                      style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";
            }
            div style="margin-top: 12px;" {
                button type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           // Honest copy (audit 2026-06-10): with the
                           // password filled the handler goes straight
                           // to sshpass — the reference key is tried
                           // ONLY when the password field is empty.
                           "Append the daemon's deploy pubkey to ~/.ssh/authorized_keys on this server. With the password filled it connects via sshpass; leave the password empty to use the configured reference key instead.",
                           "Добавить deploy-pubkey демона в ~/.ssh/authorized_keys на этом сервере. С заполненным паролем подключается через sshpass; оставь пароль пустым, чтобы использовать настроенный reference-key.",
                       ))
                       class="ed-abtn ed-abtn--recovery ed-abtn--lg" {
                    (crate::i18n::tr(lang, "push deploy key", "запушить deploy-ключ"))
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 14px;" {
                    (crate::i18n::tr(lang, "Connects to ", "Подключение к "))
                    span.ed-mono { (server.ssh_user) "@" (server.address) ":" (server.ssh_port) }
                }
            }
        }
    }
}

fn server_detail_fingerprint_section(
    server: &vpnctl_core::Server,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let sid_enc = path_segment_encode(&server.id.0);
    let current = server.trusted_host_fingerprint.clone();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "The SHA-256 of the node's SSH host public key, pinned in the inventory. Every SSH-using subsystem (deploy, probe, clash-poller) verifies the live key matches before sending any secrets — protects against MITM if someone hijacks the IP.",
                "SHA-256 публичного SSH-ключа ноды, закреплённый в инвентаре. Все подсистемы которые используют SSH (деплой, probe, clash-poller) проверяют что live-ключ совпадает прежде чем посылать секреты — защита от MITM если кто-то перехватит IP.",
            )) {
            (t(lang, K::EyebrowTrustedFingerprint))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            // Honest copy (audit 2026-06-10): the daemon's SSH transport
            // uses `StrictHostKeyChecking=accept-new` + its own
            // known_hosts and does NOT read this pin — daemon-side the
            // pin only feeds the fingerprint-drift WARNING alert
            // (health_monitor::check_fingerprint_drift). Hard refusal
            // happens only on the CLI deploy path (russh
            // `trusted_fingerprint`). The old copy claimed every
            // pipeline refuses on mismatch.
            (tr(
                lang,
                "Pinned SHA-256 of the node's SSH ed25519 host key. The CLI deploy refuses a host whose live key doesn't match; the daemon's pipelines (web deploy / probe / clash-poller) verify against their own known_hosts and use this pin to raise a fingerprint-drift warning alert — ",
                "Закреплённый SHA-256 хост-ключа ed25519 ноды. CLI-деплой отказывается работать с хостом, чей live-ключ не совпадает; пайплайны демона (web-деплой / probe / clash-poller) сверяются со своим known_hosts, а по этому пину поднимают warning-алерт о дрейфе отпечатка — ",
            ))
            span title=(tr(
                lang,
                "Trust-On-First-Use: accept whatever host key the node presents the first time, refuse changes afterwards. Standard SSH posture; same model `~/.ssh/known_hosts` uses.",
                "Trust-On-First-Use: принять любой host-ключ который нода предъявляет в первый раз, затем отказываться от смены. Стандартная SSH-модель; так же как `~/.ssh/known_hosts`.",
            )) {
                (tr(lang, "TOFU pin", "TOFU-pin"))
            }
            (tr(
                lang,
                ", set once. Update only if the node was legitimately rebuilt (and re-confirm via console).",
                ", задаётся один раз. Обновляй только если нода была легитимно пересоздана (и сверь через console).",
            ))
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin-bottom: 12px;" {
            @match &current {
                Some(fp) => { (tr(lang, "current: ", "текущий: ")) (fp) }
                None => {
                    em style="color: var(--mute);" {
                        (tr(
                            lang,
                            "(no fingerprint pinned — first SSH connection will TOFU-accept whatever the host presents)",
                            "(отпечаток не закреплён — первый SSH-коннект TOFU-примет то, что хост предъявит)",
                        ))
                    }
                }
            }
        }
        div style="display: flex; flex-direction: column; gap: 10px;" {
            form method="post"
                 action=(format!("/admin/servers/{sid_enc}/set-fingerprint"))
                 style="display: flex; gap: 8px; align-items: center;" {
                input type="hidden" name="mode" value="keyscan";
                button type="submit"
                       title=(tr(
                           lang,
                           "Run ssh-keyscan + ssh-keygen -lf - on the daemon host, pin the resulting fingerprint.",
                           "Запустить ssh-keyscan + ssh-keygen -lf - на хосте демона и закрепить полученный отпечаток.",
                       ))
                       class="ed-abtn ed-abtn--recovery ed-abtn--lg" {
                    (tr(lang, "auto-detect via ssh-keyscan →", "автоопределить через ssh-keyscan →"))
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                    (tr(lang, "(daemon will SSH-keyscan ", "(демон сделает ssh-keyscan "))
                    span.ed-mono { (server.address) ":" (server.ssh_port) }
                    (tr(lang, " and pin the SHA-256)", " и закрепит SHA-256)"))
                }
            }
            form method="post"
                 action=(format!("/admin/servers/{sid_enc}/set-fingerprint"))
                 style="display: flex; gap: 8px; align-items: center;" {
                input type="hidden" name="mode" value="manual";
                input type="text" name="fingerprint" placeholder="SHA256:..."
                      style="flex: 1; padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);"
                      pattern="SHA256:[A-Za-z0-9+/=_-]{1,44}"
                      title="SHA256:<43-char-base64>";
                button type="submit"
                       title=(tr(
                           lang,
                           "Save the SHA256 fingerprint you pasted above as the trusted host key for this server (TOFU pin). Future SSH connections refuse if the node presents a different key — protects against MITM after the initial trust.",
                           "Сохранить вставленный выше SHA256-отпечаток как доверенный host-ключ для этого сервера (TOFU pin). Будущие SSH-коннекты откажутся если нода предъявит другой ключ — защита от MITM после первичного доверия.",
                       ))
                       style="padding: 4px 12px; border: 1px solid var(--ink); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (tr(lang, "pin manually", "закрепить вручную"))
                }
            }
        }
    }
}

/// Display-name section on the server-detail page (migration 0029).
/// `current` is the operator-set `servers.display_name` (None = unset).
/// Lets the operator pin the friendly `{Country}` label end users see in
/// their client's server list — blank clears it back to the built-in
/// ISO-code→country map, then the uppercased id. Web equivalent of an
/// otherwise-unsettable field (there's no CLI for it yet).
/// Naive (Caddy + forwardproxy) per-server config. The operator sets
/// `naive.domain` + `naive.acme_email` (server_secrets) that the caddy
/// kernel renders into the Caddyfile and Caddy's built-in ACME uses to
/// mint the Let's Encrypt cert. Rendered ONLY when the `naive` protocol
/// is enabled on this server (empty markup otherwise). Carries the
/// prerequisite reminder vpnctl CANNOT satisfy for the operator: a DNS
/// A-record pointing here + open TCP 80/443.
fn server_detail_naive_config_section(
    server: &vpnctl_core::Server,
    server_secrets: &std::collections::HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server.enabled_protocols.iter().any(|p| p.0 == "naive") {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let domain = server_secrets
        .get("naive.domain")
        .map(String::as_str)
        .unwrap_or("");
    let email = server_secrets
        .get("naive.acme_email")
        .map(String::as_str)
        .unwrap_or("");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "Caddy + forwardproxy serves a real cover website (HTTP 200) to probes and tunnels authenticated clients. Domain + email feed Caddy's built-in ACME (Let's Encrypt).",
                "Caddy + forwardproxy отдаёт настоящий сайт-прикрытие (HTTP 200) зондам и туннелирует аутентифицированных клиентов. Домен + почта идут во встроенный ACME Caddy (Let's Encrypt).")) {
            (tr(lang, "NAIVE (CADDY) CONFIG", "КОНФИГ NAIVE (CADDY)"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 10px;" {
            (tr(lang,
                "Before deploy: point a DNS A-record at this server and open TCP 80+443 — Caddy's ACME needs both. vpnctl can't do DNS for you.",
                "До деплоя: направь DNS A-запись на этот сервер и открой TCP 80+443 — встроенному ACME Caddy нужны оба. DNS vpnctl за тебя не сделает."))
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/naive-config"))
             style="display: grid; grid-template-columns: 96px 1fr; gap: 6px 8px; align-items: center; max-width: 520px;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "domain", "домен"))
            }
            input type="text" name="domain" maxlength="253" required
                  value=(domain)
                  placeholder="cdn.example.com"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "ACME email", "ACME почта"))
            }
            input type="text" name="acme_email" maxlength="254"
                  value=(email)
                  placeholder="admin@example.com"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            span {}
            button type="submit"
                   title=(tr(lang, "Save naive domain + ACME email", "Сохранить домен naive + ACME почту"))
                   style="justify-self: start; padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "save naive config", "сохранить конфиг"))
            }
        }
    }
}

/// vless-ws (Caddy + reverse_proxy) per-server config. The operator sets
/// `vlessws.domain` + `vlessws.acme_email` + `vlessws.listen_port`
/// (server_secrets); the secret ws path (`vlessws.path`) is auto-minted at
/// deploy, so there's no field for it. Rendered ONLY when the `vless-ws`
/// protocol is enabled on this server. Carries the prerequisite reminder
/// vpnctl CANNOT satisfy: a DNS A-record pointing here + open TCP 80 (ACME)
/// and the front port.
fn server_detail_vlessws_config_section(
    server: &vpnctl_core::Server,
    server_secrets: &std::collections::HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server.enabled_protocols.iter().any(|p| p.0 == "vless-ws") {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let domain = server_secrets
        .get("vlessws.domain")
        .map(String::as_str)
        .unwrap_or("");
    let email = server_secrets
        .get("vlessws.acme_email")
        .map(String::as_str)
        .unwrap_or("");
    let port = server_secrets
        .get("vlessws.listen_port")
        .map(String::as_str)
        .unwrap_or("");
    // Whether the secret ws path has been minted yet (deploy mints it).
    let path_minted = server_secrets.contains_key("vlessws.path");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "Caddy terminates a real Let's-Encrypt cert on the front port, serves a decoy site at /, and reverse_proxies one secret path to a loopback sing-box VLESS+ws inbound. DIRECT (no CDN) — the RU-DPI-resistant, client-universal fallback that runs alongside REALITY on :443.",
                "Caddy терминирует настоящий сертификат Let's-Encrypt на фронт-порту, отдаёт сайт-приманку на /, и reverse_proxy одного секретного пути на loopback sing-box VLESS+ws. ПРЯМОЙ (без CDN) — устойчивый к RU-DPI, совместимый со всеми клиентами фолбэк рядом с REALITY на :443.")) {
            (tr(lang, "VLESS-WS (CADDY) CONFIG", "КОНФИГ VLESS-WS (CADDY)"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 10px;" {
            (tr(lang,
                "Before deploy: point a DNS A-record at this server and open TCP 80 (ACME) + the front port. The secret ws path is generated automatically on deploy.",
                "До деплоя: направь DNS A-запись на этот сервер и открой TCP 80 (ACME) + фронт-порт. Секретный ws-путь генерируется автоматически при деплое."))
            @if path_minted {
                (tr(lang, " The path is set.", " Путь задан."))
            } @else {
                (tr(lang, " The path is not minted yet (deploy to generate it).", " Путь ещё не сгенерирован (задеплой, чтобы создать его)."))
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/vlessws-config"))
             style="display: grid; grid-template-columns: 96px 1fr; gap: 6px 8px; align-items: center; max-width: 520px;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "domain", "домен"))
            }
            input type="text" name="domain" maxlength="253" required
                  value=(domain)
                  placeholder="de.ninitux.top"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "front port", "фронт-порт"))
            }
            input type="text" name="listen_port" maxlength="5" inputmode="numeric"
                  value=(port)
                  placeholder="8443"
                  title=(tr(lang, "Public TLS port Caddy serves on — NOT 443 (REALITY owns that). Blank = 8443.", "Публичный TLS-порт Caddy — НЕ 443 (его занимает REALITY). Пусто = 8443."))
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "ACME email", "ACME почта"))
            }
            input type="text" name="acme_email" maxlength="254"
                  value=(email)
                  placeholder="admin@example.com"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            span {}
            button type="submit"
                   title=(tr(lang, "Save vless-ws domain + front port + ACME email", "Сохранить домен vless-ws + фронт-порт + ACME почту"))
                   style="justify-self: start; padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "save vless-ws config", "сохранить конфиг"))
            }
        }
    }
}

/// VLESS+REALITY per-server listen port (`vless.listen_port`). Default 443
/// is the gold-standard cover; on a co-tenant host where something else
/// owns 443 (naive/caddy here, legacy 3x-ui elsewhere) the operator moves
/// reality to an alt port. Rendered ONLY when `vless+reality` is enabled.
/// The value is load-bearing for the firewall step, the port-conflict guard
/// and the drift table above (`effective_listen_ports`), so it gets the
/// same web surface as `vlessws.listen_port` — "web is the ONLY operator
/// surface" (PR #139 review finding 7).
fn server_detail_reality_config_section(
    server: &vpnctl_core::Server,
    server_secrets: &std::collections::HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server
        .enabled_protocols
        .iter()
        .any(|p| p.0 == "vless+reality")
    {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let port = server_secrets
        .get("vless.listen_port")
        .map(String::as_str)
        .unwrap_or("");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "REALITY binds this port directly. Default 443 (gold-standard HTTPS cover); set an alternate port when a co-tenant owns 443 on this host (naive/caddy, legacy 3x-ui). Saving re-validates against every other protocol's port and takes effect on deploy.",
                "REALITY слушает этот порт напрямую. По умолчанию 443 (золотой стандарт HTTPS-маскировки); задай другой порт, если 443 на этом хосте занят со-жителем (naive/caddy, легаси 3x-ui). При сохранении проверяется против портов всех остальных протоколов и вступает в силу при деплое.")) {
            (tr(lang, "VLESS+REALITY CONFIG", "КОНФИГ VLESS+REALITY"))
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/reality-config"))
             style="display: grid; grid-template-columns: 96px 1fr; gap: 6px 8px; align-items: center; max-width: 520px;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "listen port", "порт"))
            }
            input type="text" name="listen_port" maxlength="5" inputmode="numeric"
                  value=(port)
                  placeholder="443"
                  title=(tr(lang, "TCP port REALITY binds. Blank = 443. Must not collide with any other protocol on this node.", "TCP-порт, который слушает REALITY. Пусто = 443. Не должен совпадать с портом другого протокола на этом узле."))
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            span {}
            button type="submit"
                   title=(tr(lang, "Save the REALITY listen port", "Сохранить порт REALITY"))
                   style="justify-self: start; padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "save reality port", "сохранить порт"))
            }
        }
    }
}

fn server_detail_display_name_section(
    server: &vpnctl_core::Server,
    current: Option<&str>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    // What the label resolves to RIGHT NOW (custom → country-map → UPPER),
    // so the operator sees the effective value, not just the override.
    let effective = crate::handlers::vpn_router::server_display_label(&server.id.0, current);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Friendly name end users see in their client's server list — the '{Country}' part of the subscription label (e.g. 'Kyrgyzstan VLESS ~alice'). Blank = fall back to the built-in country map, then the uppercased server id.",
                "Понятное имя, которое пользователь видит в списке серверов клиента — часть '{Country}' в метке подписки (напр. 'Kyrgyzstan VLESS ~alice'). Пусто = фолбэк на встроенную карту стран, затем на server id в верхнем регистре.",
            )) {
            (tr(lang, "DISPLAY NAME", "ОТОБРАЖАЕМОЕ ИМЯ"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
            (tr(lang, "Subscription label clients see: ", "Метка в подписке, которую видят клиенты: "))
            span.ed-mono { (effective) " VLESS ~<user>" }
            @if current.is_none() {
                (tr(lang, " — auto (no custom name set)", " — авто (своё имя не задано)"))
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/display-name"))
             style="display: flex; gap: 8px; align-items: center;" {
            input type="text" name="display_name" maxlength="64"
                  value=(current.unwrap_or(""))
                  placeholder=(tr(lang, "e.g. Kyrgyzstan  (blank = auto)", "напр. Kyrgyzstan  (пусто = авто)"))
                  style="flex: 1; padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            button type="submit"
                   title=(tr(
                       lang,
                       "Save this server's display label. Takes effect on the next subscription pull by each client; cached URIs are unaffected.",
                       "Сохранить отображаемую метку этого сервера. Применится при следующем обновлении подписки у каждого клиента; на кэшированные URI не влияет.",
                   ))
                   style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "save name", "сохранить"))
            }
        }
    }
}

/// Auto-suppress section on the server-detail page (migration 0030).
/// Per-server opt-in to drop this server from the subscription render
/// while it's unreachable: the health monitor sets `suppressed_at` once
/// it crosses the `server.unreachable` threshold (≈30 min of failed
/// probes), and clears it on the first successful probe. Separate from
/// the manual hide (NM-10) so a suppress cycle preserves the operator's
/// per-protocol visibility. Shows the live state + a toggle.
fn server_detail_auto_suppress_section(
    server: &vpnctl_core::Server,
    opt_in: bool,
    suppressed_at: Option<&str>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let (btn_bg, btn_fg) = if opt_in {
        ("transparent", "var(--ink)")
    } else {
        ("var(--ink)", "var(--paper)")
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "When ON, the daemon removes this server from clients' subscriptions after it fails the unreachable threshold (3 consecutive SSH probes ≈ 30 min) and restores it on the first successful probe. OFF (default) = a down server stays in the subscription and clients fall back on their own.",
                "Когда ВКЛ, демон убирает этот сервер из подписок клиентов после порога недоступности (3 неудачные SSH-пробы подряд ≈ 30 мин) и возвращает при первой успешной пробе. ВЫКЛ (по умолчанию) = упавший сервер остаётся в подписке, клиенты фолбэкаются сами.",
            )) {
            (tr(lang, "AUTO-SUPPRESS WHEN DOWN", "АВТО-СКРЫТИЕ ПРИ ПАДЕНИИ"))
        }
        @if let Some(ts) = suppressed_at {
            div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--acc); color: var(--acc); margin: 8px 0 12px;" {
                (tr(lang, "● currently SUPPRESSED since ", "● сейчас СКРЫТ с ")) (ts)
                (tr(lang, " — hidden from subscriptions; auto-restores on recovery.", " — скрыт из подписок; вернётся автоматически при восстановлении."))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                @if opt_in {
                    (tr(lang, "Armed — server is currently reachable; will auto-hide if it goes down.", "Взведено — сервер сейчас доступен; авто-скроется если упадёт."))
                } @else {
                    (tr(lang, "Off — a down server stays in the subscription (clients fall back themselves).", "Выкл — упавший сервер остаётся в подписке (клиенты фолбэкаются сами)."))
                }
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/auto-suppress"))
             style="display: inline;" {
            input type="hidden" name="enabled" value=(if opt_in { "false" } else { "true" });
            button type="submit"
                   style=(format!("padding: 4px 12px; border: 1px solid var(--ink); background: {btn_bg}; color: {btn_fg}; font-family: var(--mono); font-size: 11px; cursor: pointer;")) {
                @if opt_in {
                    (tr(lang, "turn off auto-suppress", "выключить авто-скрытие"))
                } @else {
                    (tr(lang, "turn on auto-suppress", "включить авто-скрытие"))
                }
            }
        }
    }
}

/// naive↔HY2 UDP-pairing opt-in on the server-detail page (migration 0031,
/// UX-3). Takes effect only when this server exposes BOTH naive and
/// hysteria2 — the render then stamps both share-links with `pair=<server
/// id>`. Always rendered (discoverable); the copy explains the both-protocols
/// requirement. Single-server only by construction (the tag is the id).
fn server_detail_udp_pair_section(
    server: &vpnctl_core::Server,
    enabled: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let (btn_bg, btn_fg) = if enabled {
        ("transparent", "var(--ink)")
    } else {
        ("var(--ink)", "var(--paper)")
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "When ON, this node's naive AND HY2 share-links carry a shared `pair=<server id>` tag, so a client routes UDP — which naive can't carry — over the HY2 co-located on the same node. Effective only if this server has BOTH naive and HY2 enabled. Pairing is single-server only (the tag is this server's id). OFF (default) = no pair tag.",
                "Когда ВКЛ, naive- и HY2-ссылки этого узла получают общий тег `pair=<id сервера>`, чтобы клиент гнал UDP (который naive не умеет) через HY2 на том же узле. Действует только если на сервере включены И naive, И HY2. Пара — строго в рамках одного сервера (тег = id этого сервера). ВЫКЛ (по умолчанию) = без тега pair.",
            )) {
            (tr(lang, "UDP PAIRING (NAIVE ↔ HY2)", "UDP-ПАРА (NAIVE ↔ HY2)"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
            @if enabled {
                (tr(lang, "On — naive & HY2 on this node share a `pair` tag (a client routes UDP over the co-located HY2). No effect unless both run here.", "Вкл — naive и HY2 этого узла имеют общий тег `pair` (клиент гонит UDP через парный HY2). Без эффекта, если оба не подняты здесь."))
            } @else {
                (tr(lang, "Off — no pairing tag. Turn on for a node that runs BOTH naive and HY2.", "Выкл — без тега pair. Включи для узла, где есть И naive, И HY2."))
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/udp-pair"))
             style="display: inline;" {
            input type="hidden" name="enabled" value=(if enabled { "false" } else { "true" });
            button type="submit"
                   style=(format!("padding: 4px 12px; border: 1px solid var(--ink); background: {btn_bg}; color: {btn_fg}; font-family: var(--mono); font-size: 11px; cursor: pointer;")) {
                @if enabled {
                    (tr(lang, "turn off pairing", "выключить пару"))
                } @else {
                    (tr(lang, "turn on pairing", "включить пару"))
                }
            }
        }
    }
}

/// Reserved-ports section on the server-detail page (migration 0028).
/// Renders ALWAYS (even when the list is empty) so the operator has
/// a discoverable place to add port pins for a newly-detected co-
/// tenant service without having to remember the CLI invocation. The
/// list semantics are: any port here will be REFUSED by the sing-
/// box pre-apply guard, fail-closed.
fn server_detail_reserved_ports_section(
    server: &vpnctl_core::Server,
    reserved: &[u16],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let prefill: String = reserved
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Per-server allowlist of ports the daemon must NEVER bind via sing-box. Use when a co-tenant service (legacy 3x-ui Docker container, separate xray, another VPN stack) owns one of the standard ports — deploys are refused fail-closed if any rendered inbound would collide.",
                "Список портов на этом сервере, которые демону ЗАПРЕЩЕНО занимать через sing-box. Используется когда на хосте уже крутится сторонний сервис (legacy 3x-ui Docker, отдельный xray, другой VPN-стек) на стандартном порту — деплой отказывается, если какой-то рендеренный inbound попытается их занять, fail-closed.",
            )) {
                (tr(lang, "RESERVED PORTS", "ЗАРЕЗЕРВИРОВАННЫЕ ПОРТЫ"))
            }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Ports the daemon refuses to bind on this node. The sing-box pre-apply guard fails closed when any rendered inbound collides — so a co-tenant 3x-ui (or any other service vpnctl doesn't manage) can never get overwritten by a forgetful deploy.",
                "Порты, которые демон отказывается занимать на этой ноде. Пре-apply-guard sing-box падает fail-closed, если любой рендеренный inbound пересечётся — сторонний 3x-ui (или любой другой сервис, которым vpnctl не управляет) никогда не будет перезаписан забывчивым деплоем.",
            ))
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin-bottom: 12px;" {
            @if reserved.is_empty() {
                em style="color: var(--mute);" {
                    (tr(
                        lang,
                        "(no ports reserved — deploys are free to use every port the renderer picks)",
                        "(ничего не зарезервировано — деплои свободно используют любые порты, которые выбирает рендерер)",
                    ))
                }
            } @else {
                (tr(lang, "current: ", "сейчас: "))
                @for (i, port) in reserved.iter().enumerate() {
                    @if i > 0 { ", " }
                    b { (port) }
                }
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/reserved-ports"))
             style="display: flex; gap: 8px; align-items: center;" {
            input type="text" name="ports" value=(prefill)
                  placeholder="443,2053,2096"
                  style="flex: 1; padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);"
                  pattern="[0-9, ]*"
                  title=(tr(
                      lang,
                      "Comma-separated port numbers (1..=65535). Empty value clears the list.",
                      "Номера портов через запятую (1..=65535). Пустое поле очищает список.",
                  ));
            button type="submit"
                   title=(tr(
                       lang,
                       "Replace the reserved-ports list with the values above. Future sing-box deploys refuse to bind any port in the list.",
                       "Заменить список зарезервированных портов значениями выше. Будущие деплои sing-box откажутся занимать любой порт из списка.",
                   ))
                   style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "save", "сохранить"))
            }
        }
    }
}

// SHA256 shape validation + ssh-keyscan/-keygen fingerprint fetching
// live in `vpnctl-host-fingerprint`. The two inline copies that used
// to sit here had drifted on the `--` flag-injection defense (the
// wizard's third copy was missing it entirely) and on the validator
// alphabet (the inventory variant rejected URL-safe base64 the surface
// validators accepted). Crate is the single source of truth; spec
// tests live with it.

// (`validate_wgturn_vk_link` was removed 2026-05-19 — VK link is no
// longer a per-server operator input; each END USER supplies their
// own at `wgturn-cli connect-url … --vk-link <url>` time because
// each VK call has a limited concurrent-stream count. See the
// kernel's render_config comment for the upstream
// `pkg/wgshare/doc.go` quote.)

/// Render the wgturn-specific info section on `/admin/servers/{id}`.
///
/// The section is OMITTED entirely when the server doesn't have the
/// `wgturn` kernel — keeps the page short for the common case where
/// most nodes are sing-box only. When wgturn IS in `server.kernels`,
/// the section explains the operator-facing wgturn UX:
///   * VK link is END-USER-supplied at connect time, NOT operator
///     input here (Pavel 2026-05-19 + upstream `pkg/wgshare/doc.go`).
///   * Each VK call has limited concurrent streams → per-user
///     end-user-supplied is the correct model.
///   * Operator hands the user `wgturn://…` share-link from the
///     user-detail page; user pastes their own VK link into
///     `wgturn-cli connect-url … --vk-link <url>` on their device.
fn server_detail_wgturn_section(
    server: &vpnctl_core::Server,
    _secrets: &std::collections::HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let has_wgturn = server.kernels.iter().any(|k| k.0 == "wgturn");
    if !has_wgturn {
        return html! {};
    }
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "wgturn — emergency channel", "wgturn — аварийный канал")) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(lang, "VK-TURN-relayed WireGuard. The server-side daemon ", "WireGuard через VK-TURN relay. Серверный демон "))
            span.ed-mono { "wgturn-cli serve" }
            (tr(lang, " is configured automatically when you click ", " настраивается автоматически когда ты кликаешь "))
            span.ed-mono { (tr(lang, "deploy →", "деплой →")) }
            (tr(lang, " — no operator input is needed here.", " — ввод оператора здесь не нужен."))
        }
        div style="font-family: var(--serif); font-size: 13px; line-height: 1.6; padding: 10px 14px; background: var(--paper-tint); border-left: 3px solid var(--accent);" {
            b { (tr(lang, "VK link is supplied by the END USER, not the operator.", "VK-ссылку даёт КОНЕЧНЫЙ ПОЛЬЗОВАТЕЛЬ, не оператор.")) }
            (tr(
                lang,
                " Each VK call has limited concurrent streams, so a shared per-server link would saturate. Each user creates their own VK call invite on vk.com, then runs (or pastes the URL into their wgturn-cli)",
                " У каждого VK-звонка ограниченное число одновременных потоков, поэтому общая server-ссылка быстро бы переполнилась. Каждый пользователь сам создаёт инвайт на VK-звонок на vk.com, затем запускает (или вставляет URL в свой wgturn-cli)",
            ))
            br {}
            span.ed-mono style="display: inline-block; margin: 6px 0; padding: 4px 8px; background: var(--paper); font-size: 11px;" {
                "wgturn-cli connect-url '<wgturn://...>' --vk-link '<https://vk.com/call/join/...>'"
            }
            br {}
            (tr(lang, "The ", "Сама "))
            span.ed-mono { "wgturn://" }
            (tr(
                lang,
                " share-link itself lives on the user-detail page under «Per-protocol share links».",
                " share-ссылка лежит на странице пользователя в секции «Ссылки на отдельные протоколы».",
            ))
        }
    }
}

// (`server_set_wgturn_vk_link` POST handler removed 2026-05-19 —
// VK link is no longer a per-server admin input; see
// server_detail_wgturn_section above for the new operator copy.)

fn server_detail_protocols_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    hidden_map: &std::collections::HashMap<vpnctl_core::ProtocolId, bool>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let enabled: std::collections::HashSet<&vpnctl_core::ProtocolId> =
        server.enabled_protocols.iter().collect();
    let all_protocols = registry.protocol_ids();
    // Multi-kernel: protocol is "compatible" if ANY of the server's
    // declared kernels supports it. Annotation below tells the operator
    // WHICH kernel handles it (resolves "wireguard runs on amneziawg,
    // tuic on sing-box" disambiguation that matters once a node has
    // multiple kernels).
    let kernel_supports_map: Vec<(
        vpnctl_core::KernelId,
        std::collections::HashSet<vpnctl_core::ProtocolId>,
    )> = server
        .kernels
        .iter()
        .filter_map(|kid| {
            registry
                .kernel(kid)
                .map(|k| (kid.clone(), k.supported_protocols().into_iter().collect()))
        })
        .collect();
    let kernel_supports: std::collections::HashSet<vpnctl_core::ProtocolId> = kernel_supports_map
        .iter()
        .flat_map(|(_, sup)| sup.iter().cloned())
        .collect();
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        div.ed-rule {}
        // NM-12 follow-up (Pavel 2026-05-20: «каждый раз когда я
        // жму disable меня выкидывает в верх страницы»): all 4
        // visibility-toggle handlers below this row redirect to
        // `/admin/servers/{id}/protocols#enabled-protocols`. The browser
        // honours the fragment and scrolls the operator back to
        // THIS section instead of resetting to the page top.
        div.ed-art-eyebrow id="enabled-protocols" { (t(lang, K::EyebrowEnabledProtocols)) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 8px;" {
            (tr(
                lang,
                "Check what runs on this node. Protocols are wire formats; their kernels (one or more) are picked from the section above.",
                "Что крутится на этой ноде. Протоколы — это wire-форматы; их ядра (одно или больше) выбираются выше в секции Ядра.",
            ))
        }
        // Same deploy-required rule as the Kernels note above. Kept as
        // a marker for operators who scroll straight here, but R2
        // compressed it to one line — two identical banner paragraphs
        // on one screen read as a copy-paste bug.
        div style="padding: 6px 12px; margin: 0 0 12px; background: var(--paper); border-left: 3px solid var(--accent); font-family: var(--serif); font-size: 12px; line-height: 1.5;" {
            b style="color: var(--accent); font-family: var(--mono); letter-spacing: 0.1em; text-transform: uppercase; font-size: 11px;" {
                (tr(lang, "⚠ toggle here = inventory only", "⚠ тогл здесь = только инвентарь"))
            }
            (tr(lang, " — goes live on ", " — вступает в силу по "))
            a href="#deploy-button"
              style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none; font-weight: 500;" {
                span.ed-mono { (t(lang, K::BtnDeploy)) }
            }
            (tr(lang, " (details in the note under Kernels).", " (подробности — в заметке под Ядрами)."))
        }
        ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.8;" {
            @for pid in &all_protocols {
                @let is_on = enabled.contains(pid);
                @let compatible = kernel_supports.contains(pid);
                // Migration 0018 / NM-10: per-(server, protocol)
                // hidden flag. Only meaningful for `is_on=true` rows
                // (hidden state on an off-protocol is silently
                // ignored by the render path). Defaults to false
                // when the bulk-loader didn't return a row for this
                // pid (e.g. add_protocol invariant on enabled but
                // schema-missing row).
                @let is_hidden = hidden_map.get(pid).copied().unwrap_or(false);
                // NM-12: DPI / active-probing resilience tier. Read
                // straight from the protocol impl in the registry —
                // none of the inventory mutations carry this; it's
                // compile-time static. Missing protocol (impossible
                // in production, registry seeds itself in main()) →
                // None → no chip rendered.
                @let risk = registry.protocol(pid).map(|p| p.dpi_risk());
                @let pid_is_weak = matches!(risk, Some(vpnctl_core::DpiRisk::Weak));
                li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                    // Weak protocols get font-size 11px (vs 12px for
                    // Moderate/Strong) — Pavel 2026-05-20: «можешь
                    // даже шрифт меньше сделать у них». Visual
                    // de-emphasis without removing the row, so the
                    // operator can still see + toggle it.
                    span style=(format!(
                        "flex: 1; color: {}; font-size: {};",
                        if compatible { "var(--ink)" } else { "var(--mute)" },
                        if pid_is_weak { "11px" } else { "12px" },
                    )) {
                        (pid.0)
                        @if let Some(r) = risk {
                            " "
                            // DPI-risk chip: green/grey/red, sits
                            // alongside the protocol id so the
                            // operator's eye catches it. Colour
                            // helpers on `DpiRisk` are the single
                            // source of truth — adding a future tier
                            // (or recolouring the palette) is one
                            // edit in core/src/lib.rs. Tooltip carries
                            // the per-tier explainer string.
                            span title=(r.tooltip())
                                 style=(format!(
                                     "font-family: var(--mono); font-size: 10px; padding: 1px 6px; border: 1px solid {}; color: {}; letter-spacing: 0.04em;",
                                     r.border_css(),
                                     r.text_css(),
                                 )) {
                                (r.label())
                            }
                        }
                        @if !compatible {
                            " "
                            span style="font-size: 10px; color: var(--mute); font-style: italic; font-family: var(--serif);" {
                                (tr(lang, "(not supported by ", "(не поддерживается "))
                                @if server.kernels.len() == 1 {
                                    (tr(lang, "kernel ", "ядром ")) (server.kernels[0].0)
                                } @else {
                                    (tr(lang, "any kernel on this server: ", "ни одним ядром на этом сервере: "))
                                    (ordered_kernel_ids(server).iter().map(|k| k.0.clone()).collect::<Vec<_>>().join(", "))
                                }
                                ")"
                            }
                        }
                    }
                    @if is_on {
                        @if is_hidden {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                                (tr(lang, "✓ on · hidden", "✓ вкл · скрыт"))
                            }
                        } @else {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                                (tr(lang, "✓ on", "✓ вкл"))
                            }
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/protocols/{}/disable", sid_enc, path_segment_encode(&pid.0)))
                             style="margin: 0; padding: 0;" {
                            @let dis_proto_title = match lang {
                                crate::i18n::Locale::En => format!("Remove {} from {}.enabled_protocols. Takes effect on next deploy.", pid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Убрать {} из {}.enabled_protocols. Применится при следующем деплое.", pid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(dis_proto_title)
                                   class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                                (t(lang, K::BtnDisable))
                            }
                        }
                        @if !compatible {
                            span style="font-family: var(--mono); font-size: 10px; color: var(--mute); font-style: italic;" {
                                (tr(lang, "(disable to clear)", "(выключи чтобы убрать)"))
                            }
                        } @else if is_hidden {
                            form method="post"
                                 action=(format!("/admin/servers/{}/protocols/{}/unhide", sid_enc, path_segment_encode(&pid.0)))
                                 style="margin: 0; padding: 0;" {
                                @let unhide_title = match lang {
                                    crate::i18n::Locale::En => format!("Resume emitting {} in this server's subscription URLs. Live sing-box inbound was never stopped; this just unmutes the render.", pid.0),
                                    crate::i18n::Locale::Ru => format!("Снова отдавать {} в URL подписок этого сервера. Живой sing-box inbound никто не останавливал; это только снимает mute с рендера.", pid.0),
                                };
                                button type="submit"
                                       title=(unhide_title)
                                       class="ed-abtn ed-abtn--sm" {
                                    (t(lang, K::BtnUnhide))
                                }
                            }
                        } @else {
                            form method="post"
                                 action=(format!("/admin/servers/{}/protocols/{}/hide", sid_enc, path_segment_encode(&pid.0)))
                                 style="margin: 0; padding: 0;" {
                                @let hide_title = match lang {
                                    crate::i18n::Locale::En => format!("Stop emitting {} in this server's subscription URLs WITHOUT removing the live inbound. Existing client URIs keep working until they re-pull.", pid.0),
                                    crate::i18n::Locale::Ru => format!("Перестать отдавать {} в URL подписок этого сервера БЕЗ удаления живого inbound. Закешированные клиентские URI продолжают работать до следующего pull.", pid.0),
                                };
                                button type="submit"
                                       title=(hide_title)
                                       class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                                    (t(lang, K::BtnHide))
                                }
                            }
                        }
                    } @else if compatible {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-right: 4px;" {
                            "—"
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/protocols/{}/enable", sid_enc, path_segment_encode(&pid.0)))
                             style="margin: 0; padding: 0;" {
                            @let en_proto_title = match lang {
                                crate::i18n::Locale::En => format!("Add {} to {}.enabled_protocols. Takes effect on next deploy.", pid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Добавить {} в {}.enabled_protocols. Применится при следующем деплое.", pid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(en_proto_title)
                                   class="ed-abtn ed-abtn--sm" {
                                (t(lang, K::BtnEnable))
                            }
                        }
                    } @else {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            (tr(lang, "incompatible", "несовместимо"))
                        }
                    }
                }
            }
        }
    }
}

/// Per-(user, server, protocol) delivery grid — renders inside the
/// "Server access" section of /admin/users/{id}, one block per
/// granted server. Each protocol the server has enabled gets a row
/// with its current delivery state (delivered / user-blocked /
/// server-hidden) and a block/unblock button (no-op for
/// server-hidden rows — those are toggled on /admin/servers/{id}).
///
/// Migration 0018 / NM-10: the two axes are server.hidden (set on
/// server-detail) and grant_protocol_overrides.state='disabled'
/// (set here). Visibility resolution is OR-semantics — either axis
/// suppresses the protocol from this user's subscription URL.
///
/// `hidden_map = None` is treated as an empty map (server has no
/// enabled protocols at all — render an empty-state explainer).
pub(crate) fn user_detail_per_protocol_grid(
    uid: &vpnctl_core::UserId,
    server: &vpnctl_core::Server,
    hidden_map: Option<&std::collections::HashMap<vpnctl_core::ProtocolId, bool>>,
    user_overrides: &std::collections::HashMap<
        (vpnctl_core::ServerId, vpnctl_core::ProtocolId),
        bool,
    >,
    registry: &vpnctl_core::Registry,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let uid_enc = path_segment_encode(&uid.0);
    let sid_enc = path_segment_encode(&server.id.0);
    // Iterate the `server_protocols` table directly (not the in-memory
    // `enabled_protocols` field) so the OR-semantics deny resolution
    // matches `visible_protocols_for_subscription` BYTE-for-BYTE.
    // Review-agent 2026-05-20: a divergence between the in-memory
    // `enabled_protocols` cache and the on-disk `server_protocols`
    // rows would silently lie about what the operator's clients see
    // on next pull. Sort alphabetically to match the canonical
    // query's `ORDER BY sp.protocol_id`.
    let mut pids: Vec<&vpnctl_core::ProtocolId> =
        hidden_map.map(|m| m.keys().collect()).unwrap_or_default();
    pids.sort_by(|a, b| a.0.cmp(&b.0));
    html! {
        div style="margin: 8px 0 4px 16px; padding: 8px 12px 6px; border-left: 2px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.6;" {
            div style="color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; font-size: 10px; margin-bottom: 6px;" {
                (tr(lang, "Per-protocol delivery", "Доставка по протоколам"))
            }
            @if pids.is_empty() {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 0; font-size: 12px;" {
                    (tr(
                        lang,
                        "No protocols enabled on this server yet. Add one on the ",
                        "На этом сервере пока ничего не включено. Добавь хотя бы один через ",
                    ))
                    a href=(format!("/admin/servers/{sid_enc}"))
                      target="_blank"
                      rel="noopener"
                      style="color: var(--ink);" {
                        (tr(lang, "server detail page", "страницу сервера"))
                    }
                    (tr(lang, " — then the per-protocol toggles will appear here.", " — тогда тоглы по протоколам появятся здесь."))
                }
            } @else {
                ul style="list-style: none; padding: 0; margin: 0;" {
                    @for pid in &pids {
                        @let is_hidden = hidden_map
                            .and_then(|m| m.get(*pid).copied())
                            .unwrap_or(false);
                        @let is_user_blocked = user_overrides
                            .get(&(server.id.clone(), (*pid).clone()))
                            .copied()
                            .unwrap_or(false);
                        @let pid_enc = path_segment_encode(&pid.0);
                        // NM-12: same registry-driven risk chip the
                        // server-detail uses. Shrinks the protocol
                        // name to 10px (vs 11px row-default) when
                        // Weak — small visual sentence saying "you
                        // shouldn't be delivering this here".
                        @let risk = registry.protocol(pid).map(|p| p.dpi_risk());
                        @let pid_is_weak = matches!(risk, Some(vpnctl_core::DpiRisk::Weak));
                        li style="display: flex; align-items: baseline; gap: 10px; padding: 2px 0;" {
                            span style=(format!(
                                "flex: 1; color: var(--ink); font-size: {};",
                                if pid_is_weak { "10px" } else { "11px" },
                            )) {
                                (pid.0)
                                @if let Some(r) = risk {
                                    " "
                                    span title=(r.tooltip())
                                         style=(format!(
                                             "font-family: var(--mono); font-size: 9px; padding: 0 4px; border: 1px solid {}; color: {}; letter-spacing: 0.04em; margin-left: 2px;",
                                             r.border_css(),
                                             r.text_css(),
                                         )) {
                                        (r.label())
                                    }
                                }
                            }
                            @if is_hidden && is_user_blocked {
                                span style="color: var(--mute);" {
                                    (tr(lang, "server-hidden + user-blocked", "скрыт-на-сервере + заблокирован-у-юзера"))
                                }
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/protocols/{pid_enc}/enable"))
                                     style="margin: 0;" {
                                    button type="submit"
                                           title=(tr(
                                               lang,
                                               "Clear this user's override. Server-hidden flag remains — adjust on the server detail page.",
                                               "Очистить override этого пользователя. Флаг server-hidden останется — правится на странице сервера.",
                                           ))
                                           style="padding: 1px 6px; border: 1px solid var(--rule-s); background: transparent; color: var(--mute); font-family: var(--mono); font-size: 10px; cursor: pointer;" {
                                        (tr(lang, "unblock (user)", "разблокировать (юзер)"))
                                    }
                                }
                            } @else if is_hidden {
                                span style="color: var(--mute);" {
                                    (tr(lang, "server-hidden (read-only here)", "скрыт на сервере (здесь только чтение)"))
                                }
                            } @else if is_user_blocked {
                                span style="color: var(--acc);" {
                                    (tr(lang, "✗ user-blocked", "✗ заблокирован у юзера"))
                                }
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/protocols/{pid_enc}/enable"))
                                     style="margin: 0;" {
                                    @let unblock_title = match lang {
                                        crate::i18n::Locale::En => format!("Deliver {} to {} again on {}", pid.0, uid.0, server.id.0),
                                        crate::i18n::Locale::Ru => format!("Начать снова доставлять {} пользователю {} на {}", pid.0, uid.0, server.id.0),
                                    };
                                    button type="submit"
                                           title=(unblock_title)
                                           style="padding: 1px 6px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 10px; cursor: pointer;" {
                                        (tr(lang, "unblock", "разблокировать"))
                                    }
                                }
                            } @else {
                                span style="color: var(--acc);" { (tr(lang, "✓ delivered", "✓ доставляется")) }
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/protocols/{pid_enc}/disable"))
                                     style="margin: 0;" {
                                    @let block_title = match lang {
                                        crate::i18n::Locale::En => format!("Stop delivering {} to {} on {} (per-user override; other users keep getting it)", pid.0, uid.0, server.id.0),
                                        crate::i18n::Locale::Ru => format!("Перестать доставлять {} пользователю {} на {} (per-user override; остальным продолжает идти)", pid.0, uid.0, server.id.0),
                                    };
                                    button type="submit"
                                           title=(block_title)
                                           style="padding: 1px 6px; border: 1px solid var(--rule-s); background: transparent; color: var(--mute); font-family: var(--mono); font-size: 10px; cursor: pointer;" {
                                        (tr(lang, "block", "заблокировать"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════
//  PR-Server — informativeness cards for the server-detail page.
//
//  All seven cards reuse existing helpers (status_tile, sparkline_svg,
//  window_picker_section, humanize_bytes, summarize_audit_payload,
//  action_kind, .ed-time, kernel_floor_rollup) — no parallel styling.
//  Bilingual via tr() / t(). The only card that does I/O is server#1
//  (live SSH read, gated behind ?drift=live, best-effort, never 500).
// ════════════════════════════════════════════════════════════════════

/// One resolved orphan UUID for the server#1 drift-detail card: a
/// UUID the node serves that no granted user accounts for. `name`
/// is `Some(user_id)` when the orphan UUID DOES map to a known user
/// (e.g. a user whose grant was revoked but whose UUID still lives in
/// the node config) and `None` when it maps to nothing in inventory
/// (a likely service account / hand-added UUID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OrphanUuid {
    pub(super) uuid: String,
    /// Resolved inventory user id, if the UUID matches a known user.
    pub(super) name: Option<String>,
}

/// Outcome of a `?drift=live` attempt. `Ok` carries the diff; `Err`
/// carries a short, policy-safe reason string the card renders into
/// its empty-state. The reason NEVER says «ssh to the box» — it says
/// the config couldn't be read (node unreachable or deploy key).
#[derive(Debug, Clone)]
enum DriftLiveResult {
    /// Live read + parse succeeded — `orphans` are on-node UUIDs not
    /// in inventory (resolved to a user name where possible).
    Ok { orphans: Vec<OrphanUuid> },
    /// Live read failed (timeout, node down, key not authorised, parse
    /// error). The card degrades to a policy-safe empty-state.
    Unavailable,
}

/// Pure diff for server#1 — given the set of UUIDs the NODE serves and
/// the inventory `users` (whose `.uuid` already resolves
/// COALESCE(client_uuid, users.uuid)), return the orphans: UUIDs on the
/// node that are NOT in the inventory grant set. Each orphan is
/// resolved to a user id when the UUID matches a known global user
/// uuid (revoked-but-still-on-node case), else left unresolved.
///
/// Extracted as a free function so the test suite can pin the
/// orphan-detection semantics directly without standing up SSH.
pub(super) fn compute_orphan_uuids(
    node_uuids: &std::collections::BTreeSet<String>,
    granted_users: &[vpnctl_core::User],
    all_users: &[vpnctl_core::User],
) -> Vec<OrphanUuid> {
    // Inventory UUID set for THIS server = the resolved uuid of every
    // granted user. A node UUID present here is accounted-for.
    let inventory_uuids: std::collections::BTreeSet<&str> =
        granted_users.iter().map(|u| u.uuid.as_str()).collect();
    // Reverse map from any KNOWN user's global uuid → user id, so an
    // orphan can still be named if it belongs to a user who simply
    // lost their grant (the dangerous revoke case the operator most
    // wants to see).
    let uuid_to_user: std::collections::HashMap<&str, &str> = all_users
        .iter()
        .map(|u| (u.uuid.as_str(), u.id.0.as_str()))
        .collect();

    node_uuids
        .iter()
        .filter(|u| !inventory_uuids.contains(u.as_str()))
        .map(|u| OrphanUuid {
            uuid: u.clone(),
            name: uuid_to_user.get(u.as_str()).map(|s| s.to_string()),
        })
        .collect()
}

/// server#1 — best-effort LIVE read of the node's sing-box config over
/// SSH, with a hard ≤6s timeout. EVERY failure mode (transport error,
/// node down, key not authorised, non-UTF-8, parse error, or the
/// outer tokio timeout) collapses to `DriftLiveResult::Unavailable` so
/// the caller can render a policy-safe empty-state — this function
/// NEVER returns an error and NEVER panics.
///
/// `granted_users` is `users_for_server(sid)` (the inventory set for
/// the diff — a node UUID present here is accounted-for). `all_users`
/// is the full inventory user list (already loaded by the handler) so
/// a revoked-but-on-node orphan can still be NAMED instead of showing
/// as «unresolved».
async fn load_drift_live(
    server: &vpnctl_core::Server,
    granted_users: &[vpnctl_core::User],
    all_users: &[vpnctl_core::User],
) -> DriftLiveResult {
    use crate::ssh_subprocess::SubprocessSshTransport;
    use vpnctl_core::SshTransport;

    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let transport = SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        key_path,
    )
    .port(server.ssh_port)
    // Hard wall-clock cap — keep the armed path snappy even when the
    // node is black-holed (the transport already sets ConnectTimeout=10
    // + ServerAlive keepalives, but we want ≤6s end-to-end here).
    .timeout(std::time::Duration::from_secs(6));

    // Outer guard belt-and-suspenders against a wedged child the
    // transport's own timeout somehow misses — 7s leaves a 1s margin.
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        transport.read_file("/etc/sing-box/config.json"),
    )
    .await;

    let bytes = match read {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            tracing::info!(
                target = "vpnctld::admin",
                server = %server.id,
                error = %e,
                "drift=live: live config read failed (best-effort)"
            );
            return DriftLiveResult::Unavailable;
        }
        Err(_elapsed) => {
            tracing::info!(
                target = "vpnctld::admin",
                server = %server.id,
                "drift=live: live config read timed out (best-effort)"
            );
            return DriftLiveResult::Unavailable;
        }
    };

    // Parse the on-node UUIDs (pub helper; parse failure → empty set,
    // which we treat as «no on-node users observed» rather than orphan
    // noise). The diff is against the granted set; naming uses the full
    // user list so a revoked user's lingering UUID is still labelled.
    let node_uuids = vpnctl_kernels::live_config_user_uuids(&bytes);
    let orphans = compute_orphan_uuids(&node_uuids, granted_users, all_users);
    DriftLiveResult::Ok { orphans }
}

/// server#1 — drift-detail card. Two modes:
///
/// * `armed == false` (default page load): renders a «[check live
///   drift →]» link anchored to `?drift=live`. NO SSH happened.
/// * `armed == true` (`?drift=live`): renders the orphan list from the
///   best-effort live read, or a policy-safe empty-state on any
///   failure. The empty-state copy NEVER instructs the operator to
///   «ssh to the box» — per operator-action-policy it says the config
///   couldn't be read (node unreachable or deploy key).
fn server_detail_drift_detail_section(
    server: &vpnctl_core::Server,
    drift_live: Option<&DriftLiveResult>,
    armed: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        section id="drift-detail" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (t(lang, K::EyebrowDriftDetail)) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "The port-level drift above compares declared protocols to listening sockets. This card goes deeper — it reads the node's live sing-box config and lists UUIDs the node still serves that no granted user accounts for (a revoked user whose UUID lingers, or a service account). It's a live SSH read, so it runs only on demand.",
                    "Дрейф по портам выше сравнивает заявленные протоколы со слушающими сокетами. Эта карточка копает глубже — читает живой конфиг sing-box на ноде и показывает UUID, которые нода всё ещё обслуживает, но за которыми не стоит ни один выданный доступ (отозванный юзер, чей UUID завис, или сервисный аккаунт). Это живое SSH-чтение, поэтому запускается только по запросу.",
                ))
            }
            @if !armed {
                // Default fast path — link to arm the live read. No SSH
                // was attempted on this render.
                p style="font-family: var(--mono); font-size: 12px; margin: 8px 0;" {
                    a href=(format!("/admin/servers/{sid_enc}/protocols?drift=live#drift-detail"))
                      style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                        (tr(lang, "check live drift →", "проверить живой дрейф →"))
                    }
                }
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 4px 0 0;" {
                    (tr(
                        lang,
                        "Skipped by default so the page loads fast — no node is contacted until you click.",
                        "По умолчанию пропускается ради быстрой загрузки — пока не нажмёшь, нода не опрашивается.",
                    ))
                }
            } @else {
                @match drift_live {
                    Some(DriftLiveResult::Ok { orphans }) if !orphans.is_empty() => {
                        div style="margin-top: 6px; padding: 10px 12px; border: 1px solid var(--acc); background: var(--paper);" {
                            div style="font-family: var(--mono); font-size: 10px; color: var(--acc); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 6px;" {
                                (tr(lang, "orphan uuids on node", "осиротевшие uuid на ноде"))
                            }
                            ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                                @for o in orphans {
                                    li style="padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                                        span.ed-mono { (o.uuid) }
                                        " — "
                                        @match &o.name {
                                            Some(name) => {
                                                span style="color: var(--ink); font-style: italic; font-family: var(--serif);" {
                                                    (tr(lang, "maps to user ", "соответствует юзеру "))
                                                }
                                                a href=(format!("/admin/users/{}", path_segment_encode(name)))
                                                  style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                                                    (name)
                                                }
                                            }
                                            None => {
                                                span style="color: var(--mute); font-style: italic; font-family: var(--serif);" {
                                                    (tr(lang, "(unresolved — likely service account)", "(не определён — вероятно сервисный аккаунт)"))
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 8px 0 0;" {
                                (tr(
                                    lang,
                                    "A redeploy re-renders the config from inventory and removes any UUID inventory doesn't expect.",
                                    "Redeploy перерендерит конфиг из инвентаря и уберёт любой UUID, которого инвентарь не ждёт.",
                                ))
                            }
                        }
                    }
                    Some(DriftLiveResult::Ok { .. }) => {
                        // Read succeeded, no orphans — clean state.
                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--soft); margin-top: 6px;" {
                            (tr(
                                lang,
                                "Live config read OK — every UUID the node serves maps to a granted user. No orphans.",
                                "Живой конфиг прочитан — каждый UUID на ноде соответствует выданному доступу. Сирот нет.",
                            ))
                        }
                    }
                    _ => {
                        // Unavailable / None — policy-safe empty-state.
                        // NO «ssh to the box» instruction.
                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 6px;" {
                            (tr(
                                lang,
                                "Couldn't read the live config (node unreachable or deploy key not authorised on it). Nothing was changed; try again after the node is back, or run a deploy which re-pushes the config anyway.",
                                "Не удалось прочитать живой конфиг (нода недоступна или deploy-ключ на ней не авторизован). Ничего не менялось; попробуй снова когда нода вернётся, либо запусти deploy — он всё равно перезальёт конфиг.",
                            ))
                        }
                    }
                }
            }
        }
    }
}

/// server#3 — top users by 24h traffic on THIS server. Reuses
/// humanize_bytes + links each user to /admin/users/{id}. Carries the
/// NM-11 empty-state (prod per-user attribution is NULL upstream —
/// clash-api drops the user field), so an empty `rows` renders an
/// explainer instead of a blank card.
fn server_detail_top_users_section(
    rows: &[(vpnctl_core::UserId, u64)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    html! {
        section id="top-users" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (tr(lang, "Top users · last 24h", "Топ пользователей · за 24ч")) }
            @if rows.is_empty() {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                    (tr(
                        lang,
                        "No per-user traffic attributed on this server yet. Per-user attribution is NULL upstream — clash-api drops the user field (NM-11); see the dashboard note. Server-wide totals still work in the traffic chart below.",
                        "Трафик по пользователям на этом сервере пока не атрибутирован. Атрибуция per-user пустая на уровне upstream — clash-api убирает поле user (NM-11); см. заметку на дашборде. Серверные итоги всё равно работают в графике трафика ниже.",
                    ))
                }
            } @else {
                table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; margin-top: 8px;" {
                    thead {
                        tr style="border-bottom: 1px solid var(--ink);" {
                            th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                                (tr(lang, "user", "пользователь"))
                            }
                            th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                                (tr(lang, "traffic (up+down)", "трафик (вверх+вниз)"))
                            }
                        }
                    }
                    tbody {
                        @for (uid, bytes) in rows {
                            tr style="border-bottom: 1px dotted var(--rule);" {
                                td style="padding: 5px 8px;" {
                                    a href=(format!("/admin/users/{}", path_segment_encode(&uid.0)))
                                      style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                                        (uid.0)
                                    }
                                }
                                td style="padding: 5px 8px; text-align: right; color: var(--ink);" {
                                    (humanize_bytes(*bytes))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// server#4 — per-server traffic sparkline (24h / 7d / 30d / all).
/// Reuses sparkline_svg + a window_picker_section scoped to
/// /admin/servers/{id}. The rows are server-wide
/// (recent_vpn_stats_for_server); we bucket them into the window's
/// cells and feed the per-cell up+down totals to the sparkline. The
/// ↑↓ summary tiles show the window totals.
fn server_detail_traffic_section(
    rows: &[vpnctl_inventory::VpnStatsRow],
    window: VpnSparklineWindow,
    server_id: &vpnctl_core::ServerId,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // This section lives on the `activity` tab — the `?vpn_window=`
    // switcher links must keep the operator there, not bounce to status.
    let base_url = format!(
        "/admin/servers/{}/activity",
        path_segment_encode(&server_id.0)
    );
    let window_label = match lang {
        crate::i18n::Locale::En => window.label_en,
        crate::i18n::Locale::Ru => window.label_ru,
    };

    // Window totals for the ↑↓ tiles.
    let mut total_up: u64 = 0;
    let mut total_dn: u64 = 0;
    for r in rows {
        total_up = total_up.saturating_add(r.upload_bytes);
        total_dn = total_dn.saturating_add(r.download_bytes);
    }

    // Bucket into the window's cells (newest cell rightmost). Each row
    // carries a ts; index = how many bucket-widths back from now. Out-
    // of-range rows are clamped into the oldest cell.
    let now = chrono::Utc::now();
    let bucket_secs = i64::from(window.bucket_hours) * 3600;
    let cells = window.cells as usize;
    let mut series: Vec<f64> = vec![0.0; cells];
    // Guard against a degenerate window (cells == 0): `cells - 1` would
    // underflow a usize and the indexed write would panic. Every window
    // in VPN_SPARKLINE_WINDOWS has cells > 0 today, but this keeps the
    // card best-effort if that ever changes.
    if bucket_secs > 0 && cells > 0 {
        for r in rows {
            let age_secs = (now - r.ts).num_seconds().max(0);
            let back = (age_secs / bucket_secs) as usize;
            // back==0 → newest cell (last index); clamp old rows into
            // the oldest cell (index 0).
            let idx = (cells - 1).saturating_sub(back.min(cells - 1));
            let bytes = r.upload_bytes.saturating_add(r.download_bytes);
            series[idx] += bytes as f64;
        }
    }
    let has_data = series.iter().any(|v| *v > 0.0);

    html! {
        section id="server-traffic" style="margin-top: 28px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Server traffic · ", "Трафик сервера · ")) (window_label)
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 4px;" {
                (tr(
                    lang,
                    "Server-wide upload+download from clash-api 5-min ticks, bucketed across the window. Pick a window below — the sparkline + totals update together.",
                    "Серверный upload+download с 5-минутных тиков clash-api, разложенный по окну. Выбери окно ниже — спарклайн и итоги обновятся вместе.",
                ))
            }
            (window_picker_section(&base_url, window.slug, lang))
            div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 12px 0 6px;" {
                (status_tile(tr(lang, "↑ upload", "↑ отдано"), &humanize_bytes(total_up), "var(--ink)"))
                (status_tile(tr(lang, "↓ download", "↓ принято"), &humanize_bytes(total_dn), "var(--ink)"))
            }
            @if has_data {
                // R2: in-SVG label off — it printed raw bytes; the
                // humanized caption below carries the peak.
                @let series_max = series.iter().copied().fold(0.0_f64, f64::max);
                (super::dashboard::sparkline_svg_scaled(&series, 1160, 90, None, false))
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                    (tr(lang, "max ", "макс ")) (humanize_bytes(series_max as u64))
                    (tr(lang, " per bucket", " на интервал"))
                }
            } @else {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0;" {
                    (tr(
                        lang,
                        "No traffic recorded in this window yet. The clash-api poller fills this once the node reports samples.",
                        "В этом окне трафик ещё не записан. Поллер clash-api наполнит график как только нода начнёт отдавать сэмплы.",
                    ))
                }
            }
        }
    }
}

/// server#5 — TCP/UDP split from the live clash-api snapshot. Reuses
/// status_tile + humanize_bytes + the shared `network_breakdown`. The
/// caption is explicit that clash-api carries no per-protocol tag,
/// only the network kind — this card is re-scoped from the original
/// «per-protocol» idea for exactly that reason. Cheap (no DB).
fn server_detail_network_split_section(
    server_snap: Option<&crate::snapshot_cache::ServerSnapshot>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use crate::snapshot_cache::network_breakdown;
    html! {
        section id="network-split" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (tr(lang, "TCP / UDP split", "Разбивка TCP / UDP")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "From the latest clash-api snapshot. clash-api carries no per-protocol tag, only network — so this splits by transport (TCP vs UDP), not by VLESS/TUIC/etc.",
                    "Из последнего снимка clash-api. clash-api не несёт тег протокола, только network — поэтому разбивка по транспорту (TCP против UDP), а не по VLESS/TUIC/и т.п.",
                ))
            }
            @match server_snap {
                Some(snap) => {
                    @let nb = network_breakdown(&snap.snapshot);
                    div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;" {
                        (status_tile(
                            tr(lang, "tcp", "tcp"),
                            &format!("{} · {}", nb.tcp_conns, humanize_bytes(nb.tcp_bytes)),
                            "var(--ink)",
                        ))
                        (status_tile(
                            tr(lang, "udp", "udp"),
                            &format!("{} · {}", nb.udp_conns, humanize_bytes(nb.udp_bytes)),
                            "var(--ink)",
                        ))
                        (status_tile(
                            tr(lang, "other", "иные"),
                            &format!("{} · {}", nb.other_conns, humanize_bytes(nb.other_bytes)),
                            "var(--ink)",
                        ))
                    }
                }
                None => {
                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                        (tr(
                            lang,
                            "No clash-api snapshot for this server yet. The poller fires every 5 minutes; refresh after the next tick.",
                            "Снимка clash-api по этому серверу ещё нет. Поллер запускается каждые 5 минут; обнови после следующего тика.",
                        ))
                    }
                }
            }
        }
    }
}

/// server#7 — server-scoped audit timeline (last 20). Reuses
/// `summarize_audit_payload` + `action_kind` + the `.ed-time` editorial
/// component — byte-identical row shape to the dashboard + global audit
/// timeline, just filtered to rows that reference THIS server.
fn server_detail_audit_section(
    rows: &[vpnctl_inventory::AuditEntry],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    html! {
        section id="server-audit" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (tr(lang, "Audit timeline · this server", "Лента аудита · этот сервер")) }
            @if rows.is_empty() {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                    (tr(
                        lang,
                        "No audit rows reference this server yet — deploy / grant / revoke actions will start filling this stream.",
                        "Записей аудита по этому серверу пока нет — действия deploy / выдать / отозвать начнут наполнять эту ленту.",
                    ))
                }
            } @else {
                // `--compact` drops the target column — on a
                // server-scoped stream it repeated this server's id on
                // every row (zero information, stolen width; R2).
                div.ed-time.ed-time--compact {
                    @for e in rows {
                        div.ed-time-row {
                            span.ed-time-row__t { (format_msk_iso(e.ts)) }
                            span class=(format!("ed-time-row__a ed-time-row__a--{}", action_kind(&e.action))) {
                                (e.action)
                            }
                            span.ed-time-row__pl {
                                (tr(lang, "by ", "автор: ")) (e.actor)
                                @if let Some(p) = &e.payload {
                                    @let summary = summarize_audit_payload(p);
                                    @if !summary.is_empty() {
                                        " · " span.ed-mono { (summary) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// STATUS-tab drift glance (ui-audit §4): the declared-vs-observed
/// verdict + drift counts, linking to the full grid + observed-socket
/// list on the protocols tab. The list itself (100+ rows on wgturn/xray
/// nodes) stays off the status wall — that's the whole point of the tab
/// split. Counts come from the same `missing`/`extra` the full section
/// uses, so the two can never disagree.
fn server_detail_drift_summary(
    missing: &[(String, u16)],
    extra: &[(String, u16)],
    have_probe: bool,
    base: &str,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    html! {
        div.ed-rule {}
        div id="drift-summary" style="margin: 14px 0; font-family: var(--serif); font-size: 13px;" {
            @if !have_probe {
                span style="color: var(--mute); font-style: italic;" {
                    (tr(
                        lang,
                        "Drift — no probe yet (poller runs every 10 min; sing-box nodes only).",
                        "Дрейф — probe ещё нет (поллер ходит раз в 10 минут; только sing-box ноды).",
                    ))
                }
            } @else if missing.is_empty() && extra.is_empty() {
                span style="color: var(--soft);" {
                    (tr(
                        lang,
                        "✓ Declared and observed match. No drift.",
                        "✓ Заявленное и наблюдаемое совпадают. Дрейфа нет.",
                    ))
                }
            } @else {
                span style="color: var(--acc);" {
                    "⚠ " (tr(lang, "drift — ", "дрейф — "))
                    (missing.len()) " " (tr(lang, "declared-but-silent", "заявлено-но-молчит"))
                    " · "
                    (extra.len()) " " (tr(lang, "listening-but-undeclared", "слушает-но-не-заявлено"))
                }
                " "
                a href=(format!("{base}/protocols#drift-detail"))
                  style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                    (tr(lang, "full grid on protocols tab →", "полная таблица на вкладке протоколы →"))
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn server_detail_drift_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    secrets: &std::collections::HashMap<String, String>,
    observed: &std::collections::BTreeSet<(String, u16)>,
    missing: &[(String, u16)],
    extra: &[(String, u16)],
    have_probe: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // Design v2 3c — the declared × listening drift GRID: one row per
    // declared protocol, its expected ports, and whether the latest
    // probe saw each port open. Undeclared listeners follow, grouped
    // by a small classifier instead of a 100-socket wall.
    let has_wg = server
        .enabled_protocols
        .iter()
        .any(|p| p.0.contains("wireguard") || p.0.contains("amnezia") || p.0.contains("wgturn"));
    // Group the undeclared listeners. Adopt/ignore actions are
    // deliberately absent — the inventory doesn't model per-peer
    // ports yet (NM-14); this table only keeps the wall readable.
    let mut wg_peers = 0usize;
    let mut caddy_internals: Vec<String> = Vec::new();
    let mut unclassified: Vec<String> = Vec::new();
    for (proto, port) in extra {
        if proto == "tcp" && (*port == 2019 || *port == 80) {
            caddy_internals.push(format!("{proto}/{port}"));
        } else if has_wg && proto == "udp" && *port >= 30000 {
            wg_peers += 1;
        } else {
            unclassified.push(format!("{proto}/{port}"));
        }
    }
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Declared vs observed", "Заявлено vs наблюдается")) " "
            span.ed-tip title=(tr(
                lang,
                "Declared = protocol in the inventory for this node. Listening = the latest probe found the port open (ss -tlnup). A declared-but-silent port is the dangerous drift; undeclared listeners are usually per-user wg peers.",
                "Заявлено = протокол в инвентаре этой ноды. Слушает = последняя проба нашла порт открытым (ss -tlnup). Заявлено-но-молчит — опасный дрейф; незаявленные слушатели обычно пер-пировые wg-порты.",
            )) { "ⓘ" }
        }
        @if !have_probe {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin-top: 8px;" {
                (tr(lang, "(no probe yet — poller runs every 10 min; sing-box nodes only)", "(probe ещё нет — поллер ходит раз в 10 минут; только sing-box ноды)"))
            }
        } @else {
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th { (tr(lang, "protocol", "протокол")) }
                        th { (tr(lang, "port(s)", "порт(ы)")) }
                        th { (tr(lang, "declared", "заявлен")) }
                        th { (tr(lang, "listening", "слушает")) }
                    }
                }
                tbody {
                    @for pid in &server.enabled_protocols {
                        @let ports = expected_ports_for_protocol(registry, pid, secrets);
                        @let silent = ports.iter().any(|pp| !observed.contains(pp));
                        tr class=(if silent && !ports.is_empty() { "on-warn" } else { "" }) {
                            td { b { (pid.0) } }
                            td.num.ed-grid__sm {
                                @if ports.is_empty() {
                                    span.ed-grid__mut { "—" }
                                } @else {
                                    @for (i, (proto, port)) in ports.iter().enumerate() {
                                        @if i > 0 { " · " }
                                        (port) "/" (proto)
                                    }
                                }
                            }
                            td { span style="color: var(--green);" { "✓" } }
                            td.ed-grid__sm {
                                @if ports.is_empty() {
                                    span.ed-grid__mut { (tr(lang, "n/a (no fixed port)", "н/д (нет фикс. порта)")) }
                                } @else {
                                    @for (i, pp) in ports.iter().enumerate() {
                                        @if i > 0 { " · " }
                                        @if observed.contains(pp) {
                                            span style="color: var(--green);" { "✓" }
                                        } @else {
                                            span.ed-grid__flag { "✗ " (tr(lang, "silent", "молчит")) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if !missing.is_empty() {
                p style="font-family: var(--mono); font-size: 11px; color: var(--warm); margin-top: 8px;" {
                    "⚠ " (tr(lang, "declared but NOT listening: ", "заявлено, но НЕ слушает: "))
                    @for (i, (proto, port)) in missing.iter().enumerate() {
                        @if i > 0 { ", " }
                        (proto) "/" (port)
                    }
                    " — " (tr(lang, "re-deploy or check the service on the node", "передеплой или проверь сервис на ноде"))
                }
            }
            @if !extra.is_empty() {
                div.ed-art-eyebrow style="margin-top: 14px;" {
                    (tr(lang, "Listening but undeclared", "Слушает, но не заявлено"))
                    " · " (extra.len()) " "
                    span.ed-tip title=(tr(
                        lang,
                        "Per-user AmneziaWG peers each bind their own UDP port — expected, but the inventory doesn't model them yet (NM-14). This grouping keeps the wall readable; there's nothing to click.",
                        "Каждый пер-пировый порт AmneziaWG — свой UDP-сокет: ожидаемо, но инвентарь их пока не моделирует (NM-14). Группировка держит стену читабельной; кликать тут нечего.",
                    )) { "ⓘ" }
                }
                table.ed-grid style="margin-top: 8px;" {
                    thead {
                        tr {
                            th { (tr(lang, "group", "группа")) }
                            th.num { (tr(lang, "ports", "портов")) }
                            th { (tr(lang, "classification", "классификация")) }
                        }
                    }
                    tbody {
                        @if wg_peers > 0 {
                            tr {
                                td { b { (tr(lang, "wg per-user peers", "wg пер-пировые порты")) } }
                                td.num { (wg_peers) }
                                td.ed-grid__sm { span.ed-grid__flag { "⚠ " (tr(lang, "expected · unmodelled (NM-14)", "ожидаемо · не смоделировано (NM-14)")) } }
                            }
                        }
                        @if !caddy_internals.is_empty() {
                            tr {
                                td { b { "caddy internals" } }
                                td.num { (caddy_internals.len()) }
                                td.ed-grid__mut.ed-grid__sm { (caddy_internals.join(" · ")) " · " (tr(lang, "known-benign", "заведомо безобидно")) }
                            }
                        }
                        @if !unclassified.is_empty() {
                            tr {
                                td { b { (tr(lang, "unclassified", "не классифицировано")) } }
                                td.num { (unclassified.len()) }
                                td.ed-grid__sm { (unclassified.join(" · ")) }
                            }
                        }
                    }
                }
            } @else if missing.is_empty() {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--soft); margin-top: 10px;" {
                    (tr(lang, "Declared and observed match. No drift.", "Заявленное и наблюдаемое совпадают. Дрейфа нет."))
                }
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Migration 0018 — per-(server, protocol) hide + per-(user, server,
// protocol) deny override. Four POST handlers below mirror the
// inventory API (`set_server_protocol_hidden`, `set_grant_protocol_override`)
// 1:1. Each returns 303 to the originating page (server-detail or
// user-detail) so the operator sees post-mutation state without a
// stale form re-submit risk. Audit row is written by the inventory
// layer inside the same transaction — handler itself does NOT call
// `state.inv.audit()` (avoids double-audit).
//
// Convention: action is implied by the path suffix (`/hide` /
// `/unhide` / `/disable` / `/enable`) rather than a `value=` form
// field — keeps the markup template-side simple (one form per
// action button instead of a hidden input + JS).
// ────────────────────────────────────────────────────────────────────────

/// `POST /admin/users/{uid}/grants/{sid}/protocols/{pid}/disable` —
/// insert `grant_protocol_overrides` row with `state='disabled'`.
/// Render path skips this protocol for THIS user's subscription
/// while still emitting it for every other user.
pub(crate) async fn grant_protocol_disable(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str, protocol_id_str)): Path<(String, String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state
        .inv
        .set_grant_protocol_override(&uid, &sid, &pid, true)
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/admin/users/{}/access#server-access",
            path_segment_encode(&user_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

/// `POST /admin/users/{uid}/grants/{sid}/protocols/{pid}/enable` —
/// DELETE the per-user override row, returning the (user, server,
/// protocol) tuple to inherit-from-server-visibility.
pub(crate) async fn grant_protocol_enable(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str, protocol_id_str)): Path<(String, String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state
        .inv
        .set_grant_protocol_override(&uid, &sid, &pid, false)
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/admin/users/{}/access#server-access",
            path_segment_encode(&user_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

// ────────────────────────────────────────────────────────────────────────
//  Phase 5d unit tests — `format_msk` + `extract_ip_from_label`.
//
//  Live in the impl crate (not `tests/admin_smoke.rs`) because the
//  helpers themselves are file-private and the contracts are tiny;
//  adding axum/maud scaffolding for them would dwarf the asserts.
// ────────────────────────────────────────────────────────────────────────
