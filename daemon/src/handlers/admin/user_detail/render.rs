//! User-detail page render coordinator.

use std::collections::HashSet;

use axum::http::HeaderMap;
use axum::response::Response;
use maud::{Markup, html};

use super::overview::user_overview_summary;
use super::types::{UserDetailQuery, UserTab};
use crate::AppState;
use crate::handlers::admin::helpers::{
    format_msk_iso, internal_error, render_page, theme_accent_lang, user_not_found,
};
use crate::handlers::admin::legacy::{
    collect_amnezia_links, collect_awg_links, collect_share_links, detail_tabs,
    live_vpn_stats_section, ninitux_url, qr_svg, share_link_card, sub_url, ua_clusters_section,
    user_detail_per_protocol_grid, user_online_badge, user_sessions_section,
    user_source_ips_section, user_subscription_origins_section, user_top_destinations_section,
    user_traffic_limit_section,
};
use crate::handlers::admin::users::mask_secret;
use crate::http_util::path_segment_encode;

pub(crate) async fn user_detail_render(
    headers: HeaderMap,
    state: AppState,
    user_id_str: String,
    query: UserDetailQuery,
    tab: UserTab,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let uid = vpnctl_core::UserId(user_id_str.clone());

    let user = state
        .inv
        .get_user(&uid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let Some(user) = user else {
        return Err(user_not_found(&user_id_str));
    };

    let servers = state
        .inv
        .subscription_servers_for_user(&uid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // 2026-05-23 quickfix follow-up (Pavel + multiviruss incident):
    // detect servers whose running config doesn't yet include this
    // user's latest state — i.e. user was created / modified after
    // the server's most recent deploy. Surfaces as an amber banner
    // at the top of user-detail so the operator notices BEFORE the
    // user reports «connected but no traffic».
    let pending_deploy_servers: Vec<vpnctl_core::ServerId> = state
        .inv
        .servers_pending_deploy_for_user(&uid, &servers.iter().map(|s| s.id.clone()).collect::<Vec<_>>())
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid.0, error = %e, "servers_pending_deploy_for_user failed");

            Vec::new()
        });

    // Phase C-3.3: also need the FULL inventory of servers so the
    // detail page can show "ungranted" rows with a "grant" button.
    // The set of granted ids lets us split the full list visually.
    let all_servers = state
        .inv
        .list_fleet_servers()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let granted_ids: HashSet<vpnctl_core::ServerId> =
        servers.iter().map(|s| s.id.clone()).collect();

    // Pre-fetch secrets + the granted-users list for every granted
    // server. The users list goes into the RenderCtx so WireGuard's
    // per-user `/32` octet matches the server's `[Peer]` block 1:1
    // (review-agent 2026-05-17 caught a hard-coded `10.66.0.2` that
    // collided across multiple WG users on the same server).
    //
    // Also pre-fetch the (server, protocol) hidden map for every
    // granted server in the same loop (migration 0018 / NM-10).
    // Used by the per-protocol delivery grid below the "Server
    // access" toggles — without it the grid would either N+1-query
    // `is_server_protocol_hidden` per cell or omit the hidden-state
    // label entirely. Loop body now issues 3 sequential queries
    // per granted server (secrets / peers / hidden); servers count
    // is bounded (≤3 in production, ≤10 in any realistic homelab),
    // so each query × server is cheap. If this ever stretches into
    // dozens of granted servers per user, fold the three reads into
    // one JOIN-based helper.
    let mut secrets_per_server = std::collections::HashMap::new();
    let mut peers_per_server = std::collections::HashMap::new();
    let mut hidden_per_server: std::collections::HashMap<
        vpnctl_core::ServerId,
        std::collections::HashMap<vpnctl_core::ProtocolId, bool>,
    > = std::collections::HashMap::new();
    for s in &servers {
        let secrets = state
            .inv
            .list_server_secrets(&s.id)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        secrets_per_server.insert(s.id.clone(), secrets);
        let peers = state
            .inv
            .users_for_server(&s.id)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        peers_per_server.insert(s.id.clone(), peers);
        let hidden = state
            .inv
            .list_server_protocols_with_hidden(&s.id)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        hidden_per_server.insert(s.id.clone(), hidden);
    }
    // Standalone share-link formats cannot represent a sing-box outbound
    // detour. Keep chained targets in the access/grant UI, but never offer a
    // direct URI that bypasses their required entry server. A chain artefact is
    // useful only when this user is also granted the entry server.
    let mut direct_link_servers = Vec::with_capacity(servers.len());
    let mut chain_routes = Vec::new();
    for server in &servers {
        match state
            .inv
            .client_detour_via(&server.id)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?
        {
            Some(entry) => {
                if granted_ids.contains(&entry) {
                    chain_routes.push((server.id.clone(), entry));
                }
            }
            None => direct_link_servers.push(server.clone()),
        }
    }

    // Per-user override map (server_id, protocol_id) → disabled.
    // One query for the whole user; small (typically 0 entries until
    // the operator clicks "block" on a protocol). Empty map = no
    // overrides = inherit every server's visibility verbatim.
    let user_overrides = state
        .inv
        .list_protocol_overrides_for_user(&uid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let share_links = collect_share_links(
        &state,
        &user,
        &direct_link_servers,
        &secrets_per_server,
        &peers_per_server,
    )
    .await;
    // Flow C — AmneziaVPN-native deep-links (vpn://...). Built
    // separately because the format isn't `Protocol::share_link()`
    // semantics — it's an AmneziaVPN-app-specific wrapper around the
    // same WG secret material. `collect_amnezia_links` returns one
    // (server_id, vpn://...) per WG-enabled granted server.
    let amnezia_links = collect_amnezia_links(
        &state,
        &user,
        &direct_link_servers,
        &secrets_per_server,
        &peers_per_server,
    )
    .await;
    // Flow F — awg:// links for the operator's sing-box-lx client app.
    // Only AmneziaWG-capable servers (obfs minted) yield a link.
    let awg_links = collect_awg_links(
        &state,
        &user,
        &direct_link_servers,
        &secrets_per_server,
        &peers_per_server,
    )
    .await;
    let sub_token = user.sub_token.clone();
    let sub_url_str = sub_token.as_deref().map(|t| sub_url(&headers, t));
    let chain_sub_url_str = if chain_routes.is_empty() {
        None
    } else {
        sub_url_str
            .as_ref()
            .map(|url| format!("{url}?format=sing-box"))
    };
    let mut chain_route_labels = Vec::with_capacity(chain_routes.len());
    for (target, entry) in &chain_routes {
        let target_name = state
            .inv
            .server_display_name(target)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?
            .unwrap_or_else(|| target.0.clone());
        let entry_name = state
            .inv
            .server_display_name(entry)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?
            .unwrap_or_else(|| entry.0.clone());
        chain_route_labels.push(format!("{target_name} via {entry_name}"));
    }
    let chain_route_summary = chain_route_labels.join(", ");
    // Phase 3+ ninitux-compat URL: the production endpoint that mobile
    // apps actually fetch. Rendered as the PRIMARY subscription URL
    // (with QR) when the user has a device_id pinned; the legacy
    // `/sub/<token>` URL is demoted to a secondary "LAN fallback"
    // block below it. When no device_id is pinned, falls back to the
    // legacy URL as the primary — kept as an escape hatch for users
    // that haven't been mapped to ninitux yet (operator can pin one
    // via the import script or the future web action).
    let ninitux_device_id = user.vpn_router_device_id.clone();
    let ninitux_url_str = ninitux_device_id.as_deref().and_then(ninitux_url);

    // WireGuard "Flow B" diagnostics — without these the empty-state
    // copy can't tell the operator WHY no WG link rendered. Three
    // distinct cases, each with a different action:
    //   * No grants at all → "grant a server with WG"
    //   * Grants exist, none declares wireguard → name them, say
    //     "enable wireguard in <server>.enabled_protocols OR grant
    //      a different server that runs WG"
    //   * Some granted server DOES declare WG but share_link failed
    //     → fall through to the existing "missing secret / unregistered
    //       protocol" guidance with a journalctl pointer.
    // Servers granted to this user whose enabled_protocols list
    // contains "wireguard". Used by the empty-state classifier.
    let wg_capable_granted: Vec<&vpnctl_core::ServerId> = servers
        .iter()
        .filter(|s| s.enabled_protocols.iter().any(|p| p.0 == "wireguard"))
        .map(|s| &s.id)
        .collect();
    // Servers in the WHOLE inventory (not just granted) that DO
    // declare wireguard — useful as a name-drop when no granted
    // server runs WG. Cheap O(servers * protocols) scan; servers
    // list is already loaded.
    let wg_capable_inventory: Vec<&vpnctl_core::ServerId> = all_servers
        .iter()
        .filter(|s| s.enabled_protocols.iter().any(|p| p.0 == "wireguard"))
        .map(|s| &s.id)
        .collect();

    // Phase 4a — aggregates over the 30-day window for the summary
    // cards above the timeline table. Failure → zeros; cards still
    // render so the page doesn't break (operator sees the
    // diagnostic in journalctl).
    //
    // R2 2026-07-10: the Track-1 24h/7d distinct-IP counters + the
    // 25-row `recent_sub_access_filtered` load left with the legacy
    // «Subscription access» block they fed — the v2 4c tiles + paged
    // geo-log (+ the composite sharing score) carry that signal now.
    let access_aggregates = state
        .inv
        .sub_access_aggregates_for_user(&uid, 30)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_aggregates_for_user failed");
            vpnctl_inventory::SubAccessAggregates::default()
        });

    // PR-User user#2 — per-server traffic split over the last 24h
    // (Q-4b). One query. Failure → empty Vec, which renders the NM-11
    // empty-state explainer rather than a blank card.
    let traffic_by_server = state
        .inv
        .user_traffic_by_server(&uid, 24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "user_traffic_by_server failed");
            Vec::new()
        });
    // PR-User user#4 — UA clusters over the last 24h, fetched here for
    // the sharing-verdict line. `ua_clusters_section` (the per-UA
    // table) keeps its own self-contained query so it stays usable for
    // any future caller; this small bounded query (one window, ≤a few
    // UA rows) is the cost of a consolidated verdict that can't drift
    // from the table's thresholds.
    let ua_clusters = state.inv.ua_clusters_for_user(&uid, 24).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "ua_clusters_for_user (verdict) failed");
        Vec::new()
    });
    // abuse-origins — "Subscription origins" breakdown over the same
    // 30-day window the access cards use. Four grouped, index-backed
    // reads (country / ASN / IP / device-fingerprint), each excluding
    // VPN-egress + NULL-user rows. Failure on any one degrades only that
    // table to its empty-state (the page still renders).
    const ORIGINS_WINDOW_DAYS: u32 = 30;
    const ORIGINS_ASN_LIMIT: u32 = 10;
    const ORIGINS_IP_LIMIT: u32 = 15;
    let origins_by_country = state
        .inv
        .sub_access_by_country(&uid, ORIGINS_WINDOW_DAYS)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_by_country failed");
            Vec::new()
        });
    let origins_by_asn = state
        .inv
        .sub_access_by_asn(&uid, ORIGINS_WINDOW_DAYS, ORIGINS_ASN_LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_by_asn failed");
            Vec::new()
        });
    let origins_by_ip = state
        .inv
        .sub_access_by_ip(&uid, ORIGINS_WINDOW_DAYS, ORIGINS_IP_LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_by_ip failed");
            Vec::new()
        });
    let origins_device_fp = state
        .inv
        .sub_access_device_fingerprint(&uid, ORIGINS_WINDOW_DAYS)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_device_fingerprint failed");
            vpnctl_inventory::SubDeviceFp::default()
        });
    // «Source IPs» (2026-06-14) — per-(user, source_ip) activity over
    // the last 30 days from the persisted `vpn_user_source_ips` counter,
    // then a best-effort GeoIP label lookup for exactly those IPs (geo
    // is an IP attribute, so the lookup is user-independent). Both
    // degrade to an empty table on failure — the page still renders.
    const SOURCE_IPS_WINDOW_DAYS: u32 = 30;
    const SOURCE_IPS_LIMIT: u32 = 20;
    let source_ips = state
        .inv
        .top_source_ips_for_user(&uid, SOURCE_IPS_WINDOW_DAYS, SOURCE_IPS_LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "top_source_ips_for_user failed");
            Vec::new()
        });
    // TT-1 — resolve the clash-api source IPs' geo DIRECTLY from the
    // MMDB, not by borrowing a geo-resolved sub_access_log row for the
    // same IP. The borrow (`geo_labels_for_ips`) broke once the front
    // proxy started masking client IPs: real VPN-connection IPs stopped
    // appearing in sub_access_log, so ~95% of public source IPs showed
    // "(unknown)". Layering: start from the join (covers any IP the
    // MMDB doesn't know but an operator-labelled fetch did), then let
    // the authoritative MMDB win wherever it resolves. Private/CGNAT
    // IPs resolve to None here and fall through to the render's
    // reserved-range classifier, unchanged.
    let source_ip_geo = {
        let ips: Vec<String> = source_ips.iter().map(|r| r.source_ip.clone()).collect();
        let mut map = state.inv.geo_labels_for_ips(&ips).await.unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "geo_labels_for_ips failed");
            std::collections::HashMap::new()
        });
        for ip_str in &ips {
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                if let Some(info) = state.geo.lookup(ip) {
                    let country = info.country_iso.clone();
                    let asn = info.asn_label();
                    // Merge FIELD-WISE, not whole-tuple: the country-MMDB
                    // and ASN-MMDB have independent coverage, so lookup()
                    // can resolve one field and leave the other None. A
                    // whole-tuple insert would clobber a join-provided
                    // ASN whenever only the country resolved (or vice
                    // versa). MMDB wins per-field where it resolves;
                    // join-provided fields it can't resolve survive.
                    if country.is_some() || asn.is_some() {
                        let e = map.entry(ip_str.clone()).or_insert((None, None));
                        if country.is_some() {
                            e.0 = country;
                        }
                        if asn.is_some() {
                            e.1 = asn;
                        }
                    }
                }
            }
        }
        map
    };
    // PR-User user#5 — lifecycle facts (Q-4d). created_at +
    // last_sub_fetch + age_days. On failure compose a defensible
    // fallback from the user's own created_at so the section still
    // renders (created_at is always present for an existing user).
    let lifecycle = state.inv.user_lifecycle(&uid).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "user_lifecycle failed");
        vpnctl_inventory::UserLifecycle {
            created_at: chrono::Utc::now(),
            last_sub_fetch: access_aggregates.last_seen,
            age_days: 0,
        }
    });
    // PR-User user#1 — online-now presence. Walk the in-memory
    // snapshot cache across the granted servers PLUS the full
    // inventory (a connection can land on a server before the grant is
    // reflected, and the cache is cheap to read). Dedup the id set so
    // we don't double-count a server present in both lists.
    let presence_server_ids: Vec<vpnctl_core::ServerId> = {
        let mut seen: HashSet<vpnctl_core::ServerId> = HashSet::new();
        let mut out = Vec::new();
        for s in servers.iter().chain(all_servers.iter()) {
            if seen.insert(s.id.clone()) {
                out.push(s.id.clone());
            }
        }
        out
    };
    // PR-User user#1 — render the presence badge here (it does an
    // async cache + fallback-query read, which the maud `html!` block
    // below can't `.await`). Cheap: in-memory cache reads + at most one
    // bounded `users_for_source_ips` query.
    let online_badge = user_online_badge(
        &state,
        &uid,
        &presence_server_ids,
        access_aggregates.last_seen,
        lang,
    )
    .await;

    // Design v2 group C — tab-scoped data loads.
    // 4c Activity: newest geo-resolved fetch rows + this user's
    // composite sharing score (same scorer as the dashboard panel).
    // v2 4c — 25 rows/page, walked by `?log_page`; `log_total` backs
    // the «of M» count + the older/newer link visibility.
    const LOG_PAGE_SIZE: i64 = 25;
    let log_page = query.log_page();
    let (recent_log, sharing, log_total, proxy_masked) = if tab == UserTab::Activity {
        let log = state
            .inv
            .recent_sub_access_paged(&uid, LOG_PAGE_SIZE, log_page * LOG_PAGE_SIZE)
            .await
            .unwrap_or_default();
        let total = state.inv.sub_access_count_for_user(&uid).await.unwrap_or(0);
        let sc = state
            .inv
            .sharing_signals_all_users(30, 2.0)
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|sig| sig.user_id == uid)
            .map(|sig| crate::sharing_score::score(&sig));
        // TT-2 — proxy-masked accounting over the same 30d window the
        // tiles use, for the honesty banner.
        let masked = state
            .inv
            .sub_access_proxy_masked_stats(&uid, 30)
            .await
            .unwrap_or_default();
        (log, sc, total, masked)
    } else {
        (
            Vec::new(),
            None,
            0,
            vpnctl_inventory::ProxyMaskedStats::default(),
        )
    };
    // 4b Access: per-grant dates + per-server visible protocol lists.
    let (user_grant_dates, access_protos) = if tab == UserTab::Access {
        let dates: std::collections::HashMap<
            vpnctl_core::ServerId,
            Option<chrono::DateTime<chrono::Utc>>,
        > = state
            .inv
            .grant_dates_for_user(&uid)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut protos: std::collections::HashMap<vpnctl_core::ServerId, Vec<String>> =
            std::collections::HashMap::new();
        for srv in &all_servers {
            let v = state
                .inv
                .visible_protocols_for_subscription(&uid, &srv.id)
                .await
                .unwrap_or_default();
            protos.insert(srv.id.clone(), v.into_iter().map(|p| p.0).collect());
        }
        (dates, protos)
    } else {
        Default::default()
    };

    let body = html! {
            nav.ed-crumb {
                a href="/admin/users" style="color: var(--mute); text-decoration: none;" {
                    (crate::i18n::tr(lang, "← all users", "← все пользователи"))
                }
            }
            div.ed-headrow {
                h1.ed-sumbar__h { (user.id.0) }
                (online_badge)
                div.ed-headrow__actions {
                    a href=(format!("/admin/users/{}/delete-confirm", path_segment_encode(&user.id.0)))
                      class="ed-abtn ed-abtn--danger ed-abtn--sm" {
                        (crate::i18n::tr(lang, "delete…", "удалить…"))
                    }
                }
            }
            div.ed-detail-meta { "uuid " (user.uuid) }

            // 2026-05-23 quickfix follow-up — pending-deploy banner.
            // Surfaces servers whose running config doesn't yet include
            // this user's current state. Hidden when empty (quiet
            // dashboard contract). Each server name links straight to
            // its detail page's #deploy-button anchor so one click moves
            // the operator from «I see the warning» to «I'm one click
            // from fixing it».
            //
            // Visual: amber border, prominent at the top so it's
            // noticed before the operator starts copying the QR.
            @if !pending_deploy_servers.is_empty() {
                div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap; border: 1px solid var(--warm); border-left-width: 3px; background: color-mix(in oklab, var(--warm) 9%, var(--paper)); padding: 9px 12px; margin: 12px 0 16px;" {
                    div style="font-family: var(--serif); font-weight: 500; color: var(--warm); font-size: 13px;" {
                        (crate::i18n::tr(
                            lang,
                            "⚠ Config not yet deployed to:",
                            "⚠ Конфиг ещё не задеплоен на:",
                        ))
                        " "
                        @for (i, sid) in pending_deploy_servers.iter().enumerate() {
                            @if i > 0 { ", " }
                            a href=(format!("/admin/servers/{}#deploy-button", path_segment_encode(&sid.0)))
                              style="color: var(--acc); font-family: var(--mono); font-weight: 600;" {
                                (sid.0)
                            }
                        }
                    }
                    span.ed-tip title=(crate::i18n::tr(
                        lang,
                        "Until deploy, the user's sing-box entry is absent: REALITY handshake succeeds but VLESS auth silently drops, so the client can show connected with no traffic.",
                        "До деплоя записи пользователя нет в sing-box: REALITY-рукопожатие проходит, но VLESS-auth молча отказывает, поэтому клиент может показывать подключение без трафика.",
                    )) { "ⓘ" }
                    // One-click fix right here in the user view: deploy
                    // ONLY the pending servers the banner names (was the
                    // fleet-wide deploy-all until 2026-07-10 — one
                    // pending node redeployed the whole fleet).
                    // `data-reload-self` reloads this user page on done
                    // so the banner re-computes and clears. A down node
                    // is reported ✗ in the log; the rest still deploy.
                    div style="margin-left: auto;" {
                        button type="button"
                               data-sse-url=(format!("/admin/users/{}/deploy-pending/sse", path_segment_encode(&user.id.0)))
                               data-log="user-deploy-log"
                               data-reload-self="true"
                               data-busy-label=(crate::i18n::tr(lang, "deploying… (watch the log)", "деплою… (смотри лог)"))
                               data-retry-label=(crate::i18n::tr(lang, "retry deploy", "повторить деплой"))
                               title=(crate::i18n::tr(
                                   lang,
                                   "Deploy the listed servers now — pushes this user's config onto each pending node. Servers that are already up to date are left untouched. Reloads this page when done.",
                                   "Задеплоить перечисленные серверы — пушит конфиг юзера на каждую отставшую ноду. Уже актуальные серверы не трогаются. По завершении страница перезагрузится.",
                               ))
                               class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                            (crate::i18n::tr(lang, "deploy pending ", "задеплоить недостающие "))
                            "(" (pending_deploy_servers.len()) ") →"
                        }
                    }
                }
                pre id="user-deploy-log" hidden
                    style="margin: -8px 0 16px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}
            }

    @let tab_base = format!("/admin/users/{}", path_segment_encode(&user.id.0));
    @let access_tab_label = format!("{} · {}", crate::i18n::tr(lang, "Access", "Доступ"), servers.len());
    (detail_tabs(&tab_base, tab.slug(), &[("overview", crate::i18n::tr(lang, "Overview", "Обзор")), ("delivery", crate::i18n::tr(lang, "Delivery", "Выдача")), ("access", access_tab_label.as_str()), ("activity", crate::i18n::tr(lang, "Activity", "Активность")), ("traffic", crate::i18n::tr(lang, "Traffic", "Трафик"))]))
    @if tab == UserTab::Overview {
        div.ed-user-overview {
            aside.ed-user-overview__sub {
            // Subscription URL + QR — the headline for this page.
            //
            // Two URLs may exist per user post-Phase-5 (ninitux cutover,
            // 2026-05-19):
            //   * PRIMARY: the ninitux production URL
            //     `https://ninitux.com/api/v1/app/config/<device_id>` —
            //     the URL clients actually fetch. Only present when the
            //     user has a `vpn_router_device_id` pinned (33/33
            //     production users do; legacy bash-only or freshly-
            //     created users may not).
            //   * SECONDARY / LAN fallback: the legacy `/sub/<token>`
            //     URL served by vpnctld directly on port 18402. Useful
            //     for LAN debugging and as the fallback artefact for
            //     users without a device_id.
            //
            // The QR encodes the PRIMARY URL when available — that's
            // what a mobile-app user must scan. Showing the LAN URL in
            // the QR (the pre-Phase-5 behaviour) silently broke any
            // share-via-QR workflow because the client app can't reach
            // 192.168.0.236 from outside the operator's LAN. Caught by
            // visual review 2026-05-19; this block is the fix.
            div.ed-art-eyebrow style="margin-top: 28px;" {
                (crate::i18n::tr(lang, "Subscription", "Подписка"))
                " "
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "The QR and URL are the same ready-to-import artefact. ninitux.com is the production endpoint; the legacy token endpoint is the LAN fallback.",
                    "QR и URL — один готовый к импорту артефакт. ninitux.com — production endpoint; старый token endpoint — LAN fallback.",
                )) { "ⓘ" }
            }
            @match (&ninitux_device_id, &ninitux_url_str, &sub_token, &sub_url_str) {
                (Some(device_id), Some(ninitux), _, _) => {
                    // Primary: ninitux production URL — QR scans this.
                    div style="padding: 8px 0;" {
                        (qr_svg(ninitux))
                        div style="font-family: var(--mono); font-size: 11px; line-height: 1.7; min-width: 0;" {
                            div.ed-user-overview__url { (ninitux) }
                            div.ed-user-overview__url title=(device_id) { "device " (device_id) }
                            div style="margin-top: 8px; color: var(--soft); font-family: var(--serif); font-style: italic; font-size: 11px;" {
                                (crate::i18n::tr(lang, "Production URL served via nginx on ", "Production URL подаётся через nginx на "))
                                span.ed-mono { "ninitux.com" }
                                (crate::i18n::tr(lang, " → vpnctld. ", " → vpnctld. "))
                                (crate::i18n::tr(
                                    lang,
                                    "The user's mobile app polls this URL on a fixed schedule (3600s). ",
                                    "Мобильное приложение опрашивает этот URL по таймеру (3600 сек). ",
                                ))
                                (crate::i18n::tr(
                                    lang,
                                    "Share the QR or the URL — both encode the same thing.",
                                    "Отдай QR или URL — кодируют одно и то же.",
                                ))
                            }
                        }
                    }
                    // Legacy LAN fallback — collapsed below the primary,
                    // muted styling, only useful for LAN debugging.
                    @if let (Some(token), Some(legacy_url)) = (sub_token.as_ref(), sub_url_str.as_ref()) {
                        details style="margin-top: 8px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            summary style="cursor: pointer;" { "legacy /sub/<token> fallback (LAN-only)" }
                            div style="padding: 8px 0 0 16px; line-height: 1.7;" {
                                div { span style="color: var(--mute);" { "url   " } (legacy_url) }
                                div { span style="color: var(--mute);" { "token " } (mask_secret(token)) }
                                form method="post"
                                     action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                                     style="margin-top: 10px;" {
                                    button type="submit"
                                           title=(crate::i18n::tr(
                                               lang,
                                               "Mint a new sub_token. Does NOT affect the ninitux URL above — that one is keyed by device_id, which is stable.",
                                               "Сгенерировать новый sub_token. НЕ влияет на ninitux URL выше — тот ключевой по device_id, который стабилен.",
                                           ))
                                           class="ed-abtn ed-abtn--secondary" {
                                        (crate::i18n::tr(lang, "rotate sub-token", "ротировать sub-token"))
                                    }
                                }
                            }
                        }
                    }
                }
                (None, _, Some(token), Some(url)) => {
                    // No device_id pinned — fall back to legacy /sub/<token>
                    // as the primary. Operator should pin a device_id to
                    // unlock the ninitux URL (import script or future web
                    // action).
                    div style="padding: 8px 0;" {
                        (qr_svg(url))
                        div style="font-family: var(--mono); font-size: 11px; line-height: 1.7; min-width: 0;" {
                            div.ed-user-overview__url { (url) }
                            div { span style="color: var(--mute);" { (crate::i18n::tr(lang, "token ", "token ")) } (mask_secret(token)) }
                            div style="margin-top: 12px; color: var(--soft); font-family: var(--serif); font-style: italic;" {
                                (crate::i18n::tr(lang, "Legacy ", "Легаси ")) span.ed-mono { "/sub/<token>" }
                                (crate::i18n::tr(lang, " URL — LAN-only. No ", " URL — только LAN. У этого пользователя нет "))
                                span.ed-mono { "vpn_router_device_id" }
                                (crate::i18n::tr(
                                    lang,
                                    " pinned for this user, so the production ",
                                    ", поэтому production-URL ",
                                ))
                                span.ed-mono { "ninitux.com" }
                                (crate::i18n::tr(lang, " URL is not available yet. Pin one via ", " пока недоступен. Привяжи через "))
                                span.ed-mono { "scripts/import_from_subscription_server.py --apply" } "."
                            }
                            form method="post"
                                 action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                                 style="margin-top: 14px;" {
                                button type="submit"
                                       title=(crate::i18n::tr(
                                           lang,
                                           "Mint a new sub_token; the previous URL stops working immediately",
                                           "Сгенерировать новый sub_token; предыдущий URL перестанет работать немедленно",
                                       ))
                                       class="ed-abtn ed-abtn--warning" {
                                    (crate::i18n::tr(lang, "rotate sub-token", "ротировать sub-token"))
                                }
                            }
                        }
                    }
                }
                _ => {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                        "No sub-token assigned to this user. "
                        form method="post"
                             action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                             style="display: inline; margin-left: 8px;" {
                            button type="submit"
                                   title="Generate this user's FIRST sub-token + the public /sub/<token> URL. Safe — no existing config to invalidate; the user's QR + clients will start working after this."
                                   class="ed-abtn ed-abtn--recovery" {
                                    "mint sub-token"
                                }
                        }
                    }
                }
            }

            // Extra-protocol per-user password — TUIC / naive / Hysteria2 all
            // reuse `tuic_password`. Shown ONLY when absent: a user without it
            // silently gets NO naive/HY2/TUIC links (the cdn 2026-06-07
            // incident). One-click mint turns that silent skip into a fix.
            @if user.tuic_password.is_none() {
                div.ed-rule {}
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "Extra-protocol password", "Пароль доп-протоколов")) }
                div style="padding: 12px 0;" {
                    p style="font-family: var(--serif); color: var(--acc); font-size: 13px; line-height: 1.6;" {
                        (crate::i18n::tr(
                            lang,
                            "⚠ No tuic_password — TUIC, naive and Hysteria2 links can't be minted for this user, so those protocols silently won't appear in their config (VLESS is unaffected).",
                            "⚠ Нет tuic_password — ссылки TUIC, naive и Hysteria2 для этого юзера не собираются, поэтому эти протоколы молча не попадают в его конфиг (VLESS не затронут).",
                        ))
                    }
                    form method="post"
                         action=(format!("/admin/users/{}/tuic-password/mint", path_segment_encode(&user.id.0)))
                         style="margin-top: 10px;" {
                        button type="submit"
                               title=(crate::i18n::tr(
                                   lang,
                                   "Mint this user's per-user password used by TUIC / naive / Hysteria2. Safe — no existing secret to invalidate. Redeploy the user's servers afterwards so the node accepts it.",
                                   "Сгенерировать per-user пароль для TUIC / naive / Hysteria2. Безопасно — нечего инвалидировать. Затем передеплой серверы юзера, чтобы узел принял пароль.",
                               ))
                               class="ed-abtn ed-abtn--recovery" {
                            (crate::i18n::tr(lang, "mint tuic password", "сгенерировать tuic-пароль"))
                        }
                    }
                    p style="font-family: var(--serif); font-style: italic; color: var(--soft); font-size: 12px; margin-top: 8px;" {
                        (crate::i18n::tr(
                            lang,
                            "After minting, redeploy the affected server(s) so the node accepts the new password.",
                            "После генерации передеплой затронутые серверы, чтобы узел принял новый пароль.",
                        ))
                    }
                }
            }
            }
            section {
                (user_overview_summary(
                    &user,
                    (&lifecycle, access_aggregates.last_seen, &access_aggregates, &ua_clusters),
                    &traffic_by_server,
                    (&all_servers, &granted_ids),
                    lang,
                ))
            }
        }

            // WireGuard / AmneziaWG key material + distribution. Always
            // shows the pubkey verbatim (it's public). Private key marker
            // only — actual value flows through `/sub/<token>` (sing-box-
            // style clients) AND as inline QR/share-links below for
            // WG-native clients (AmneziaVPN, official WireGuard app).
            // Per CLAUDE.md "users are low-tech" — the operator must see
            // every artefact needed to onboard the user in one place.
    }
    @if tab == UserTab::Delivery {
        // v2 4a — compact subscription recap on top of Delivery: the
        // one artefact the operator actually hands out, plus the legacy
        // fallback. The QR itself lives on Overview (linked) — the mock
        // duplicates it here; we link instead of double-rendering.
        div.ed-inbar {
            span.ed-inbar__label { (crate::i18n::tr(lang, "subscription", "подписка")) }
            @match (&ninitux_url_str, &sub_url_str) {
                (Some(u), _) | (None, Some(u)) => {
                    span style="font-family: var(--mono); font-size: 10px; color: var(--ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 420px;" { (u) }
                },
                (None, None) => {
                    em.ed-grid__mut { (crate::i18n::tr(lang, "no subscription URL yet — mint a sub-token below", "URL подписки нет — сгенерируй sub-token ниже")) }
                },
            }
            a.ed-grid__open href=(format!("/admin/users/{}", path_segment_encode(&user.id.0))) {
                (crate::i18n::tr(lang, "QR on Overview →", "QR на Обзоре →"))
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "The mobile app polls this URL on a fixed schedule; rotating the sub-token below invalidates the old URL immediately.",
                "Приложение опрашивает этот URL по расписанию; ротация sub-token ниже мгновенно гасит старый URL.",
            )) { "ⓘ" }
            @if let Some(t) = &sub_token {
                span.ed-grid__mut style="margin-left: auto; font-family: var(--mono); font-size: 10px;" {
                    (crate::i18n::tr(lang, "legacy /sub/", "легаси /sub/"))
                    (mask_secret(t))
                    " · " (crate::i18n::tr(lang, "LAN-only fallback", "LAN-only fallback"))
                }
            }
        }
        @if let Some(url) = chain_sub_url_str.as_ref() {
            div style="margin: 20px 0; padding: 16px; border: 1px solid var(--rule);" {
                div.ed-art-eyebrow {
                    (crate::i18n::tr(lang, "Sing-box chain subscription", "Sing-box подписка с цепочкой"))
                }
                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 8px 0;" {
                    (&chain_route_summary)
                }
                (share_link_card(url, &html! {
                    (crate::i18n::tr(
                        lang,
                        "Import this URL when the chained exit is needed. The target disappears automatically if its entry server is unavailable; standalone links remain direct-only.",
                        "Импортируй этот URL, когда нужен выход через цепочку. Целевой сервер автоматически исчезнет, если входной сервер недоступен; отдельные ссылки остаются только прямыми.",
                    ))
                }))
            }
        }
            div.ed-rule {}
            div.ed-art-eyebrow { (crate::i18n::tr(lang, "WireGuard keypair", "WireGuard-пара ключей")) }
            @match (&user.wireguard_pubkey, &user.wireguard_private) {
                (Some(pub_b64), Some(_priv_marker)) => {
                    div style="padding: 12px 0;" {
                        div style="font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                            div { span style="color: var(--mute);" { "pubkey  " } (pub_b64) }
                            div {
                                span style="color: var(--mute);" { "private " }
                                span.ed-mono style="color: var(--acc);" { "✓ stored — served via /sub/<token> only" }
                            }
                        }
                        p style="font-family: var(--serif); font-style: italic; color: var(--soft); font-size: 12px; margin-top: 8px;" {
                            "Both halves were generated when the user was created. Pick the distribution flow matching the user's client app:"
                        }
                        form method="post"
                             action=(format!("/admin/users/{}/wireguard/regenerate", path_segment_encode(&user.id.0)))
                             style="margin-top: 12px;" {
                            button type="submit"
                                   title="Mint a fresh Curve25519 pair. The previous keys stop working — every device using the old config must re-import."
                                   class="ed-abtn ed-abtn--warning" {
                                "rotate WG keypair"
                            }
                        }

                        // Distribution panel — one column per client app.
                        // Same secret material, several wire formats:
                        //   * Flow A — sing-box JSON via /sub/<token> URL
                        //   * Flow B — wireguard:// (official WG app, Hiddify)
                        //   * Flow C — vpn://    (AmneziaVPN)
                        //
                        // Plus a .conf-file download per WG-capable server
                        // as a universal fallback (drag-drop into ANY WG
                        // client incl AmneziaVPN's "File with settings"
                        // button).
                        //
                        // Pre-2026-05-17 (commit `799e28b`) Flow B claimed
                        // to cover BOTH AmneziaVPN and the WG app, but the
                        // `wireguard://?conf=` format AmneziaVPN rejects
                        // with ErrorCode 900 («нет контейнеров») — Amnezia
                        // expects its own `vpn://<base64(qCompress(json))>`
                        // deep-link. Split into B + C; honest labels.
                        //
                        // Grid uses `auto-fit minmax(340px, 1fr)` so the
                        // column count adapts to viewport (3 cols; wraps
                        // to 2x2 on narrower viewports).
                        div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 20px; margin-top: 24px; padding-top: 16px; border-top: 1px dotted var(--rule);" {
                            // Flow A — sing-box / Hiddify subscription URL.
                            // The QR renders the same sub_url shown in the
                            // Subscription block at the top of the page;
                            // duplicated here on purpose so the operator
                            // copies the WG-via-Hiddify link from the same
                            // distribution panel as the WG-native link.
                            div {
                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                    (crate::i18n::tr(lang, "Flow A — Hiddify / Sing-box", "Поток A — Hiddify / Sing-box"))
                                }
                                @match (&sub_token, &sub_url_str) {
                                    (Some(_), Some(url)) => {
                                        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "all granted servers · refreshes on its own",
                                                "все выданные серверы · обновляется само",
                                            ))
                                        }
                                        (share_link_card(url, &html! {
                                            (crate::i18n::tr(
                                                lang,
                                                "Sing-box / Hiddify pulls the full config (every protocol on every granted server, including WireGuard with the private key embedded) and refreshes on its own schedule. ",
                                                "Sing-box / Hiddify тянет полный конфиг (все протоколы на всех выданных серверах, включая WireGuard с приватным ключом) и обновляет сам по расписанию. ",
                                            ))
                                            b { (crate::i18n::tr(
                                                lang,
                                                "Recommended default — one URL covers everything.",
                                                "Рекомендованный default — один URL покрывает всё.",
                                            )) }
                                        }))
                                    }
                                    _ => {
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(lang, "Mint a sub-token in the ", "Сгенерируй sub-token в блоке "))
                                            b { (crate::i18n::tr(lang, "Subscription", "Подписка")) }
                                            (crate::i18n::tr(lang, " block above to populate this card.", " выше, чтобы заполнить эту карточку.", ))
                                        }
                                    }
                                }
                            }
                            // Flow B — official WireGuard app + Hiddify.
                            // The `wireguard://?conf=<base64>` link works
                            // in the official WG mobile/desktop apps and
                            // in Hiddify, NOT in AmneziaVPN (separate Flow
                            // C below covers that).
                            div {
                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                    (crate::i18n::tr(lang, "Flow B — official WireGuard app / Hiddify", "Поток B — официальное WireGuard / Hiddify"))
                                }
                                @let wg_links: Vec<_> = share_links
                                    .iter()
                                    .filter(|(_, pid, _)| pid.0 == "wireguard")
                                    .collect();
                                @if wg_links.is_empty() {
                                    @if servers.is_empty() {
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "No servers granted to this user yet. Grant a server in the ",
                                                "У пользователя пока нет грантов. Выдай сервер в секции ",
                                            ))
                                            b { (crate::i18n::tr(lang, "Server access", "Доступ к серверам")) }
                                            (crate::i18n::tr(
                                                lang,
                                                " section below — if it runs WireGuard, the QR appears here.",
                                                " ниже — если сервер крутит WireGuard, QR появится здесь.",
                                            ))
                                        }
                                    } @else if wg_capable_granted.is_empty() {
                                        // Case B — granted servers exist but
                                        // NONE declare wireguard. Most
                                        // common case for bash-imported
                                        // users (vps-is-01 et al. run
                                        // VLESS/TUIC/Hy2, not WG).
                                        p style="font-family: var(--serif); font-size: 12px; line-height: 1.55; color: var(--ink); margin: 0 0 8px;" {
                                            b { (crate::i18n::tr(
                                                lang,
                                                "Keys exist, but no granted server runs WireGuard.",
                                                "Ключи есть, но ни на одном выданном сервере не крутится WireGuard.",
                                            )) }
                                            (crate::i18n::tr(
                                                lang,
                                                " The user has a WG keypair (see pubkey above), so the moment a WG-capable server is granted — or ",
                                                " У пользователя есть WG-пара ключей (см. pubkey выше), так что в момент когда WG-сервер будет выдан — либо ",
                                            ))
                                            span.ed-mono { "wireguard" }
                                            (crate::i18n::tr(
                                                lang,
                                                " is added to an existing server's ",
                                                " добавится в ",
                                            ))
                                            span.ed-mono { "enabled_protocols" }
                                            (crate::i18n::tr(
                                                lang,
                                                " — the QR will appear here.",
                                                " существующего сервера — QR появится здесь.",
                                            ))
                                        }
                                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 6px;" {
                                            (crate::i18n::tr(lang, "Currently granted: ", "Текущие гранты: "))
                                            @for (i, s) in servers.iter().enumerate() {
                                                @if i > 0 { ", " }
                                                span.ed-mono { (s.id.0) }
                                            }
                                            (crate::i18n::tr(lang, " — none have ", " — ни у одного нет "))
                                            span.ed-mono { "wireguard" }
                                            (crate::i18n::tr(lang, " in their protocol list.", " в списке протоколов."))
                                        }
                                        @if !wg_capable_inventory.is_empty() {
                                            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0;" {
                                                (crate::i18n::tr(
                                                    lang,
                                                    "WG-capable servers in the inventory you could grant: ",
                                                    "WG-серверы в инвентаре, которые можно выдать: ",
                                                ))
                                                @for (i, sid) in wg_capable_inventory.iter().enumerate() {
                                                    @if i > 0 { ", " }
                                                    span.ed-mono { (sid.0) }
                                                }
                                                "."
                                            }
                                        } @else {
                                            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0;" {
                                                (crate::i18n::tr(
                                                    lang,
                                                    "No WG-capable server in the entire inventory. The ",
                                                    "В инвентаре нет ни одного WG-сервера. ",
                                                ))
                                                span.ed-mono { "amneziawg" }
                                                (crate::i18n::tr(lang, " kernel + ", " kernel + "))
                                                span.ed-mono { "wireguard" }
                                                (crate::i18n::tr(
                                                    lang,
                                                    " protocol need to be enabled on the server first — open its Settings page, add the protocol and kernel, then redeploy.",
                                                    " протокол должны быть сначала включены на сервере — открой страницу настроек сервера, добавь протокол и ядро, затем задеплой.",
                                                ))
                                            }
                                        }
                                    } @else {
                                        // Case C — at least one granted
                                        // server DOES declare wireguard but
                                        // share_link failed (most likely:
                                        // missing wireguard.server_public_key
                                        // secret). Existing journalctl
                                        // pointer remains the right action.
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(lang, "Granted servers ", "Выданные серверы "))
                                            @for (i, sid) in wg_capable_granted.iter().enumerate() {
                                                @if i > 0 { ", " }
                                                span.ed-mono { (sid.0) }
                                            }
                                            (crate::i18n::tr(
                                                lang,
                                                " declare wireguard but the share-link render failed. Likely missing ",
                                                " объявляют wireguard, но рендер share-link провалился. Скорее всего нет ",
                                            ))
                                            span.ed-mono { "wireguard.server_public_key" }
                                            " / "
                                            span.ed-mono { "wireguard.server_private_key" }
                                            (crate::i18n::tr(lang, " server secret — open the server's Settings page to review its secrets.", " серверного секрета — открой страницу настроек сервера и проверь секреты."))
                                        }
                                    }
                                } @else {
                                    // R2 2026-07-10: one explainer per flow
                                    // + per-server QRs behind <details> —
                                    // 4 servers × 3 flows used to unroll
                                    // into a 12-QR wall with the same
                                    // paragraph repeated under each.
                                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 8px;" {
                                        (crate::i18n::tr(
                                            lang,
                                            "Opens in the official WireGuard app (mobile + desktop) and Hiddify; the private key is base64-embedded inside. Expand a server for its QR.",
                                            "Открывается в официальном WireGuard (mobile + desktop) и Hiddify; приватный ключ закодирован внутри. Разверни сервер, чтобы показать QR.",
                                        ))
                                    }
                                    @for (sid, _pid, link) in &wg_links {
                                        details style="margin-bottom: 4px; border-bottom: 1px dotted var(--rule);" {
                                            summary style="cursor: pointer; font-family: var(--mono); font-size: 11px; color: var(--ink); padding: 5px 0;" {
                                                (crate::i18n::tr(lang, "server ", "сервер ")) b { (sid.0) }
                                                span style="color: var(--mute);" {
                                                    " · " (link.len()) (crate::i18n::tr(lang, " chars", " символов")) " · QR"
                                                }
                                            }
                                            div style="margin: 8px 0 12px;" {
                                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                                    a href=(format!("/admin/users/{}/wireguard/conf/{}",
                                                                    path_segment_encode(&user.id.0),
                                                                    path_segment_encode(&sid.0)))
                                                      download=(format!("{}-{}.conf", user.id.0, sid.0))
                                                      style="color: var(--mute); text-decoration: underline;" {
                                                        (crate::i18n::tr(lang, "download .conf", "скачать .conf"))
                                                    }
                                                }
                                                (share_link_card(link, &html! {
                                                    (crate::i18n::tr(
                                                        lang,
                                                        "Click the box above to select-all + copy.",
                                                        "Кликни на блок выше, чтобы выделить и скопировать.",
                                                    ))
                                                }))
                                            }
                                        }
                                    }
                                }
                            }
                            // Flow C — AmneziaVPN-native deep link.
                            // Same secret material as Flow B but wrapped
                            // in AmneziaVPN's `vpn://<base64(qCompress(json))>`
                            // container format. Without this card,
                            // AmneziaVPN rejects the Flow B link with
                            // ErrorCode 900 («нет контейнеров»).
                            div {
                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                    (crate::i18n::tr(lang, "Flow C — AmneziaVPN", "Поток C — AmneziaVPN"))
                                }
                                @let amnezia_links: Vec<_> = amnezia_links
                                    .iter()
                                    .collect();
                                @if amnezia_links.is_empty() {
                                    @if servers.is_empty() {
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "Grant a WireGuard-capable server to populate this card.",
                                                "Выдай сервер с WireGuard, чтобы заполнить эту карточку.",
                                            ))
                                        }
                                    } @else if wg_capable_granted.is_empty() {
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "No granted server runs WireGuard yet — add ",
                                                "Ни на одном выданном сервере не крутится WireGuard — добавь ",
                                            ))
                                            span.ed-mono { "wireguard" }
                                            (crate::i18n::tr(
                                                lang,
                                                " to an existing server's protocols on its detail page.",
                                                " в протоколы существующего сервера на странице деталей.",
                                            ))
                                        }
                                    } @else {
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(lang, "Granted WG servers ", "Выданные WG-серверы "))
                                            @for (i, sid) in wg_capable_granted.iter().enumerate() {
                                                @if i > 0 { ", " }
                                                span.ed-mono { (sid.0) }
                                            }
                                            (crate::i18n::tr(
                                                lang,
                                                " — but AmneziaVPN link rendering failed (open the server's Settings page to review its secrets).",
                                                " — но рендер AmneziaVPN-ссылки провалился (открой страницу настроек сервера и проверь секреты).",
                                            ))
                                        }
                                    }
                                } @else {
                                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 8px;" {
                                        (crate::i18n::tr(
                                            lang,
                                            "QR / paste opens in AmneziaVPN (zlib-compressed JSON-container inside); the ",
                                            "QR или вставка открывается в AmneziaVPN (внутри zlib-сжатый JSON-контейнер); ",
                                        ))
                                        span.ed-mono { ".conf" }
                                        (crate::i18n::tr(
                                            lang,
                                            " download is the fallback for AmneziaVPN's ",
                                            " — резерв через ",
                                        ))
                                        em { (crate::i18n::tr(lang, "File with settings", "Файл с настройками")) }
                                        (crate::i18n::tr(lang, " import path. Expand a server for its QR.", ". Разверни сервер, чтобы показать QR."))
                                    }
                                    @for (sid, link) in &amnezia_links {
                                        details style="margin-bottom: 4px; border-bottom: 1px dotted var(--rule);" {
                                            summary style="cursor: pointer; font-family: var(--mono); font-size: 11px; color: var(--ink); padding: 5px 0;" {
                                                (crate::i18n::tr(lang, "server ", "сервер ")) b { (sid.0) }
                                                span style="color: var(--mute);" {
                                                    " · " (link.len()) (crate::i18n::tr(lang, " chars", " символов")) " · QR"
                                                }
                                            }
                                            div style="margin: 8px 0 12px;" {
                                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                                    a href=(format!("/admin/users/{}/wireguard/conf/{}",
                                                                    path_segment_encode(&user.id.0),
                                                                    path_segment_encode(&sid.0)))
                                                      download=(format!("{}-{}.conf", user.id.0, sid.0))
                                                      style="color: var(--mute); text-decoration: underline;" {
                                                        (crate::i18n::tr(lang, "download .conf", "скачать .conf"))
                                                    }
                                                }
                                                (share_link_card(link, &html! {
                                                    (crate::i18n::tr(
                                                        lang,
                                                        "Click the box above to select-all + copy.",
                                                        "Кликни на блок выше, чтобы выделить и скопировать.",
                                                    ))
                                                }))
                                            }
                                        }
                                    }
                                }
                            }
                            // Flow F — AmneziaWG `awg://` link for the
                            // operator's sing-box-lx-based client app. Carries
                            // the per-server obfs (s1/s2/h1-h4 minted by
                            // bootstrap) + the server-generated client key, so
                            // it's a one-tap import. Only renders when at least
                            // one granted server runs the amneziawg kernel
                            // (obfs minted ⇒ a link was produced). Letter F:
                            // A=sub, B=wireguard://, C=AmneziaVPN vpn://,
                            // F=AmneziaWG awg://.
                            @if !awg_links.is_empty() {
                                div {
                                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                        (crate::i18n::tr(lang, "Flow F — AmneziaWG (awg://)", "Поток F — AmneziaWG (awg://)"))
                                    }
                                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 8px;" {
                                        (crate::i18n::tr(
                                            lang,
                                            "Opens in the sing-box-lx-based app — per-server AmneziaWG obfuscation (s1/s2/h1-h4) baked in; one-tap, no on-device key-gen. Expand a server for its QR.",
                                            "Открывается в приложении на sing-box-lx — per-server AmneziaWG-обфускация (s1/s2/h1-h4) уже внутри; один тап, без генерации ключей. Разверни сервер, чтобы показать QR.",
                                        ))
                                    }
                                    @for (sid, link) in &awg_links {
                                        details style="margin-bottom: 4px; border-bottom: 1px dotted var(--rule);" {
                                            summary style="cursor: pointer; font-family: var(--mono); font-size: 11px; color: var(--ink); padding: 5px 0;" {
                                                (crate::i18n::tr(lang, "server ", "сервер ")) b { (sid.0) }
                                                span style="color: var(--mute);" {
                                                    " · " (link.len()) (crate::i18n::tr(lang, " chars", " символов")) " · QR"
                                                }
                                            }
                                            div style="margin: 8px 0 12px;" {
                                                (share_link_card(link, &html! {
                                                    (crate::i18n::tr(
                                                        lang,
                                                        "Click the box above to select-all + copy.",
                                                        "Кликни на блок выше, чтобы выделить и скопировать.",
                                                    ))
                                                }))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                (Some(pub_b64), None) => {
                    // Operator-paranoid path (CLI `--wireguard-pubkey`): only
                    // pubkey present, private stays on the user device. No
                    // rotate button — that'd overwrite the user's privkey
                    // pairing. Operator can `vpnctl user remove` + `add`
                    // to switch flows.
                    div style="padding: 12px 0;" {
                        div style="font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                            div { span style="color: var(--mute);" { "pubkey  " } (pub_b64) }
                            div {
                                span style="color: var(--mute);" { "private " }
                                span.ed-mono style="color: var(--mute);" { "on user device (operator-paranoid path)" }
                            }
                        }
                    }
                }
                (None, _) => {
                    // Should be impossible for users created via the web
                    // form (always auto-gens both). Falls through for
                    // legacy users imported pre-2026-05-16 — show a
                    // self-heal button.
                    div style="padding: 12px 0;" {
                        p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                            (crate::i18n::tr(
                                lang,
                                "No WireGuard keypair on this user. Imported from the legacy bash project, or created before the auto-gen default.",
                                "У этого пользователя нет WireGuard-пары. Импортирован из старого bash-проекта или создан до того как auto-gen стал дефолтом.",
                            ))
                        }
                        form method="post"
                             action=(format!("/admin/users/{}/wireguard/regenerate", path_segment_encode(&user.id.0)))
                             style="margin-top: 8px;" {
                            button type="submit"
                                   title="Mint a fresh Curve25519 keypair for this user (legacy self-heal — only shown when the user has no key on file). No existing WireGuard client config to break."
                                   style="padding: 4px 10px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                "generate WG keypair"
                            }
                        }
                    }
                }
            }

            // Server access (Phase C-3.3) — full server inventory with a
            // per-row grant/revoke form. Granted rows show "✓ access ·
            // [revoke]"; ungranted rows show "[grant]". One POST per
            // click, server returns 303 to this same detail page so the
            // operator sees the post-mutation state immediately.
    }
    @if tab == UserTab::Access {
        // v2 4b — per-server grant/key-state table above the existing
        // per-protocol delivery grid.
        div.ed-art-eyebrow style="margin-top: 12px;" {
            (crate::i18n::tr(lang, "Grants · per-server key state", "Гранты · состояние ключей по серверам")) " "
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Keys are minted at grant time; «on node» means the deployed config actually contains them. Grant + forget-to-deploy is the #1 silent failure — the banner above tracks it.",
                "Ключи чеканятся при гранте; «на ноде» значит, что задеплоенный конфиг реально их содержит. Грант без деплоя — тихий сбой №1, баннер выше его отслеживает.",
            )) { "ⓘ" }
        }
        @let keys_str = {
            let mut parts = vec!["uuid ✓"];
            if user.tuic_password.is_some() { parts.push("tuic ✓"); }
            if user.wireguard_pubkey.is_some() { parts.push("wg ✓"); }
            parts.join(" · ")
        };
        table.ed-grid style="margin-top: 8px;" {
            thead {
                tr {
                    th style="width: 70px;" { (crate::i18n::tr(lang, "server", "сервер")) }
                    th { (crate::i18n::tr(lang, "granted", "выдан")) }
                    th { (crate::i18n::tr(lang, "keys minted", "ключи")) }
                    th { (crate::i18n::tr(lang, "on node", "на ноде")) }
                    th { (crate::i18n::tr(lang, "protocols available", "доступные протоколы")) }
                    th.num style="width: 110px;" {}
                }
            }
            tbody {
                @for srv in &all_servers {
                    @let is_granted = granted_ids.contains(&srv.id);
                    @let is_pending = pending_deploy_servers.contains(&srv.id);
                    @let sid_enc = path_segment_encode(&srv.id.0);
                    @let uid_enc = path_segment_encode(&user.id.0);
                    tr class=(if is_granted && is_pending { "on-warn" } else { "" }) {
                        td { b { (srv.id.0) } }
                        td.ed-grid__sm {
                            @if is_granted {
                                span style="color: var(--green);" { "✓ " }
                                span.ed-grid__mut {
                                    @match user_grant_dates.get(&srv.id).copied().flatten() {
                                        Some(ts) => (format_msk_iso(ts)),
                                        None => "—",
                                    }
                                }
                            } @else {
                                span.ed-grid__mut { "— " (crate::i18n::tr(lang, "not granted", "не выдан")) }
                            }
                        }
                        td.ed-grid__sm {
                            @if is_granted { (keys_str) }
                            @else { span.ed-grid__mut { "—" } }
                        }
                        td.ed-grid__sm {
                            @if !is_granted { span.ed-grid__mut { "—" } }
                            @else if is_pending {
                                span.ed-grid__flag { "⚠ " (crate::i18n::tr(lang, "pending deploy", "ждёт деплоя")) }
                            } @else {
                                span style="color: var(--green);" { "✓" }
                            }
                        }
                        td.ed-grid__mut.ed-grid__sm {
                            @match access_protos.get(&srv.id) {
                                Some(v) if !v.is_empty() => (v.join(" · ")),
                                _ => "—",
                            }
                        }
                        td.num {
                            @if is_granted {
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/revoke"))
                                     style="margin: 0; padding: 0; display: inline;" {
                                    button type="submit" class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                                        (crate::i18n::tr(lang, "revoke →", "отозвать →"))
                                    }
                                }
                            } @else {
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}"))
                                     style="margin: 0; padding: 0; display: inline;" {
                                    button type="submit" class="ed-abtn ed-abtn--sm" {
                                        (crate::i18n::tr(lang, "grant →", "выдать →"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // v2 4b — per-protocol identities, masked (secrets never leave
        // the server unmasked; length hint only — mock's reveal button
        // deliberately not implemented).
        div.ed-art-eyebrow style="margin-top: 16px;" {
            (crate::i18n::tr(lang, "Per-protocol identities", "Идентичности по протоколам"))
        }
        table.ed-feed style="margin: 8px 0 16px;" {
            tbody {
                tr {
                    td.ed-grid__mut style="width: 150px;" { "uuid (vless/tuic)" }
                    td { (user.uuid) }
                }
                tr {
                    td.ed-grid__mut { "tuic password" }
                    td.ed-grid__mut {
                        @match &user.tuic_password {
                            Some(p) => { (mask_secret(p)) " · " (p.chars().count()) "ch" },
                            None => "—",
                        }
                    }
                }
                tr {
                    td.ed-grid__mut { "wg pubkey" }
                    td.ed-grid__mut {
                        @match &user.wireguard_pubkey {
                            Some(k) => { (mask_secret(k)) " · " (k.chars().count()) "ch" },
                            None => "—",
                        }
                    }
                }
                tr {
                    td.ed-grid__mut { "sub-token" }
                    td.ed-grid__mut {
                        @match &user.sub_token {
                            Some(t) => { (mask_secret(t)) " · " (t.chars().count()) "ch" },
                            None => "—",
                        }
                    }
                }
            }
        }
            div.ed-rule {}
            // NM-12 follow-up: the per-grant disable/enable buttons in
            // the per-protocol grid below redirect with the
            // `#server-access` fragment so the operator stays anchored
            // here after a click instead of being scrolled to the top.
            div.ed-art-eyebrow id="server-access" {
                (crate::i18n::t(lang, crate::i18n::K::EyebrowServerAccess))
            }
            @if all_servers.is_empty() {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 12px 0;" {
                    (crate::i18n::tr(
                        lang,
                        "No servers in the inventory yet. Add one from the Servers page wizard (paste IP + root password).",
                        "Серверов в инвентаре ещё нет. Добавь сервер через мастер на странице серверов (вставь IP + root-пароль).",
                    ))
                }
            } @else {
                ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 14px; line-height: 1.8;" {
                    @for s in &all_servers {
                        // Outer li wraps BOTH the grant toggle row AND
                        // (for granted servers only) the per-protocol
                        // delivery grid. Single `border-bottom` keeps the
                        // visual rule between *servers*, not between the
                        // grant toggle and its own grid below.
                        li style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                            div style="display: flex; align-items: baseline; gap: 12px;" {
                                // Server id → link to /admin/servers/{id} in a
                                // new tab (Pavel 2026-05-19: «хочу чтоб через
                                // пользователя можно было открыть страницу
                                // сервера в отдельном окне»). `target="_blank"`
                                // + `rel="noopener"` so the new tab doesn't
                                // share window.opener with the user-detail
                                // page (security hygiene + tab-isolation).
                                span style="flex: 1;" {
                                    a href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0)))
                                      target="_blank"
                                      rel="noopener"
                                      title=(match lang {
                                          crate::i18n::Locale::En => format!("Open /admin/servers/{} in a new tab", s.id.0),
                                          crate::i18n::Locale::Ru => format!("Открыть /admin/servers/{} в новой вкладке", s.id.0),
                                      })
                                      style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                        b { (s.id.0) }
                                    }
                                    " (" span.ed-mono { (s.address) ":" (s.ssh_port) } ", "
                                    (s.kernels.iter().map(|k| k.0.clone()).collect::<Vec<_>>().join("+"))
                                    ")"
                                }
                                @if granted_ids.contains(&s.id) {
                                    span style="font-family: var(--mono); font-size: 11px; color: var(--acc);" {
                                        (crate::i18n::tr(lang, "✓ access", "✓ доступ"))
                                    }
                                    form method="post"
                                         action=(format!("/admin/users/{}/grants/{}/revoke",
                                                         path_segment_encode(&user.id.0),
                                                         path_segment_encode(&s.id.0)))
                                         style="margin: 0;" {
                                        @let title_str = match lang {
                                            crate::i18n::Locale::En => format!("Revoke {}'s access to {}", user.id.0, s.id.0),
                                            crate::i18n::Locale::Ru => format!("Отозвать доступ {} к {}", user.id.0, s.id.0),
                                        };
                                        button type="submit"
                                               title=(title_str)
                                               style="padding: 2px 8px; border: 1px solid var(--rule-s); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--mute); cursor: pointer;" {
                                            (crate::i18n::tr(lang, "revoke", "отозвать"))
                                        }
                                    }
                                } @else {
                                    span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "—" }
                                    form method="post"
                                         action=(format!("/admin/users/{}/grants/{}",
                                                         path_segment_encode(&user.id.0),
                                                         path_segment_encode(&s.id.0)))
                                         style="margin: 0;" {
                                        @let title_str = match lang {
                                            crate::i18n::Locale::En => format!("Grant {} access to {}", user.id.0, s.id.0),
                                            crate::i18n::Locale::Ru => format!("Выдать доступ {} к {}", user.id.0, s.id.0),
                                        };
                                        button type="submit"
                                               title=(title_str)
                                               style="padding: 2px 8px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                            (crate::i18n::tr(lang, "grant", "выдать"))
                                        }
                                    }
                                }
                            }
                            // Per-(user, server, protocol) delivery grid
                            // (migration 0018 / NM-10). Renders ONLY for
                            // GRANTED servers — ungranted ones have no
                            // (user, server) row to attach overrides to,
                            // so `set_grant_protocol_override` would
                            // refuse with Invalid. Each protocol cell
                            // shows its current delivery state +
                            // block/unblock button. Server-hidden
                            // protocols are flagged read-only (operator
                            // adjusts those on /admin/servers/{id}).
                            @if granted_ids.contains(&s.id) {
                                (user_detail_per_protocol_grid(
                                    &user.id,
                                    s,
                                    hidden_per_server.get(&s.id),
                                    &user_overrides,
                                    &state.registry,
                                    lang,
                                ))
                            }
                        }
                    }
                }
            }

    }
    @if tab == UserTab::Delivery {

            // Per-protocol share-links — only meaningful for granted servers.
            // ponytail: collapsed <details> — the Flow cards above already deliver
            // every link with a QR; this raw server×protocol dump (up to ~32 lines)
            // is the copy-all / debug view, not prime-scroll content. Content stays
            // in the DOM (just collapsed), so copy-contract + smoke tests still see it.
            @if !servers.is_empty() {
                details style="margin-top: 24px;" {
                    summary style="cursor: pointer;" {
                        span.ed-art-eyebrow {
                            (crate::i18n::tr(lang, "Per-protocol share links", "Ссылки на отдельные протоколы"))
                        }
                    }
                    @if share_links.is_empty() {
                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin-top: 8px;" {
                            (crate::i18n::tr(
                                lang,
                                "No share-links could be rendered (missing secrets or unregistered protocols). Open each server's Settings page to review its secrets.",
                                "Не удалось отрендерить ни одной ссылки (нет секретов или протокол не зарегистрирован). Открой страницу настроек каждого сервера и проверь секреты.",
                            ))
                        }
                    } @else {
                        ul style="list-style: none; padding: 0; margin-top: 8px; font-family: var(--mono); font-size: 11px; line-height: 1.7; color: var(--soft);" {
                            @for (sid, pid, link) in &share_links {
                                li style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                                    span style="color: var(--mute);" { (sid.0) " · " (pid.0) " · " }
                                    (link)
                                }
                            }
                        }
                    }
                }
            }

    }
    @if tab == UserTab::Activity {
        // TT-2 — proxy-masked honesty banner. When a MATERIAL fraction
        // of the 30d real-client fetches logged the front proxy's IP
        // instead of the client's, the empty geo below is a config gap,
        // not "no data" — say so, with the count/%/date-span + the fix.
        @let pm = &proxy_masked;
        @let masked_pct = pm.masked_rows.saturating_mul(100).checked_div(pm.window_rows).unwrap_or(0);
        @if pm.masked_rows > 0 && masked_pct >= 20 {
            div style="border: 1px solid var(--warm); border-left-width: 3px; background: color-mix(in oklab, var(--warm) 9%, var(--paper)); padding: 9px 12px; margin: 12px 0 4px; font-family: var(--serif); font-size: 12px; line-height: 1.5;" {
                b style="color: var(--warm);" {
                    "⚠ " (pm.masked_rows) (crate::i18n::tr(lang, " of ", " из ")) (pm.window_rows)
                    (crate::i18n::tr(lang, " fetches (", " обращений ("))
                    (masked_pct) (crate::i18n::tr(lang, "%) arrived via the front proxy — client IP not captured.", "%) пришли через фронт-прокси — клиентский IP не пойман."))
                }
                " "
                (crate::i18n::tr(
                    lang,
                    "Those rows carry the proxy's private address, so their country/ISP below is blank and the sharing signal can't see them. This is a reverse-proxy trust gap the daemon can't close itself — the front proxy needs to be trusted in ",
                    "Эти строки несут приватный адрес прокси, поэтому страна/ISP ниже пустые, а сигнал шаринга их не видит. Это разрыв доверия к reverse-proxy, который демон не может закрыть сам — фронт-прокси должен быть доверенным в ",
                ))
                span.ed-mono { "VPNCTLD_TRUSTED_PROXIES" }
                (crate::i18n::tr(lang, " and forward the real client IP via Caddy ", " и передавать реальный клиентский IP через Caddy "))
                span.ed-mono { "header_up X-Real-IP {remote_host}" }
                "."
                @if let (Some(mn), Some(mx)) = (&pm.masked_min_ts, &pm.masked_max_ts) {
                    @if let (Ok(a), Ok(b)) = (chrono::DateTime::parse_from_rfc3339(mn), chrono::DateTime::parse_from_rfc3339(mx)) {
                        " " span style="color: var(--mute);" {
                            "(" (format_msk_iso(a.with_timezone(&chrono::Utc))) " – " (format_msk_iso(b.with_timezone(&chrono::Utc))) ")"
                        }
                    }
                }
            }
        }
        // v2 4c — four fact tiles + the geo-resolved fetch log.
        div.ed-status-strip style="grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 12px;" {
            @let (verdict_txt, verdict_color, score_note) = match &sharing {
                Some(sc) if sc.is_flagged() => (
                    crate::i18n::tr(lang, "likely shared", "вероятно расшарен"),
                    "var(--warm)",
                    format!("{} {} 100", sc.score, crate::i18n::tr(lang, "of", "из")),
                ),
                Some(sc) => (
                    crate::i18n::tr(lang, "single-user", "один пользователь"),
                    "var(--green)",
                    format!("{} {} 100", sc.score, crate::i18n::tr(lang, "of", "из")),
                ),
                None => (
                    crate::i18n::tr(lang, "no data", "нет данных"),
                    "var(--mute)",
                    // Re-audit: the scorer only sees REAL-client rows
                    // (sharing_signals gates on real_client_ip_predicate),
                    // so a fully proxy-masked user is absent from it while
                    // «sub fetches · 30d» (ungated) still shows N. Say
                    // "no real-client fetches" so the note never
                    // contradicts a nonzero fetch tile.
                    crate::i18n::tr(
                        lang,
                        "no real-client fetches in 30d",
                        "нет обращений от реальных клиентов за 30д",
                    )
                    .to_string(),
                ),
            };
            div.ed-status-tile {
                div.ed-status-tile__k {
                    (crate::i18n::tr(lang, "sharing verdict", "вердикт шаринга")) " "
                    span.ed-tip title=(crate::i18n::tr(
                        lang,
                        "Heuristic over the 30-day window. Weights SIMULTANEOUS VPN-connection networks (/24s, from live clash data) + impossible travel between fetches, far above sub-fetch IP diversity — so it can differ from the «client IPs» tile, which counts sub-fetch source IPs.",
                        "Эвристика по 30-дневному окну. Одновременные сети VPN-подключений (/24, из живых данных clash) + невозможные перемещения между обращениями весят намного больше, чем разнообразие source-IP обращений — поэтому может отличаться от плитки «клиентских IP», которая считает source-IP обращений.",
                    )) { "ⓘ" }
                }
                div.ed-status-tile__v style=(format!("color: {verdict_color}; font-size: 14px;")) { (verdict_txt) }
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin-top: 2px;" { (score_note) }
            }
            div.ed-status-tile {
                div.ed-status-tile__k
                    title=(crate::i18n::tr(
                        lang,
                        "Distinct REAL client source IPs of sub-fetches over 30 days — private/reserved/proxy addresses excluded, the same real-client basis the «Subscription origins» section below uses. Proxy-masked fetches still count toward «sub fetches» but don't add a distinct client here. This is fetch-side diversity, not the sharing verdict.",
                        "Уникальные РЕАЛЬНЫЕ клиентские source-IP обращений за 30 дней — приватные/зарезервированные/прокси-адреса исключены, та же основа реальных клиентов, что в разделе «Источники подписки» ниже. Proxy-masked обращения считаются в плитке «обращений · 30д», но не добавляют уникального клиента здесь. Это разнообразие со стороны обращений, а не вердикт шаринга.",
                    )) { (crate::i18n::tr(lang, "client IPs · 30d", "клиентских IP · 30д")) }
                div.ed-status-tile__v { (access_aggregates.distinct_ips) }
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin-top: 2px;" {
                    (crate::i18n::n_of(lang, access_aggregates.distinct_asns, "ASN", "ASNs", "ASN", "ASN", "ASN"))
                    " · "
                    (crate::i18n::n_of(lang, access_aggregates.distinct_countries, "country", "countries", "страна", "страны", "стран"))
                }
            }
            div.ed-status-tile {
                div.ed-status-tile__k { (crate::i18n::tr(lang, "sub fetches · 30d", "обращений · 30д")) }
                div.ed-status-tile__v { (access_aggregates.total_rows) }
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin-top: 2px;" {
                    "+" (access_aggregates.egress_rows) " " (crate::i18n::tr(lang, "via VPN egress", "через VPN-egress"))
                }
            }
            div.ed-status-tile {
                div.ed-status-tile__k { (crate::i18n::tr(lang, "last fetch", "последнее обращение")) }
                div.ed-status-tile__v style="font-size: 14px;" {
                    @match access_aggregates.last_seen {
                        Some(ts) => (format_msk_iso(ts)),
                        None => (crate::i18n::tr(lang, "never", "никогда")),
                    }
                }
            }
        }
        div.ed-art-eyebrow style="margin-top: 14px;" {
            (crate::i18n::tr(lang, "Sub-access log · GeoIP-resolved", "Лог обращений · GeoIP")) " "
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Every fetch of the config URL, resolved against the GeoIP DBs at request time. A local/VPN-range source usually means the client refreshed over its own tunnel.",
                "Каждое обращение к config-URL, обогащённое GeoIP на момент запроса. Локальный/VPN-диапазон обычно значит, что клиент обновлялся через собственный туннель.",
            )) { "ⓘ" }
        }
        // TT-3 — the log is newest-first and UNBOUNDED (all rows, all
        // sources), while the tiles above are a 30d, real-client-only
        // slice. Say so, so «N client IPs» over a visibly-longer log
        // reads as two intentionally-different views, not a bug.
        p style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin: 4px 0 0;" {
            (crate::i18n::tr(
                lang,
                "newest first · every row, all sources — includes proxy-masked and VPN-egress fetches the «client IPs» tile excludes",
                "новые сверху · все строки, все источники — включая proxy-masked и VPN-egress обращения, которые плитка «клиентских IP» исключает",
            ))
        }
        @if recent_log.is_empty() {
            p.ed-grid__mut style="font-family: var(--serif); font-style: italic; font-size: 12px;" {
                (crate::i18n::tr(lang, "No fetches recorded yet.", "Обращений ещё не записано."))
            }
        } @else {
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th style="width: 130px;" { (crate::i18n::tr(lang, "time", "время")) }
                        th style="width: 130px;" { "ip" }
                        th style="width: 90px;" { "geo" }
                        th { "asn" }
                        th { "user-agent" }
                        th.num style="width: 60px;" { (crate::i18n::tr(lang, "result", "код")) }
                    }
                }
                tbody {
                    @for e in &recent_log {
                        tr {
                            td.ed-grid__mut.ed-grid__sm { (format_msk_iso(e.ts)) }
                            td.ed-grid__sm {
                                (e.ip)
                                @if e.is_vpn_egress {
                                    " " span.ed-grid__flag title=(crate::i18n::tr(
                                        lang,
                                        "VPN-egress / local-range source — the fetch came through a tunnel",
                                        "VPN-egress / локальный диапазон — обращение пришло через туннель",
                                    )) { "⚠" }
                                }
                            }
                            td.ed-grid__sm {
                                @match e.geo_country.as_deref() {
                                    Some(c) => (c),
                                    None => span.ed-grid__mut { "—" },
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm {
                                @match e.geo_asn.as_deref() {
                                    Some(a) => (a),
                                    None => "—",
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm {
                                @match e.ua.as_deref() {
                                    Some(ua) => (ua),
                                    None => "—",
                                }
                            }
                            td.num {
                                @if e.status < 400 { span style="color: var(--green);" { (e.status) } }
                                @else { span style="color: var(--red);" { (e.status) } }
                            }
                        }
                    }
                }
            }
        }
        // v2 4c — «showing N of M» + newer/older paging + CSV export.
        @if log_total > 0 {
            @let uid_enc_log = path_segment_encode(&user.id.0);
            @let shown_from = log_page * LOG_PAGE_SIZE + 1;
            @let shown_to = (log_page * LOG_PAGE_SIZE) + recent_log.len() as i64;
            @let has_older = shown_to < log_total as i64;
            div style="display: flex; align-items: center; gap: 14px; margin-top: 8px; font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                span {
                    (crate::i18n::tr(lang, "showing ", "показано "))
                    (shown_from) "–" (shown_to)
                    (crate::i18n::tr(lang, " of ", " из ")) (log_total)
                }
                @if log_page > 0 {
                    a href=(format!("/admin/users/{uid_enc_log}/activity?log_page={}", log_page - 1)) style="color: var(--acc);" {
                        (crate::i18n::tr(lang, "← newer", "← новее"))
                    }
                }
                @if has_older {
                    a href=(format!("/admin/users/{uid_enc_log}/activity?log_page={}", log_page + 1)) style="color: var(--acc);" {
                        (crate::i18n::tr(lang, "older →", "старше →"))
                    }
                }
                a href=(format!("/admin/users/{uid_enc_log}/access.csv")) style="margin-left: auto; color: var(--acc);" {
                    (crate::i18n::tr(lang, "export csv →", "экспорт csv →"))
                }
            }
        }
            // R2 2026-07-10: the legacy «Subscription access» stats+table
            // and the standalone sharing-verdict paragraph duplicated the v2
            // 4c tiles + geo-log above (same aggregates, second 25-row table).
            // Origins / UA / source-IPs / sessions below carry the unique data.

    }
    @if tab == UserTab::Activity {
            // ── abuse-origins — "Subscription origins" (#origins) ────
            // WHO is sharing: country / ISP / IP breakdown + a rough
            // device-count line. Anchored so the dashboard likely-shared
            // card links straight here. Sits below the verdict (the
            // headline) and above the per-UA table (the /16 evidence).
            (user_subscription_origins_section(
                &origins_by_country,
                &origins_by_asn,
                &origins_by_ip,
                &origins_device_fp,
                lang,
            ))

            // ── UA fingerprint (Phase Track-4) + user#7 geo footer ───
            (ua_clusters_section(&state, &uid, &access_aggregates, lang).await)

    }
    @if tab == UserTab::Traffic {
            // R2 2026-07-10: the fixed-24h «Traffic by server» table
            // that used to open this tab duplicated the window-driven
            // per-server table inside Live-VPN-stats below (same
            // numbers at the default 24h window). The live table
            // gained its «total» column; one table remains.

            // ── Live VPN stats (Track-3 chunk 3) + user#6 trend ──────
            // The window picker (24h/7d/30d/all) is now folded INTO this
            // section — it re-fetches the picked window's rows once and
            // drives both the compact `sparkline_svg` trend and the full
            // chart, so the previous page-level picker is gone (it would
            // have rendered a second, duplicate picker).
            (live_vpn_stats_section(&state, &uid, query.vpn_window.as_deref(), lang).await)
            (user_top_destinations_section(&state, &uid, lang).await)

    }
    @if tab == UserTab::Activity {
            // ── Source IPs (2026-06-14) — «откуда» counterpart to the
            // «куда» destinations table: per-client-IP activity grounded
            // in real VPN connections, GeoIP-labelled + reserved-range
            // classified (the «проработай (неизвестно)» + «разбей трафик
            // по IP» deliverable). Pre-fetched above.
            (user_source_ips_section(&source_ips, &source_ip_geo, lang))

            (user_sessions_section(&state, &uid, lang).await)

    }
    @if tab == UserTab::Overview {
            // ── Traffic limit + alert threshold (Pavel D.6c) ──────────
            // Show current month-to-date usage + the configured cap
            // (if any) + an inline form to change both, plus the user#3
            // month-end projection when a cap is set. Re-runs the usage
            // query so the page-after-redirect immediately reflects new
            // limits.
            (user_traffic_limit_section(&state, &uid, lang).await)

            // B1.user (audit 2026-05-22) — soft suspend. Banner +
            // toggle button. When user.disabled = true, an amber banner
            // says «this user is paused»; button reads «enable». When
            // false, just the «disable» button as part of the normal
            // user-detail card flow. No double-submit confirm because
            // the action is fully reversible (one click in either
            // direction, no secrets rotated, no grants lost).
            div.ed-rule {}
            div.ed-art-eyebrow style="margin-top: 24px;" {
                (crate::i18n::tr(lang, "Access state", "Состояние доступа"))
            }
            @if user.disabled {
                div style="border: 1px solid var(--acc); background: var(--paper); padding: 12px 14px; margin: 8px 0;" {
                    div style="font-family: var(--serif); font-weight: 500; color: var(--acc); font-size: 14px;" {
                        (crate::i18n::tr(lang, "user is DISABLED", "пользователь ОТКЛЮЧЁН"))
                    }
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 4px 0 0;" {
                        (crate::i18n::tr(
                            lang,
                            "Subscription endpoints return an empty config. Secrets, sub-token, WG keypair and grants are unchanged — re-enable to restore access byte-for-byte.",
                            "Endpoints подписки возвращают пустой config. Секреты, sub-token, WG-пара и гранты не тронуты — включи обратно, чтобы вернуть доступ байт-в-байт.",
                        ))
                    }
                    form method="post"
                         action=(format!("/admin/users/{}/enable", path_segment_encode(&user.id.0)))
                         style="display: inline; margin-top: 8px;" {
                        button type="submit"
                               class="ed-abtn ed-abtn--primary" {
                            (crate::i18n::tr(lang, "enable user", "включить пользователя"))
                        }
                    }
                }
            } @else {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
                    (crate::i18n::tr(
                        lang,
                        "Pause a user's subscription without rotating secrets or revoking grants. Re-enable later restores access byte-for-byte. Useful for: forgotten phone, paused billing, temporary access freeze.",
                        "Поставь подписку на паузу без ротации секретов и без отзыва грантов. Повторное включение вернёт доступ байт-в-байт. Полезно для: забытого телефона, паузы в оплате, временной заморозки доступа.",
                    ))
                }
                form method="post"
                     action=(format!("/admin/users/{}/disable", path_segment_encode(&user.id.0)))
                     style="display: inline;" {
                    button type="submit"
                           title=(crate::i18n::tr(
                               lang,
                               "Soft mute: /sub/<token> and /api/v1/app/config/<device_id> return an empty config. Everything else is preserved.",
                               "Мягкое отключение: /sub/<token> и /api/v1/app/config/<device_id> возвращают пустой config. Всё остальное сохраняется.",
                           ))
                           class="ed-abtn ed-abtn--warning" {
                        (crate::i18n::tr(lang, "disable user", "отключить пользователя"))
                    }
                }
            }

    }
        };
    Ok(render_page(&state, "users", &theme, &accent, lang, body).await)
}
