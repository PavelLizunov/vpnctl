use std::collections::HashSet;

use crate::handlers::admin::icons::icon;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{Markup, html};

use super::tabs;
use super::types::{UserDetailQuery, UserTab};
use crate::AppState;
use crate::handlers::admin::helpers::{
    internal_error, render_page, theme_accent_lang, user_not_found,
};
use crate::handlers::admin::legacy::{
    app_config_url, collect_amnezia_links, collect_awg_links, collect_share_links, detail_tabs,
    mihomo_sub_url, public_base, sub_url, user_online_badge,
};
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

    let pending_deploy_result = state
        .inv
        .servers_pending_deploy_for_user(
            &uid,
            &servers.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        )
        .await;
    let pending_deploy_known = pending_deploy_result.is_ok();
    let pending_deploy_servers = pending_deploy_result.unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid.0, error = %e, "servers_pending_deploy_for_user failed");

            Vec::new()
        });

    let all_servers = state
        .inv
        .list_fleet_servers()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let granted_ids: HashSet<vpnctl_core::ServerId> =
        servers.iter().map(|s| s.id.clone()).collect();

    let mut secrets_per_server = std::collections::HashMap::new();
    let mut peers_per_server = std::collections::HashMap::new();
    let mut hidden_per_server: std::collections::HashMap<
        vpnctl_core::ServerId,
        std::collections::HashMap<vpnctl_core::ProtocolId, bool>,
    > = std::collections::HashMap::new();
    for s in &servers {
        if tab == UserTab::Delivery {
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
        }
        if tab == UserTab::Access {
            let hidden = state
                .inv
                .list_server_protocols_with_hidden(&s.id)
                .await
                .map_err(|e| internal_error(anyhow::Error::new(e)))?;
            hidden_per_server.insert(s.id.clone(), hidden);
        }
    }
    let mut direct_link_servers = Vec::with_capacity(servers.len());
    let mut chain_routes = Vec::new();
    if tab == UserTab::Delivery {
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
    }

    let user_overrides = if tab == UserTab::Access {
        state
            .inv
            .list_protocol_overrides_for_user(&uid)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?
    } else {
        Default::default()
    };

    let share_links = if tab == UserTab::Delivery {
        collect_share_links(
            &state,
            &user,
            &direct_link_servers,
            &secrets_per_server,
            &peers_per_server,
        )
        .await
    } else {
        Default::default()
    };

    let amnezia_links = if tab == UserTab::Delivery {
        collect_amnezia_links(
            &state,
            &user,
            &direct_link_servers,
            &secrets_per_server,
            &peers_per_server,
        )
        .await
    } else {
        Default::default()
    };

    let awg_links = if tab == UserTab::Delivery {
        collect_awg_links(
            &state,
            &user,
            &direct_link_servers,
            &secrets_per_server,
            &peers_per_server,
        )
        .await
    } else {
        Default::default()
    };

    let mut amnezia_files = Vec::new();
    if tab == UserTab::Delivery {
        for server in &servers {
            let (Some(secrets), Some(peers)) = (
                secrets_per_server.get(&server.id),
                peers_per_server.get(&server.id),
            ) else {
                continue;
            };
            for version in [2, 3] {
                if crate::handlers::admin::user_actions::amnezia_conf_available(
                    &state, &user, server, peers, version,
                )
                .await
                .map_err(|_| {
                    internal_error(anyhow::anyhow!(
                        "Unable to verify AmneziaWG delivery settings"
                    ))
                })? {
                    let ctx = vpnctl_core::RenderCtx::with_peers(server, secrets, peers);
                    let ready =
                        crate::handlers::admin::user_actions::amnezia_user_keypair_valid(&user)
                            && crate::handlers::admin::user_actions::amnezia_server_keypair_valid(
                                version, secrets,
                            )
                            && vpnctl_protocols::render_amnezia_conf(version, &ctx, &user).is_ok();
                    amnezia_files.push((server.id.clone(), version, ready));
                }
            }
        }
    }
    let sub_token = user.sub_token.clone();
    let configured_base = if matches!(tab, UserTab::Overview | UserTab::Delivery) {
        state
            .inv
            .get_public_base_url()
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?
    } else {
        Default::default()
    };

    let base = public_base(&headers, configured_base.as_deref());
    let sub_url_str = sub_token.as_deref().map(|t| sub_url(&headers, t));
    let mihomo_sub_url_str = sub_token.as_deref().map(|t| mihomo_sub_url(&base, t));
    // Public base, not the request Host: the QRs are scanned off-LAN.
    let flow_a_sub_url_str = sub_token.as_deref().map(|t| format!("{base}/sub/{t}"));
    let chain_sub_url_str = if chain_routes.is_empty() {
        None
    } else {
        sub_token
            .as_deref()
            .map(|t| format!("{}?format=sing-box", mihomo_sub_url(&base, t)))
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
    let app_device_id = user.vpn_router_device_id.clone();
    let app_config_url_str = app_device_id
        .as_deref()
        .and_then(|id| app_config_url(&base, id));

    let wg_capable_granted: Vec<&vpnctl_core::ServerId> = servers
        .iter()
        .filter(|s| s.enabled_protocols.iter().any(|p| p.0 == "wireguard"))
        .map(|s| &s.id)
        .collect();
    let wg_capable_inventory: Vec<&vpnctl_core::ServerId> = all_servers
        .iter()
        .filter(|s| s.enabled_protocols.iter().any(|p| p.0 == "wireguard"))
        .map(|s| &s.id)
        .collect();

    let last_seen_result = state.inv.user_last_seen(&uid).await;
    let access_aggregates = if matches!(tab, UserTab::Overview | UserTab::Activity)
        || !last_seen_result.as_ref().is_ok_and(Option::is_some)
    {
        state
        .inv
        .sub_access_aggregates_for_user(&uid, 30)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_aggregates_for_user failed");
            vpnctl_inventory::SubAccessAggregates::default()
        })
    } else {
        vpnctl_inventory::SubAccessAggregates::default()
    };

    let traffic_by_server = if tab == UserTab::Overview {
        state
        .inv
        .user_traffic_by_server(&uid, 24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "user_traffic_by_server failed");
            Vec::new()
        })
    } else {
        Default::default()
    };

    let ua_clusters = if tab == UserTab::Overview {
        state.inv.ua_clusters_for_user(&uid, 24).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "ua_clusters_for_user (verdict) failed");
        Vec::new()
    })
    } else {
        Default::default()
    };

    const ORIGINS_WINDOW_DAYS: u32 = 30;
    const ORIGINS_ASN_LIMIT: u32 = 10;
    const ORIGINS_IP_LIMIT: u32 = 15;
    let origins_by_country = if tab == UserTab::Activity {
        state
        .inv
        .sub_access_by_country(&uid, ORIGINS_WINDOW_DAYS)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_by_country failed");
            Vec::new()
        })
    } else {
        Default::default()
    };

    let origins_by_asn = if tab == UserTab::Activity {
        state
        .inv
        .sub_access_by_asn(&uid, ORIGINS_WINDOW_DAYS, ORIGINS_ASN_LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_by_asn failed");
            Vec::new()
        })
    } else {
        Default::default()
    };

    let origins_by_ip = if tab == UserTab::Activity {
        state
        .inv
        .sub_access_by_ip(&uid, ORIGINS_WINDOW_DAYS, ORIGINS_IP_LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_by_ip failed");
            Vec::new()
        })
    } else {
        Default::default()
    };

    let origins_device_fp = if tab == UserTab::Activity {
        state
        .inv
        .sub_access_device_fingerprint(&uid, ORIGINS_WINDOW_DAYS)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_device_fingerprint failed");
            vpnctl_inventory::SubDeviceFp::default()
        })
    } else {
        Default::default()
    };

    const SOURCE_IPS_WINDOW_DAYS: u32 = 30;
    const SOURCE_IPS_LIMIT: u32 = 20;
    let source_ips = if tab == UserTab::Activity {
        state
        .inv
        .top_source_ips_for_user(&uid, SOURCE_IPS_WINDOW_DAYS, SOURCE_IPS_LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "top_source_ips_for_user failed");
            Vec::new()
        })
    } else {
        Default::default()
    };

    let source_ip_geo = if tab == UserTab::Activity {
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
    } else {
        Default::default()
    };

    let lifecycle = if tab == UserTab::Overview {
        state.inv.user_lifecycle(&uid).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "user_lifecycle failed");
        vpnctl_inventory::UserLifecycle {
            created_at: chrono::Utc::now(),
            last_sub_fetch: access_aggregates.last_seen,
            age_days: 0,
        }
    })
    } else {
        vpnctl_inventory::UserLifecycle {
            created_at: chrono::Utc::now(),
            last_sub_fetch: None,
            age_days: 0,
        }
    };

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
    let true_last_seen = last_seen_result
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "user_last_seen failed");
            access_aggregates.last_seen
        })
        .or(access_aggregates.last_seen);

    let online_badge =
        user_online_badge(&state, &uid, &presence_server_ids, true_last_seen, lang).await;

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
                    (icon("arrow-left")) (crate::i18n::tr(lang, "all users", "все пользователи"))
                }
            }
            div.ed-headrow {
                h1.ed-sumbar__h { (user.id.0) }
                (online_badge)
                div.ed-headrow__actions {
                    a href=(format!("/admin/users/{}/delete-confirm", path_segment_encode(&user.id.0)))
                      class="ed-abtn ed-abtn--danger ed-abtn--sm" {
                        (icon("trash-2")) (crate::i18n::tr(lang, "delete…", "удалить…"))
                    }
                }
            }
            div.ed-detail-meta { "uuid " (user.uuid) }

            @if !pending_deploy_servers.is_empty() {
                div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap; border: 1px solid var(--warm); border-left-width: 3px; background: color-mix(in oklab, var(--warm) 9%, var(--paper)); padding: 9px 12px; margin: 12px 0 16px;" {
                    div style="font-family: var(--serif); font-weight: 500; color: var(--warm); font-size: 13px;" {
                        (icon("triangle-alert"))
                        (crate::i18n::tr(
                            lang,
                            "Config not yet deployed to:",
                            "Конфиг ещё не задеплоен на:",
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
                    )) { (icon("info")) }
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
                            (icon("upload"))
                            span data-icon-label {
                                (crate::i18n::tr(lang, "deploy pending ", "задеплоить недостающие "))
                                "(" (pending_deploy_servers.len()) ")"
                            }
                        }
                    }
                }
                pre id="user-deploy-log" hidden
                    style="margin: -8px 0 16px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}
            }

    @let tab_base = format!("/admin/users/{}", path_segment_encode(&user.id.0));
    @let access_tab_label = format!("{} · {}", crate::i18n::tr(lang, "Access", "Доступ"), servers.len());
    (detail_tabs(&tab_base, tab.slug(), &[("overview", crate::i18n::tr(lang, "Overview", "Обзор")), ("delivery", crate::i18n::tr(lang, "Delivery", "Выдача")), ("access", access_tab_label.as_str()), ("activity", crate::i18n::tr(lang, "Activity", "Активность")), ("traffic", crate::i18n::tr(lang, "Traffic", "Трафик"))], lang))
    @match tab {
        UserTab::Overview => {
            (tabs::overview::render_overview_tab(
                &state,
                &user,
                &app_device_id,
                &app_config_url_str,
                &sub_token,
                &sub_url_str,
                &lifecycle,
                true_last_seen,
                &access_aggregates,
                &ua_clusters,
                &traffic_by_server,
                &all_servers,
                &granted_ids,
                lang,
            ).await)
        }
        UserTab::Delivery => {
            (tabs::delivery::render_delivery_tab(
                &state,
                &user,
                &servers,
                app_config_url_str.as_deref(),
                flow_a_sub_url_str.as_deref(),
                sub_token.as_deref(),
                mihomo_sub_url_str.as_deref(),
                &chain_route_summary,
                chain_sub_url_str.as_deref(),
                &amnezia_links,
                &awg_links,
                &amnezia_files,
                &share_links,
                &wg_capable_granted,
                &wg_capable_inventory,
                lang,
            ))
        }
        UserTab::Access => {
            (tabs::access::render_access_tab(
                &state,
                &user,
                &all_servers,
                &granted_ids,
                &pending_deploy_servers,
                pending_deploy_known,
                &user_grant_dates,
                &access_protos,
                &hidden_per_server,
                &user_overrides,
                lang,
            ))
        }
        UserTab::Activity => {
            (tabs::activity::render_activity_tab(
                &state,
                &user,
                &uid,
                &proxy_masked,
                sharing.as_ref(),
                &access_aggregates,
                log_total,
                log_page,
                &recent_log,
                &origins_by_country,
                &origins_by_asn,
                &origins_by_ip,
                &origins_device_fp,
                &source_ips,
                &source_ip_geo,
                lang,
            ).await)
        }
        UserTab::Traffic => {
            (tabs::traffic::render_traffic_tab(
                &state,
                &uid,
                &query,
                lang,
            ).await)
        }
    }
        };
    Ok(render_page(&state, "users", &theme, &accent, lang, body).await)
}
