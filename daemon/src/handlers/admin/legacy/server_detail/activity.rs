use std::collections::HashMap;

use maud::{Markup, html};

use super::telemetry::status_tile;
use crate::handlers::admin::audit::{action_kind, summarize_audit_payload};
use crate::handlers::admin::helpers::{
    VpnSparklineWindow, format_msk_iso, humanize_bytes, window_picker_section,
};
use crate::handlers::admin::legacy::dashboard::sparkline_svg_scaled;
use crate::http_util::path_segment_encode;
use crate::snapshot_cache::{
    ServerSnapshot, aggregate_by_destination, aggregate_by_source, network_breakdown,
};

/// Phase 4b — server-wide live activity tile (active conns now +\n/// 24h bytes up/down + last poll ts + attributed-users counter).
/// Companion to the per-user «Live VPN stats» section on
/// /admin/users/<id>; that one shows ONE user across all servers,
/// this one shows ALL traffic on ONE server.
///
/// NM-11 caveat surfaced in the empty-state copy: per-user
/// attribution from clash-api is blocked by a sing-box upstream
/// bug (TrackerMetadata.MarshalJSON omits the User field). Server-
/// wide totals work, per-user counts always read 0 until upstream
/// PR lands or operator adopts a forked sing-box build.
pub(super) fn server_detail_live_activity_section(
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
pub(super) fn server_detail_gap_section(
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
pub(super) fn server_detail_live_connections_section(
    server_snap: Option<&ServerSnapshot>,
    source_user_map: &HashMap<String, Vec<(vpnctl_core::UserId, u64)>>,
    dns_ptr_map: &HashMap<String, Option<String>>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
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
    let mut ip_to_log_user: HashMap<&str, HashMap<&str, u32>> = HashMap::new();
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
    let log_ip_winner: HashMap<&str, &str> = ip_to_log_user
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
                                    a href=(format!("/admin/users/{}", path_segment_encode(log_user)))
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
                                        a href=(format!("/admin/users/{}", path_segment_encode(&top_uid.0)))
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

/// server#3 — top users by 24h traffic on THIS server. Reuses
/// humanize_bytes + links each user to /admin/users/{id}. Carries the
/// NM-11 empty-state (prod per-user attribution is NULL upstream —
/// clash-api drops the user field), so an empty `rows` renders an
/// explainer instead of a blank card.
pub(super) fn server_detail_top_users_section(
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
pub(super) fn server_detail_traffic_section(
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
                (sparkline_svg_scaled(&series, 1160, 90, None, false))
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
pub(super) fn server_detail_network_split_section(
    server_snap: Option<&ServerSnapshot>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
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
pub(super) fn server_detail_audit_section(
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
