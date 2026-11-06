use std::collections::HashMap;

use maud::{Markup, html};

use super::telemetry::status_tile;
use crate::handlers::admin::audit::{action_kind, summarize_audit_payload};
use crate::handlers::admin::helpers::{format_msk_iso, humanize_bytes};
use crate::handlers::admin::legacy::user_sections::{VpnSparklineWindow, window_picker_section};
use crate::http_util::path_segment_encode;
use crate::snapshot_cache::{
    ServerSnapshot, aggregate_by_destination, aggregate_by_source, network_breakdown,
};

pub(super) fn server_detail_live_activity_section(
    activity: &vpnctl_inventory::ServerLiveActivity,
    nic: Option<&vpnctl_inventory::NodeNicUsage>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let last_seen_str = activity
        .last_sample_ts
        .map(format_msk_iso)
        .unwrap_or_else(|| tr(lang, "never", "никогда").to_string());
    let bytes = |f: fn(&vpnctl_inventory::NodeNicUsage) -> u64| {
        nic.map(|u| humanize_bytes(f(u)))
            .unwrap_or_else(|| "—".into())
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Live activity · last 24h", "Живая активность · 24 часа")) }
        p { (tr(lang,
            "Full interface traffic: every VPN protocol, OS traffic and GAP. Connection counts and per-user attribution are shown separately.",
            "Весь трафик интерфейса: все протоколы VPN, трафик ОС и ГЭП. Соединения и атрибуция по пользователям показаны отдельно.")) }
        div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 12px 0 8px;" {
            (status_tile(tr(lang, "active now", "активных сейчас"), &activity.active_now.map(|n| n.to_string()).unwrap_or_else(|| "—".into()), "var(--ink)"))
            (status_tile(tr(lang, "NIC total 24h", "NIC всего 24ч"), &bytes(|u| u.total_bytes), "var(--ink)"))
            (status_tile(tr(lang, "RX incoming 24h", "RX входящий 24ч"), &bytes(|u| u.rx_bytes), "var(--ink)"))
            (status_tile(tr(lang, "TX outgoing 24h", "TX исходящий 24ч"), &bytes(|u| u.tx_bytes), "var(--ink)"))
        }
        @if let Some(u) = nic {
            p { (tr(lang, "NIC measured: ", "NIC измерено: ")) (format_msk_iso(u.first_sample_ts)) " → " (format_msk_iso(u.last_sample_ts))
                " · " (if chrono::Utc::now().timestamp().saturating_sub(u.last_sample_ts.timestamp()) as u64 > crate::server_traffic::max_gap_seconds() { tr(lang, "stale / partial; observed minimum", "устарело / неполно; измеренный минимум") } else if u.complete { tr(lang, "complete coverage", "полное покрытие") } else { tr(lang, "partial coverage; observed minimum", "неполное покрытие; измеренный минимум") })
            }
        } @else { p { (tr(lang, "NIC data unavailable", "Нет данных NIC")) } }
        p { (tr(lang, "last poll: ", "последний поллинг: ")) b { (last_seen_str) }
            " · " (activity.distinct_users_attributed) (tr(lang, " users attributed", " пользователей атрибутировано"))
        }
    }
}

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
    let gap_pct = t
        .gap_bytes
        .saturating_mul(100)
        .checked_div(t.nic_total_bytes)
        .unwrap_or(0)
        .min(100);
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
                "Observed interface traffic includes GAP already. Compare it with attributed VPN traffic: the remainder can include other protocols, OS traffic and overhead. Hoster billing may differ; GAP is not assigned to users.",
                "Измеренный трафик интерфейса уже включает ГЭП. Сравнение с атрибутированным VPN-трафиком: остаток может включать другие протоколы, трафик ОС и оверхед. Учёт хостера может отличаться; ГЭП не начисляется пользователям.",
            ))
        }
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 8px;" {
            div title=(tr(lang, "Total bytes (rx+tx) on the node's default-route interface over 24h, summed from the probe's cumulative counters. This is the real traffic — every protocol, plus overhead.", "Всего байт (rx+tx) на default-route интерфейсе ноды за 24ч, сумма дельт кумулятивных счётчиков probe. Это реальный трафик — все протоколы плюс оверхед.")) {
                (status_tile(tr(lang, "NIC total", "NIC всего"), &humanize_bytes(t.nic_total_bytes), "var(--ink)"))
            }
            div title=(tr(lang, "Bytes clash-api attributed to sing-box protocols (VLESS/REALITY, TUIC, hy2, Trojan, …) over 24h — the part vpnctl can break down per-user.", "Байт, которые clash-api атрибутировал sing-box-протоколам (VLESS/REALITY, TUIC, hy2, Trojan…) за 24ч — часть, которую vpnctl раскладывает по юзерам.")) {
                (status_tile(tr(lang, "sing-box (attributed)", "sing-box (атриб.)"), &humanize_bytes(t.attributed_bytes), "var(--ink)"))
            }
            div title=(tr(lang, "NIC total minus the attributed part: non-sing-box protocols (naive/Caddy) + protocol/OS overhead. This is what vpnctl currently can't see per-user.", "NIC всего минус атрибутированное: не-sing-box протоколы (naive/Caddy) + оверхед протокола/ОС. Это то, что vpnctl сейчас не видит по юзерам.")) {
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

    let mut ip_to_log_user: HashMap<&str, HashMap<&str, u32>> = HashMap::new();
    for c in &snap.connections {
        if let Some(user) = c.metadata.user.as_deref()
            && !c.metadata.source_ip.is_empty()
        {
            *ip_to_log_user
                .entry(c.metadata.source_ip.as_str())
                .or_default()
                .entry(user)
                .or_insert(0) += 1;
        }
    }
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
                "Per-connection detail from clash-api. sing-box does not report the user of a connection, so we attribute connections to users via the source-IP ↔ subscription-fetch IP correlation (last 7 days). Best-effort — accuracy drops for NAT collisions.",
                "Деталь по соединениям из clash-api. sing-box не сообщает юзера соединения, поэтому атрибуция идёт через корреляцию source IP ↔ IP запроса подписки (последние 7 дней). Best-effort — точность падает при коллизии NAT.",
            ))
        }
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
                        "No per-user traffic attributed on this server yet. sing-box does not report users per connection; see the dashboard note. Server-wide totals still work in the traffic chart below.",
                        "Трафик по пользователям на этом сервере пока не атрибутирован. sing-box не сообщает юзера для соединения; см. заметку на дашборде. Серверные итоги всё равно работают в графике трафика ниже.",
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

pub(super) fn server_detail_traffic_section(
    data: &crate::handlers::admin::nic_traffic::NicWindow,
    window: VpnSparklineWindow,
    server_id: &vpnctl_core::ServerId,
    active_now: Option<u32>,
    lang: crate::i18n::Locale,
) -> Markup {
    let base_url = format!(
        "/admin/servers/{}/activity",
        path_segment_encode(&server_id.0)
    );
    html! {
        section id="server-traffic" style="margin-top:28px;" {
            (window_picker_section(&base_url, window.slug, lang))
            (crate::handlers::admin::nic_traffic::panel(data, &[(server_id.clone(), active_now.and_then(|n| usize::try_from(n).ok()))], lang))
        }
    }
}

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
