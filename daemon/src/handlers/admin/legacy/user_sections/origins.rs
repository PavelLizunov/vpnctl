use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use crate::handlers::admin::icons::{icon, status};
use chrono::{DateTime, Utc};
use maud::{Markup, html};

use crate::AppState;
use crate::handlers::admin::helpers::{format_msk, format_msk_iso};
use crate::i18n::{Locale, tr};

pub(crate) async fn user_online_badge(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    server_ids: &[vpnctl_core::ServerId],
    last_seen: Option<DateTime<Utc>>,
    lang: Locale,
) -> Markup {
    let mut conns_per_server: BTreeMap<String, u32> = BTreeMap::new();
    let mut unresolved: HashMap<String, Vec<String>> = HashMap::new();
    for sid in server_ids {
        let Some(snap) = state.snapshot_cache.get_live(sid) else {
            continue;
        };
        for c in &snap.snapshot.connections {
            match c.metadata.user.as_deref() {
                Some(u) if u == uid.0.as_str() => {
                    *conns_per_server.entry(sid.0.clone()).or_insert(0) += 1;
                }
                Some(_) => {}
                None => {
                    if !c.metadata.source_ip.is_empty() {
                        unresolved
                            .entry(c.metadata.source_ip.clone())
                            .or_default()
                            .push(sid.0.clone());
                    }
                }
            }
        }
    }

    if !unresolved.is_empty() {
        let ips: Vec<String> = unresolved.keys().cloned().collect();
        match state.inv.users_for_source_ips(&ips, 7).await {
            Ok(map) => {
                for (ip, candidates) in &map {
                    let owner_is_user = candidates
                        .first()
                        .map(|(u, _)| u.0.as_str() == uid.0.as_str())
                        .unwrap_or(false);
                    if owner_is_user {
                        if let Some(servers) = unresolved.get(ip) {
                            for s in servers {
                                *conns_per_server.entry(s.clone()).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "users_for_source_ips (online badge fallback) failed");
            }
        }
    }

    let total_conns: u32 = conns_per_server.values().copied().sum();
    let online = total_conns > 0;

    html! {
        @if online {
            @let server_count = conns_per_server.len();
            @let server_list = conns_per_server
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            span.ed-stat.ed-stat--active
                title=(tr(
                    lang,
                    "Presence — live from each node's clash-api snapshot (≤5 min old). Connections without a known user are attributed by source IP; unseen IPs remain uncounted.",
                    "Присутствие — live-снимок clash-api каждой ноды (не старше 5 мин). Соединения без известного юзера атрибутируются по source IP; незнакомые IP не учитываются.",
                )) {
                (icon("circle"))
                b { (tr(lang, "online", "онлайн")) }
                " · " (total_conns) " "
                @if total_conns == 1 { (tr(lang, "conn", "соединение")) }
                @else { (tr(lang, "conns", "соединений")) }
                " "
                @if server_count == 1 { (tr(lang, "on ", "на ")) }
                @else { (tr(lang, "across ", "на ")) }
                span.ed-mono { (server_list) }
            }
        } @else {
            span.ed-stat.ed-stat--unknown
                title=(tr(lang, "Presence — no live connection in the latest clash-api snapshots.", "Присутствие — в последних снимках clash-api нет активных соединений.")) {
                (icon("circle-dashed"))
                (tr(lang, "offline", "офлайн"))
                " · "
                @match last_seen {
                    Some(ts) => {
                        @let ago = humanize_since(ts, lang);
                        (tr(lang, "last seen ", "последний раз ")) (ago)
                    }
                    None => (tr(lang, "never connected", "ни разу не подключался")),
                }
            }
        }
    }
}

fn humanize_since(ts: DateTime<Utc>, lang: Locale) -> String {
    let secs = (Utc::now() - ts).num_seconds().max(0);
    if secs < 60 {
        tr(lang, "just now", "только что").to_string()
    } else if secs < 3600 {
        format!("{}{}", secs / 60, tr(lang, "m ago", "м назад"))
    } else if secs < 86_400 {
        format!("{}{}", secs / 3600, tr(lang, "h ago", "ч назад"))
    } else {
        format!("{}{}", secs / 86_400, tr(lang, "d ago", "д назад"))
    }
}

pub(crate) fn user_is_likely_shared(
    aggregates: &vpnctl_inventory::SubAccessAggregates,
    ua_clusters: &[vpnctl_inventory::UaCluster],
) -> bool {
    aggregates.distinct_asns >= 3
        || ua_clusters.iter().any(|c| {
            matches!(
                ua_verdict(c.distinct_ips, c.distinct_slash16),
                UaVerdict::LikelyShared
            )
        })
}

fn format_origin_ts(raw: &str) -> String {
    match DateTime::parse_from_rfc3339(raw) {
        Ok(dt) => format_msk_iso(dt.with_timezone(&Utc)),
        Err(_) => raw.to_string(),
    }
}

pub(in crate::handlers::admin::legacy) fn classify_reserved_ip(ip: &str) -> Option<&'static str> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_private() {
                Some("private/LAN")
            } else if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
                Some("CGNAT")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if v4.is_unspecified() {
                Some("unspecified")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Some("loopback")
            } else if v6.is_unspecified() {
                Some("unspecified")
            } else {
                let seg = v6.segments();
                if (seg[0] & 0xfe00) == 0xfc00 {
                    Some("private/ULA")
                } else if (seg[0] & 0xffc0) == 0xfe80 {
                    Some("link-local")
                } else {
                    None
                }
            }
        }
    }
}

fn ip_geo_fallback(ip: &str, unknown: &str) -> Markup {
    match classify_reserved_ip(ip) {
        Some(cls) => html! { em style="color: var(--mute);" { (cls) } },
        None => html! { em style="color: var(--mute);" { (unknown) } },
    }
}

const ORIGINS_TH: &str = "padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;";
const ORIGINS_TD: &str = "padding: 5px 8px;";

pub(crate) fn user_subscription_origins_section(
    by_country: &[vpnctl_inventory::SubOriginCountry],
    by_asn: &[vpnctl_inventory::SubOriginAsn],
    by_ip: &[vpnctl_inventory::SubOriginIp],
    device_fp: &vpnctl_inventory::SubDeviceFp,
    lang: Locale,
) -> Markup {
    let unknown = tr(lang, "(unknown)", "(неизвестно)");
    let empty = by_country.is_empty() && by_asn.is_empty() && by_ip.is_empty();

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow id="origins" {
            (tr(lang, "Subscription origins", "Источники подписки"))
        }
        @if empty {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
                (tr(
                    lang,
                    "No external subscription fetches recorded — nothing to break down by country, ISP or IP yet.",
                    "Внешних обращений к подписке не записано — пока нечего разбивать по странам, ISP или IP.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "Where this one subscription URL was fetched from over the last 30 days — real client IPs only (VPN-egress excluded). Many countries / ISPs / IPs for a single subscription is the clearest who-is-sharing signal.",
                    "Откуда тянули этот один URL подписки за последние 30 дней — только реальные клиентские IP (VPN-egress исключён). Много стран / ISP / IP на одну подписку — самый явный сигнал, что ссылку расшарили.",
                ))
            }

            @let has_families = device_fp.distinct_device_classes > 0;
            @let lead_n = if has_families { device_fp.distinct_device_classes } else { device_fp.distinct_uas };
            p style="font-family: var(--mono); font-size: 12px; color: var(--ink); margin: 0 0 16px;" {
                "≈ " b { (lead_n) } " "
                @if has_families { (tr(lang, "client families", "клиентских семейств")) }
                @else { (tr(lang, "distinct user-agents", "уникальных user-agent")) }
                " "
                span.ed-tip title=(tr(
                    lang,
                    "«Client families» collapse app-version churn — four Streisand builds count as one client. The raw user-agent count is the upper bound (each version is a distinct string). Clients the UA parser doesn't recognise (the custom ninitux app) leave device_class NULL, so families under-count. TLS fingerprints (JA4) aren't captured — no fingerprint-forwarding proxy is wired.",
                    "«Клиентские семейства» схлопывают версии приложения — четыре сборки Streisand считаются одним клиентом. Сырое число user-agent — верхняя граница (каждая версия — отдельная строка). Клиенты, которых парсер UA не узнаёт (кастомный ninitux), оставляют device_class NULL, поэтому семейства недосчитывают. TLS-отпечатки (JA4) не снимаются — прокси с их форвардингом не подключён.",
                )) { (status("info", lang, "Information", "Информация")) }
                @if has_families {
                    " " span style="color: var(--mute);" {
                        "(" (device_fp.distinct_uas) " " (tr(lang, "distinct UA", "уник. UA")) ")"
                    }
                }
            }

            div.ed-art-eyebrow style="margin-top: 4px;" {
                (tr(lang, "By country", "По странам"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; margin-bottom: 18px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country", "страна")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "fetches", "обращений")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "distinct IPs", "уник. IP")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "distinct ASNs", "уник. ASN")) }
                    }
                }
                tbody {
                    @for row in by_country {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink);")) {
                                @match row.country.as_deref() {
                                    Some(c) if !c.is_empty() => (c),
                                    _ => em style="color: var(--mute);" { (unknown) },
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink);")) { (row.fetches) }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--soft);")) { (row.ips) }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--soft);")) { (row.asns) }
                        }
                    }
                }
            }

            div.ed-art-eyebrow {
                (tr(lang, "By ISP", "По провайдерам"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; margin-bottom: 18px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "ASN / ISP", "ASN / ISP")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country", "страна")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "fetches", "обращений")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "distinct IPs", "уник. IP")) }
                    }
                }
                tbody {
                    @for row in by_asn {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink); overflow-wrap: anywhere;")) {
                                @match row.asn.as_deref() {
                                    Some(a) if !a.is_empty() => (a),
                                    _ => em style="color: var(--mute);" { (unknown) },
                                }
                            }
                            td style=(format!("{ORIGINS_TD} color: var(--soft);")) {
                                @match row.country.as_deref() {
                                    Some(c) if !c.is_empty() => (c),
                                    _ => em style="color: var(--mute);" { (unknown) },
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink);")) { (row.fetches) }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--soft);")) { (row.ips) }
                        }
                    }
                }
            }

            div.ed-art-eyebrow {
                (tr(lang, "By IP", "По IP"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "ip", "ip")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country", "страна")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "ASN / ISP", "ASN / ISP")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "fetches", "обращений")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "first seen", "впервые")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "last seen", "последний раз")) }
                    }
                }
                tbody {
                    @for row in by_ip {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink); overflow-wrap: anywhere;")) { (row.ip) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft);")) {
                                @match row.country.as_deref() {
                                    Some(c) if !c.is_empty() => (c),
                                    _ => (ip_geo_fallback(&row.ip, unknown)),
                                }
                            }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); overflow-wrap: anywhere;")) {
                                @match row.asn.as_deref() {
                                    Some(a) if !a.is_empty() => (a),
                                    _ => (ip_geo_fallback(&row.ip, unknown)),
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink);")) { (row.fetches) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); white-space: nowrap;")) { (format_origin_ts(&row.first_seen)) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); white-space: nowrap;")) { (format_origin_ts(&row.last_seen)) }
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn user_source_ips_section(
    rows: &[vpnctl_inventory::VpnUserSourceIpRow],
    geo: &HashMap<String, (Option<String>, Option<String>)>,
    lang: Locale,
) -> Markup {
    let unknown = tr(lang, "(unknown)", "(неизвестно)");
    let distinct_public = rows
        .iter()
        .filter(|r| classify_reserved_ip(&r.source_ip).is_none())
        .count();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow id="source-ips" {
            (tr(lang, "Source IPs · last 30 days", "Source IP · 30 дней"))
        }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                (tr(
                    lang,
                    "No source-IP history yet. The poller records one hit per (client IP, 5-min tick) a connection was attributed to this user — wait for the next clash-api scrape, or the user simply hasn't connected.",
                    "Истории по source IP ещё нет. Поллер пишет один hit на (клиентский IP, 5-мин тик), в котором соединение отнесено к этому юзеру — подожди следующий скрейп clash-api, либо юзер просто не подключался.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "Which client IPs this user actually connected FROM (real VPN connections, not /sub fetches), over the last 30 days. Activity-weighted: hits = 5-min ticks the IP was live, not bytes. Private / LAN / CGNAT addresses are labelled rather than left as «(unknown)». Many distinct public IPs or countries = the strongest grounded sharing signal.",
                    "С каких клиентских IP юзер реально подключался (реальные VPN-соединения, не обращения к /sub) за 30 дней. Взвешено активностью: hits = 5-мин тики, в которых IP был живой, не байты. Приватные / LAN / CGNAT адреса подписаны, а не оставлены как «(неизвестно)». Много разных публичных IP или стран = самый достоверный сигнал расшаривания.",
                ))
            }
            p style="font-family: var(--mono); font-size: 12px; color: var(--ink); margin: 0 0 14px;" {
                "≈ " b { (distinct_public) } " "
                (tr(lang, "distinct public IPs · 30d", "уник. публичных IP · 30д"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "source ip", "source ip")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country / ISP", "страна / ISP")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}"))
                           title=(tr(lang, "Number of 5-min clash ticks where this user had a live connection from this IP. Not bytes, not connection count — activity time.", "Число 5-мин тиков clash, в которых у юзера было живое соединение с этого IP. Не байты и не число соединений — время активности.")) {
                            (tr(lang, "hits · 30d", "hits · 30д"))
                        }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "last seen", "последний раз")) }
                    }
                }
                tbody {
                    @for r in rows {
                        @let (country, asn) = geo.get(&r.source_ip).cloned().unwrap_or((None, None));
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink); overflow-wrap: anywhere;")) { (r.source_ip) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); overflow-wrap: anywhere;")) {
                                @match country.as_deref() {
                                    Some(c) if !c.is_empty() => {
                                        (c)
                                        @if let Some(a) = asn.as_deref() {
                                            @if !a.is_empty() {
                                                span style="color: var(--mute);" { " · " (a) }
                                            }
                                        }
                                    }
                                    _ => (ip_geo_fallback(&r.source_ip, unknown)),
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink); font-weight: 500;")) { (r.hit_count) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); white-space: nowrap;")) { (format_msk(r.last_seen)) }
                        }
                    }
                }
            }
        }
    }
}

pub(crate) async fn ua_clusters_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    aggregates: &vpnctl_inventory::SubAccessAggregates,
    lang: Locale,
) -> Markup {
    let clusters = match state.inv.ua_clusters_for_user(uid, 24).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "ua_clusters_for_user failed");
            return html! {
                div.ed-rule {}
                div.ed-art-eyebrow { (tr(lang, "UA fingerprint", "Отпечаток User-Agent")) }
                p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                    "(temporarily unavailable — please retry)"
                }
            };
        }
    };
    if clusters.is_empty() {
        return html! {};
    }

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "UA fingerprint · last 24h", "Отпечаток User-Agent · за 24ч"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Heuristic. One device usually roams within one ISP /16, while a shared sub URL spreads across many ISPs. Labels: orange = likely shared, green = likely roaming.",
                "Эвристика. Одно устройство обычно ходит в пределах одного ISP /16, а расшаренный sub URL расползается по разным ISP. Метки: оранжевый = вероятно расшарен, зелёный = вероятно роуминг.",
            ))
        }
        table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
            thead {
                tr style="border-bottom: 1px solid var(--ink);" {
                    th title="Distinct User-Agent strings the subscription URL was pulled with in the last 24h. Each cluster is one row."
                       style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "user-agent" }
                    th title="Total subscription pulls from this UA (one row per /sub/<token> or /api/v1/app/config/<device> GET that produced 200)."
                       style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "hits" }
                    th title="Distinct source IPs that pulled with this UA. Normal mobile client = 1-3 IPs (home wifi + LTE + travel). Many IPs = either roaming heavily or shared URL."
                       style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "ips" }
                    th title="Distinct /16 IPv4 prefixes (≈ISP-scale buckets). One user roaming between LTE + wifi tends to stay in 1-2 /16s. >=3 /16s strongly suggests the subscription URL was shared past one human."
                       style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "/16 nets" }
                    th title="Heuristic classification from (hits, ips, /16 nets): single = one human, roaming = one human on the move, shared = the URL escaped past one human."
                       style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "verdict" }
                }
            }
            tbody {
                @for c in &clusters {
                    @let verdict = ua_verdict(c.distinct_ips, c.distinct_slash16);
                    tr style="border-bottom: 1px dotted var(--rule);" {
                        td style="padding: 5px 8px; color: var(--soft); overflow-wrap: anywhere;" {
                            @match &c.ua {
                                Some(s) => (s),
                                None => em style="color: var(--mute);" { "(no UA)" },
                            }
                        }
                        td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (c.hits) }
                        td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (c.distinct_ips) }
                        td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (c.distinct_slash16) }
                        td style=(verdict.style()) { (verdict.label()) }
                    }
                }
            }
        }
        div style="display: flex; flex-wrap: wrap; gap: 28px; padding: 12px 0 0; font-family: var(--serif); font-size: 12px; color: var(--mute);" {
            span title=(tr(lang, "Distinct ISO country codes the subscription was fetched from over the last 30 days (GeoIP).", "Уникальных ISO-кодов стран, из которых тянули подписку за 30 дней (GeoIP).")) {
                span.ed-mono style="color: var(--ink);" { (aggregates.distinct_countries) }
                " " (tr(lang, "countries · 30d", "стран · 30д"))
            }
            span title=(tr(lang, "Distinct ASN / ISP labels over the last 30 days (GeoIP-ASN).", "Уникальных ASN / ISP за 30 дней (GeoIP-ASN).")) {
                span.ed-mono style="color: var(--ink);" { (aggregates.distinct_asns) }
                " " (tr(lang, "ASNs · 30d", "ASN · 30д"))
            }
            span title=(tr(lang, "Most recent /sub fetch (any IP).", "Последнее обращение к /sub (любой IP).")) {
                (tr(lang, "last seen ", "последний раз "))
                @match aggregates.last_seen {
                    Some(ts) => span.ed-mono style="color: var(--ink);" { (format_msk_iso(ts)) },
                    None => em { (tr(lang, "never", "никогда")) },
                }
            }
        }
    }
}

enum UaVerdict {
    LikelyShared,
    LikelyRoaming,
    Unlabeled,
}

impl UaVerdict {
    fn label(&self) -> &'static str {
        match self {
            Self::LikelyShared => "likely shared URL",
            Self::LikelyRoaming => "likely roaming",
            Self::Unlabeled => "—",
        }
    }
    fn style(&self) -> &'static str {
        match self {
            Self::LikelyShared => "padding: 5px 8px; color: var(--acc); font-style: italic;",
            Self::LikelyRoaming => "padding: 5px 8px; color: var(--soft); font-style: italic;",
            Self::Unlabeled => "padding: 5px 8px; color: var(--mute);",
        }
    }
}

fn ua_verdict(distinct_ips: u64, distinct_slash16: u64) -> UaVerdict {
    if distinct_slash16 >= 3 {
        UaVerdict::LikelyShared
    } else if distinct_ips >= 3 && distinct_slash16 <= 1 {
        UaVerdict::LikelyRoaming
    } else {
        UaVerdict::Unlabeled
    }
}
