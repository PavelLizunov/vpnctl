use maud::{Markup, html};
use std::collections::HashMap;
use vpnctl_core::{User, UserId};
use vpnctl_inventory::{
    ProxyMaskedStats, SubAccessAggregates, SubAccessEntry, SubDeviceFp, SubOriginAsn,
    SubOriginCountry, SubOriginIp, VpnUserSourceIpRow,
};

use crate::AppState;
use crate::handlers::admin::helpers::format_msk_iso;
use crate::handlers::admin::legacy::{
    ua_clusters_section, user_sessions_section, user_source_ips_section,
    user_subscription_origins_section,
};
use crate::http_util::path_segment_encode;
use crate::i18n::Locale;
use crate::sharing_score::SharingScore;

const LOG_PAGE_SIZE: i64 = 25;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn render_activity_tab(
    state: &AppState,
    user: &User,
    uid: &UserId,
    proxy_masked: &ProxyMaskedStats,
    sharing: Option<&SharingScore>,
    access_aggregates: &SubAccessAggregates,
    log_total: u64,
    log_page: i64,
    recent_log: &[SubAccessEntry],
    origins_by_country: &[SubOriginCountry],
    origins_by_asn: &[SubOriginAsn],
    origins_by_ip: &[SubOriginIp],
    origins_device_fp: &SubDeviceFp,
    source_ips: &[VpnUserSourceIpRow],
    source_ip_geo: &HashMap<String, (Option<String>, Option<String>)>,
    lang: Locale,
) -> Markup {
    html! {
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
                    @for e in recent_log {
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


            // ── abuse-origins — "Subscription origins" (#origins) ────
            // WHO is sharing: country / ISP / IP breakdown + a rough
            // device-count line. Anchored so the dashboard likely-shared
            // card links straight here. Sits below the verdict (the
            // headline) and above the per-UA table (the /16 evidence).
            (user_subscription_origins_section(
                origins_by_country,
                origins_by_asn,
                origins_by_ip,
                origins_device_fp,
                lang,
            ))

            // ── UA fingerprint (Phase Track-4) + user#7 geo footer ───
            (ua_clusters_section(state, uid, access_aggregates, lang).await)


            // ── Source IPs (2026-06-14) — «откуда» counterpart to the
            // «куда» destinations table: per-client-IP activity grounded
            // in real VPN connections, GeoIP-labelled + reserved-range
            // classified (the «проработай (неизвестно)» + «разбей трафик
            // по IP» deliverable). Pre-fetched above.
            (user_source_ips_section(source_ips, source_ip_geo, lang))

            (user_sessions_section(state, uid, lang).await)


    }
}
