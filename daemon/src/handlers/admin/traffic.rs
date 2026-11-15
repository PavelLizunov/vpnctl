use super::helpers::{format_msk_iso, humanize_bytes};
use crate::{
    http_util::path_segment_encode,
    i18n::{Locale, tr},
    server_traffic::ServerTraffic,
};
use maud::{Markup, html};
use vpnctl_core::ServerId;

fn date(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "—".into())
}

pub(crate) fn summary(t: &ServerTraffic, lang: Locale) -> Markup {
    html! {
        p style="font-family:var(--mono); font-size:12px; margin:6px 0;" { (date(t.period_start)) " → " (date(t.period_end)) }
        @if let Some(u) = &t.usage {
            p style="font-family:var(--mono); font-size:12px; margin:6px 0;" { b { (tr(lang, "Observed: ", "Учтено: ")) (humanize_bytes(u.total_bytes)) }
                " · RX " (humanize_bytes(u.rx_bytes)) " · TX " (humanize_bytes(u.tx_bytes))
            }
            p style="font-family:var(--mono); font-size:12px; margin:6px 0;" { (quality(t, lang)) " · " (tr(lang, "measured ", "измерено ")) (format_msk_iso(u.first_sample_ts)) " → " (format_msk_iso(u.last_sample_ts)) }
        } @else { p style="font-family:var(--mono); font-size:12px; margin:6px 0;" { (tr(lang, "No usable NIC observations", "Нет пригодных сетевых измерений")) } }
        @if let Some(l) = &t.limit {
            p { (tr(lang,"Chargeable usage: ","Расход для лимита: ")) (t.used_bytes().map(humanize_bytes).unwrap_or_else(|| "—".into())) " · " (direction(&l.direction, lang)) }
            p style="font-family:var(--mono); font-size:12px; margin:6px 0;" { (tr(lang, "Limit: ", "Лимит: ")) (humanize_bytes(l.limit_bytes))
                " (" (l.limit_bytes) " B) · " (direction(&l.direction, lang))
                " · " (tr(lang, "warn at ", "предупреждать от ")) (l.warning_pct) "%"
            }
            @if t.percent().is_some_and(|pct| pct >= 100) {
                p role="status" { b { (tr(lang, "Observed usage has reached the limit", "Измеренный расход достиг лимита")) } }
            } @else if t.percent().is_some_and(|pct| pct >= u64::from(l.warning_pct)) {
                p role="status" { b { (tr(lang, "Observed usage has reached the warning threshold", "Измеренный расход достиг порога предупреждения")) } }
            }
            @if t.complete() {
                p style="font-family:var(--mono); font-size:12px; margin:6px 0;" { (t.percent().unwrap_or(0)) "% · " (tr(lang, "remaining: ", "остаток: ")) (humanize_bytes(l.limit_bytes.saturating_sub(t.used_bytes().unwrap_or(0)))) }
            } @else {
                p style="font-family:var(--mono); font-size:12px; margin:6px 0;" { (tr(lang, "Incomplete history: observed usage is a lower bound; remaining quota is unknown.", "История неполная: показан минимум расхода; точный остаток лимита неизвестен.")) }
            }
        } @else { p style="font-family:var(--mono); font-size:12px; margin:6px 0;" { (tr(lang, "Hoster limit not configured", "Лимит хостера не задан")) } }
    }
}

fn direction(value: &str, lang: Locale) -> &'static str {
    match value {
        "rx" => tr(lang, "RX (incoming)", "RX (входящий)"),
        "tx" => tr(lang, "TX (outgoing)", "TX (исходящий)"),
        _ => tr(lang, "RX + TX", "RX + TX"),
    }
}

fn quality(t: &ServerTraffic, lang: Locale) -> &'static str {
    if t.usage.is_none() {
        tr(lang, "unavailable", "нет данных")
    } else if !t.fresh {
        tr(lang, "stale / partial", "устарело / неполно")
    } else if t.complete() {
        tr(lang, "complete coverage", "полное покрытие")
    } else {
        tr(lang, "partial coverage", "неполное покрытие")
    }
}

pub(crate) fn server_section(sid: &ServerId, t: &ServerTraffic, lang: Locale) -> Markup {
    // Bytes expressed in GB with nine fractional digits round-trip every setting.
    let amount = t
        .limit
        .as_ref()
        .map(|l| {
            format!(
                "{}.{:09}",
                l.limit_bytes / 1_000_000_000,
                l.limit_bytes % 1_000_000_000
            )
        })
        .unwrap_or_default();
    let selected = t.limit.as_ref().map_or("both", |l| l.direction.as_str());
    html! {
        div.ed-rule {}
        section id="traffic-limit" {
            h2 { (tr(lang, "Hoster traffic · billing month", "Трафик хостера · расчётный месяц")) }
            p style="font-family:var(--mono); font-size:12px; margin:6px 0;" { (tr(lang, "Default-route interface, all protocols and OS traffic, including GAP. Hoster billing may differ. UTC reset; short months use their last day.", "Основной сетевой интерфейс: все протоколы и трафик ОС, включая ГЭП. Учёт хостера может отличаться. Сброс по UTC; в коротком месяце — в последний день.")) }
            (summary(t, lang))
            form style="display:flex; flex-wrap:wrap; gap:14px; align-items:end; margin-top:14px;" method="post" action=(format!("/admin/servers/{}/traffic-limit", path_segment_encode(&sid.0))) {
                label.ed-field__input style="min-width:150px; flex:1; font-family:var(--mono); font-size:11px;" { (tr(lang, "Monthly limit (empty = disabled)", "Месячный лимит (пусто = отключён)"))
                    input.ed-input name="limit" type="text" inputmode="decimal" value=(amount) placeholder=(tr(lang, "no cap", "нет лимита"));
                }
                label.ed-field__input style="min-width:150px; flex:1; font-family:var(--mono); font-size:11px;" {
                    (tr(lang, "Traffic unit", "Единица трафика"))
                    select.ed-input name="unit" {
                    option value="GB" selected { "GB (10⁹ B)" } option value="TB" { "TB (10¹² B)" }
                    option value="GiB" { "GiB (2³⁰ B)" } option value="TiB" { "TiB (2⁴⁰ B)" }
                    }
                }
                label.ed-field__input style="min-width:150px; flex:1; font-family:var(--mono); font-size:11px;" { (tr(lang, "Hoster counts", "Хостер считает"))
                    select.ed-input name="direction" { @for d in ["rx", "tx", "both"] { option value=(d) selected[d == selected] { (direction(d, lang)) } } }
                }
                label.ed-field__input style="min-width:150px; flex:1; font-family:var(--mono); font-size:11px;" { (tr(lang, "Reset day (UTC)", "День сброса (UTC)"))
                    input.ed-input name="reset_day" type="number" min="1" max="31" value=(t.limit.as_ref().map_or(1, |l| l.reset_day));
                }
                label.ed-field__input style="min-width:150px; flex:1; font-family:var(--mono); font-size:11px;" { (tr(lang, "Warn at %", "Предупреждать от %"))
                    input.ed-input name="warning_pct" type="number" min="1" max="100" value=(t.limit.as_ref().map_or(80, |l| l.warning_pct));
                }
                button.ed-btn type="submit" { (tr(lang, "Save traffic limit", "Сохранить лимит трафика")) }
            }
        }
    }
}

pub(crate) fn fleet(rows: &[(ServerId, ServerTraffic)], lang: Locale) -> Markup {
    html! {
        div.ed-rule {}
        h2 { (tr(lang, "Hoster traffic · billing month", "Трафик хостера · расчётный месяц")) }
        p style="font-family:var(--mono); font-size:12px; margin:6px 0;" { (tr(lang, "Full interface traffic including GAP. Configure a hoster quota in each server's Activity tab.", "Весь трафик интерфейса, включая ГЭП. Лимит хостера задаётся в разделе «Активность» сервера.")) }
        table.ed-grid { thead { tr { th { (tr(lang, "Server", "Сервер")) } th { (tr(lang, "Monthly usage", "Расход за месяц")) } } }
            tbody { @for (sid, t) in rows { tr {
                td { a href=(format!("/admin/servers/{}/activity#traffic-limit", path_segment_encode(&sid.0))) { (&sid.0) } }
                td { (summary(t, lang)) }
            } } }
        }
    }
}
