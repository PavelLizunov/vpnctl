use std::collections::HashMap;

use maud::{Markup, html};
use vpnctl_core::{Server, ServerId};
use vpnctl_inventory::{NodeNicUsage, SqliteInventory, SqliteInventoryError};

use super::helpers::{format_msk_iso, humanize_bytes};
use crate::{
    http_util::path_segment_encode,
    i18n::{Locale, tr},
};

#[derive(Clone)]
pub(crate) struct NicWindow {
    start: i64,
    pub now: i64,
    hours: u32,
    pub nodes: HashMap<ServerId, NodeNicUsage>,
    total_nodes: usize,
    server_ids: Vec<ServerId>,
}

impl NicWindow {
    pub(crate) async fn load(
        inv: &SqliteInventory,
        servers: &[Server],
        now: i64,
        hours: u32,
    ) -> Result<Self, SqliteInventoryError> {
        if ![24, 168, 720, 960].contains(&hours) {
            return Err(SqliteInventoryError::Invalid(
                "unsupported NIC display window".into(),
            ));
        }
        let start = now - i64::from(hours) * 3600;
        let mut nodes = HashMap::new();
        for server in servers {
            if let Some(u) = inv
                .node_nic_usage(
                    &server.id,
                    start,
                    now,
                    crate::server_traffic::max_gap_seconds(),
                )
                .await?
            {
                nodes.insert(server.id.clone(), u);
            }
        }
        Ok(Self {
            start,
            now,
            hours,
            nodes,
            total_nodes: servers.len(),
            server_ids: servers.iter().map(|s| s.id.clone()).collect(),
        })
    }

    fn totals(&self) -> Option<(u64, u64, u64)> {
        if self.nodes.is_empty() {
            return None;
        }
        let (rx, tx) = self.nodes.values().try_fold((0u64, 0u64), |(rx, tx), u| {
            Some((rx.checked_add(u.rx_bytes)?, tx.checked_add(u.tx_bytes)?))
        })?;
        Some((rx, tx, rx.checked_add(tx)?))
    }
}

pub(crate) fn quality(u: &NodeNicUsage, now: i64, lang: Locale) -> &'static str {
    if now.saturating_sub(u.last_sample_ts.timestamp()) as u64
        > crate::server_traffic::max_gap_seconds()
    {
        tr(lang, "stale / partial", "устарело / неполно")
    } else if u.complete {
        tr(lang, "complete coverage", "полное покрытие")
    } else {
        tr(
            lang,
            "partial coverage · observed minimum",
            "неполное покрытие · измеренный минимум",
        )
    }
}

pub(crate) fn hours(slug: &str) -> u32 {
    match slug {
        "7d" => 7 * 24,
        "30d" => 30 * 24,
        "all" => 40 * 24,
        _ => 24,
    }
}

pub(crate) fn panel(w: &NicWindow, active: &[(ServerId, Option<usize>)], lang: Locale) -> Markup {
    let value = |which: usize| {
        w.totals()
            .map(|(rx, tx, total)| humanize_bytes([rx, tx, total][which]))
            .unwrap_or_else(|| "—".into())
    };
    let complete = w.totals().is_some()
        && w.nodes.len() == w.total_nodes
        && w.nodes.values().all(|u| u.complete);
    let total_active = if active.len() == w.total_nodes {
        active
            .iter()
            .try_fold(0usize, |sum, (_, n)| sum.checked_add((*n)?))
    } else {
        None
    };
    let label = match w.hours {
        24 => tr(lang, "24h", "24ч"),
        168 => tr(lang, "7 days", "7 дней"),
        720 => tr(lang, "30 days", "30 дней"),
        _ => tr(
            lang,
            "retained history · up to 40 days",
            "сохранённая история · до 40 дней",
        ),
    };
    let buckets = if w.hours == 24 { 24 } else { w.hours / 24 };
    let step = i64::from(w.hours) * 3600 / i64::from(buckets);
    let mut series = vec![0f64; buckets as usize];
    let mut observed = vec![false; buckets as usize];
    for u in w.nodes.values() {
        for d in &u.deltas {
            let at = d.ts.timestamp();
            if at < w.start || at > w.now {
                continue;
            }
            let idx = ((at - w.start) / step).min(i64::from(buckets) - 1) as usize;
            observed[idx] = true;
            series[idx] += d.rx_bytes as f64 + d.tx_bytes as f64;
        }
    }
    let maximum = series.iter().copied().fold(1.0_f64, f64::max);
    let bar_width = 1160.0 / f64::from(buckets);
    html! {
        section.full-nic-traffic data-source="nic" {
            div.ed-art-eyebrow { (tr(lang,"Full server traffic · ","Полный расход серверов · ")) (label) }
            p { (tr(lang,"RX + TX for every protocol and OS traffic, including GAP. No billing coefficients.","RX + TX всех протоколов и трафика ОС, включая ГЭП. Без тарифных коэффициентов.")) }
            (crate::handlers::admin::status_tile(tr(lang,"active now","активных сейчас"), &total_active.map(|n| n.to_string()).unwrap_or_else(|| "—".into()), "var(--ink)"))
            p { (chrono::DateTime::from_timestamp(w.start,0).map(format_msk_iso).unwrap_or_default()) " → " (chrono::DateTime::from_timestamp(w.now,0).map(format_msk_iso).unwrap_or_default()) }
            p { (tr(lang,"Measured nodes: ","Узлов с измерениями: ")) (w.nodes.len()) " / " (w.total_nodes) " · "
                (if complete { tr(lang,"complete coverage","полное покрытие") } else { tr(lang,"partial coverage · observed minimum","неполное покрытие · измеренный минимум") })
            }
            div style="display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; margin:12px 0;" {
                @for (idx,title) in [(0,"RX"),(1,"TX"),(2,tr(lang,"Total RX + TX","Всего RX + TX"))] {
                    (crate::handlers::admin::status_tile(title, &value(idx), "var(--ink)"))
                }
            }
            @if w.totals().is_some() {
                p { (tr(lang,"Observed deltas by sample end time; gaps are not interpolated.","Измеренные дельты по времени конца замера; пропуски не интерполируются.")) }
                svg viewBox="0 0 1160 110" preserveAspectRatio="xMidYMid meet" style="display:block;width:100%;height:auto;" role="img" aria-label=(tr(lang,"Full NIC traffic chart","График полного сетевого расхода")) {
                    @for (idx, value) in series.iter().enumerate() {
                        @let x = idx as f64 * bar_width;
                        @if observed[idx] {
                            @let height = (value / maximum * 90.0).max(1.0);
                            rect x=(x) y=(100.0-height) width=((bar_width-3.0).max(1.0)) height=(height) fill="var(--acc)" {
                                title { (humanize_bytes(*value as u64)) }
                            }
                        } @else {
                            line x1=(x) x2=(x+bar_width-3.0) y1="105" y2="105" stroke="var(--mute)" {
                                title { (tr(lang,"No observations","Нет измерений")) }
                            }
                        }
                    }
                }
            } @else { p { (tr(lang,"No NIC observations. Open Monitoring to check node probes.","Нет сетевых измерений. Откройте «Мониторинг» для проверки узлов.")) " " a href="/admin/monitoring" { (tr(lang,"Monitoring","Мониторинг")) } } }
            div.ed-grid-wrap { table.ed-grid {
                thead { tr { th { (tr(lang,"Server","Сервер")) } th.num { (tr(lang,"Connections now","Соединений сейчас")) } th.num { "RX" } th.num { "TX" } th.num { (tr(lang,"Total RX + TX","Всего RX + TX")) } th { (tr(lang,"Coverage / last observation","Покрытие / последний замер")) } } }
                tbody { @for sid in &w.server_ids { tr {
                    @let u = w.nodes.get(sid);
                    td { a href=(format!("/admin/servers/{}/activity",path_segment_encode(&sid.0))) { (&sid.0) } }
                    td.num { (active.iter().find(|(id,_)| id==sid).and_then(|(_,c)| *c).map(|c| c.to_string()).unwrap_or_else(|| "—".into())) }
                    td.num { (u.map(|u| humanize_bytes(u.rx_bytes)).unwrap_or_else(|| "—".into())) } td.num { (u.map(|u| humanize_bytes(u.tx_bytes)).unwrap_or_else(|| "—".into())) } td.num { (u.map(|u| humanize_bytes(u.total_bytes)).unwrap_or_else(|| "—".into())) }
                    td { @if let Some(u) = u { (quality(u,w.now,lang)) " · " (format_msk_iso(u.last_sample_ts)) } @else { (tr(lang,"unavailable","нет данных")) } }
                } } }
            } }
        }
    }
}
