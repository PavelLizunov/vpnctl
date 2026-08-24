use maud::Markup;

use crate::handlers::admin::helpers::format_msk_iso;

/// Phase 3c — the «update now» button hits
/// `/admin/settings/geoip/update-now` (SSE source). The button
/// flips into a live log pane that streams stdout/stderr from the
/// `vpnctl geoip-update` subprocess until the terminal Ok/Error
/// event closes the connection.
pub(crate) fn settings_geoip_section(lang: crate::i18n::Locale) -> Markup {
    // anchor target for the monitoring page link
    use crate::i18n::tr;
    let dir = std::env::var_os("VPNCTLD_GEOIP_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/vpnctl/geoip"));
    let city = dir.join("GeoLite2-City.mmdb");
    let asn = dir.join("GeoLite2-ASN.mmdb");
    let describe = |p: &std::path::Path| -> Option<(u64, String)> {
        let meta = std::fs::metadata(p).ok()?;
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                // GeoIP file mtime — render in MSK to match the
                // rest of the operator-facing UI.
                chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0)
                    .map(format_msk_iso)
                    .unwrap_or_else(|| "?".to_string())
            })
            .unwrap_or_else(|| "?".to_string());
        Some((size, mtime))
    };
    let city_meta = describe(&city);
    let asn_meta = describe(&asn);
    let any_loaded = city_meta.is_some() || asn_meta.is_some();
    maud::html! {
        div #geoip.ed-art-eyebrow {
            (tr(lang, "GeoIP — IP enrichment", "GeoIP — обогащение IP-адресов"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "When the DB-IP Lite (or MaxMind GeoLite2) MMDB files are present in this dir, every new sub_access_log row is enriched with country ISO + ASN before being persisted. Old rows + dimensions the DB doesn't recognise stay NULL — render falls back to bare IP. The DBs are queried OFFLINE — no network requests during request handling.",
                "Когда в этой папке лежат файлы DB-IP Lite (или MaxMind GeoLite2) в формате MMDB, каждая новая строка sub_access_log обогащается ISO-кодом страны + ASN перед сохранением. Старые строки и dimensions, которые DB не распознала, остаются NULL — рендер откатывается к голому IP. БД читаются ОФФЛАЙН — никаких сетевых запросов на пути запроса.",
            ))
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin-bottom: 12px;" {
            div { (tr(lang, "dir   ", "папка ")) (dir.display()) }
            div {
                "City  "
                @match &city_meta {
                    Some((size, mtime)) => {
                        b style="color: var(--soft);" {
                            (tr(lang, "present", "загружен"))
                        }
                        " · " (size) " " (tr(lang, "bytes", "байт"))
                        " · " (tr(lang, "modified ", "изменён "))
                        (mtime)
                    }
                    None => {
                        em style="color: var(--mute);" {
                            (tr(lang, "(missing — use the «update now» button below)", "(отсутствует — нажми «обновить сейчас» ниже)"))
                        }
                    }
                }
            }
            div {
                "ASN   "
                @match &asn_meta {
                    Some((size, mtime)) => {
                        b style="color: var(--soft);" {
                            (tr(lang, "present", "загружен"))
                        }
                        " · " (size) " " (tr(lang, "bytes", "байт"))
                        " · " (tr(lang, "modified ", "изменён "))
                        (mtime)
                    }
                    None => {
                        em style="color: var(--mute);" {
                            (tr(lang, "(missing — use the «update now» button below)", "(отсутствует — нажми «обновить сейчас» ниже)"))
                        }
                    }
                }
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            @if any_loaded {
                (tr(
                    lang,
                    "Update once a month with the ",
                    "Обновлять раз в месяц кнопкой ",
                ))
            } @else {
                (tr(
                    lang,
                    "Drop fresh MMDB files into the dir + restart the daemon, or use the ",
                    "Положи свежие MMDB-файлы в папку + перезапусти демон, либо используй ",
                ))
            }
            span.ed-mono { (tr(lang, "update now", "обновить сейчас")) }
            (tr(
                lang,
                " button below. It downloads DB-IP Lite (CC-BY 4.0, no signup) and atomic-renames the .mmdb files into this dir, then reloads the DB.",
                " ниже. Она скачивает DB-IP Lite (CC-BY 4.0, без регистрации) и атомарно подменяет .mmdb-файлы в этой папке, затем перезагружает БД.",
            ))
        }
        // ── «update now» button (Phase 3c, CSP-safe since 2026-06-10) ──
        // Operator clicks → live log pane streams from
        // /admin/settings/geoip/update-now. Wired through admin.js's
        // generic `[data-sse-url]` trigger — the original inline
        // `<script>` + `onclick` were silently REFUSED by the admin CSP
        // (`script-src 'self'`, no 'unsafe-inline'), so the button did
        // nothing in a real browser (audit 2026-06-10). The geoip
        // runner's step/ok/error event shapes parse fine in the generic
        // handler (no `phase` field → message renders bare; terminal
        // `ok` has no redirect → admin.js reloads this page, which
        // also refreshes the file-status lines above). Idempotent
        // server-side: a concurrent click hits the 1-permit semaphore
        // and streams an «already running» error event.
        div style="margin: 14px 0;" {
            button id="geoip-update-now-btn"
                   type="button"
                   data-sse-url="/admin/settings/geoip/update-now"
                   data-log="geoip-update-now-log"
                   data-busy-label=(tr(lang, "running…", "запущено…"))
                   data-retry-label=(tr(lang, "retry", "повторить"))
                   style="font-family: var(--mono); font-size: 12px; padding: 6px 14px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); cursor: pointer;"
                   title=(tr(
                       lang,
                       "Spawn the geoip-update subprocess on the daemon host and stream its progress here. Same action the monthly timer fires.",
                       "Запустить подпроцесс geoip-update на хосте демона и показать прогресс здесь. То же действие, что и ежемесячный таймер.",
                   )) {
                (tr(lang, "update now", "обновить сейчас"))
            }
            pre id="geoip-update-now-log" hidden
                style="margin: 10px 0 0; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}
        }
    }
}
