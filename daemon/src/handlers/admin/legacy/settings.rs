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
/// Render the «GeoIP — IP enrichment» section on Settings.
///
/// Reads `VPNCTLD_GEOIP_DIR` (defaults to `/var/lib/vpnctl/geoip`)
/// and reports per-file: present? last-modified? size?
///
/// Phase 5e — «Disaster recovery» single-glance summary in Settings.
///
/// Consolidates the operator's «what if 236 burns?» story onto one
/// screen:
///
///   1. Where the backups live (3 tiers: local hourly Rust snapshots,
///      daily encrypted bundle on 207, off-site daily bundle on
///      Iceland).
///   2. What's in each bundle (so the operator knows BEFORE the
///      disaster what they'll get back — chiefly the deploy SSH
///      key, without which a restored vpnctld is locked out of every
///      VPN node).
///   3. Last restore self-test result (from `audit_log` —
///      `backup.self_test` action) — with a "run again" button.
///   4. The restore procedure (3 steps).
///
/// All text is bilingual (EN/RU). No new persistence — the last-
/// test status is read from `audit_log` via a 50-row tail filtered
/// in the caller. If `last_self_test` is `None` the section renders
/// «not yet run» + the call-to-action.
///
/// Operator-policy compliance: this section lists shell commands
/// (`age -d`, `vpnctl restore`, `systemctl restart vpnctld`) — all
/// covered by the «daemon literally can't help» exception in
/// CLAUDE.md. The whole procedure runs on a DIFFERENT HOST than
/// 236 (because 236 is presumed dead — the entire reason this
/// section exists). At that point the daemon doesn't exist to be
/// asked to push buttons; the operator is bootstrapping a new
/// vpnctld instance from scratch. Every action that COULD be a
/// Web UI button on the running 236 (push deploy key, etc) is
/// kept in the procedure as a Web UI step on the NEW host.
fn settings_disaster_recovery_section(
    lang: crate::i18n::Locale,
    last_self_test: Option<&vpnctl_inventory::AuditEntry>,
) -> Markup {
    use crate::i18n::tr;
    // Format the last self-test: status chip + when + duration.
    // Pulled from audit_log payload, which is JSON; we don't
    // panic if the shape doesn't match — just show «(missing
    // field)» so future schema changes don't break the page.
    let last = last_self_test.map(|e| {
        let payload = e.payload.as_ref();
        let overall = payload
            .and_then(|p| p.get("overall").and_then(|v| v.as_str()))
            .unwrap_or("?")
            .to_string();
        // `Option` so a future audit-payload schema drift renders
        // «(missing)» rather than a misleading «0 ms» that would
        // look like a fast successful run in a post-mortem.
        let duration_ms: Option<i64> =
            payload.and_then(|p| p.get("duration_ms").and_then(|v| v.as_i64()));
        (e.ts, overall, duration_ms)
    });

    html! {
        div.ed-rule {}
        div #disaster-recovery.ed-art-eyebrow {
            (tr(lang, "Disaster recovery — if 192.168.0.236 burns", "Аварийное восстановление — если 192.168.0.236 сгорит"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "What happens when the homelab host disappears and you need to bring vpnctld back from scratch — sources of truth, what's in each bundle, the self-test status, and the 3-step recovery path. Click the button below ANY time to prove the latest snapshot is restorable BEFORE you need to do it for real.",
                "Что произойдёт когда хост homelab пропадёт и нужно поднять vpnctld с нуля — источники истины, что в каждом архиве, статус self-test'а и трёхшаговый план восстановления. Нажми кнопку ниже ЛЮБОЕ время чтобы доказать что последний снэпшот восстанавливается ДО того как это станет нужно по-настоящему.",
            ))
        }

        // ── Where backups live ──────────────────────────────────────────
        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; margin-top: 16px;" {
            (tr(lang, "Where backups live · 3 tiers", "Где живут бэкапы · 3 уровня"))
        }
        table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px; margin-top: 8px;" {
            thead {
                tr style="border-bottom: 1px solid var(--ink);" {
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "tier", "уровень"))
                    }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "location", "путь"))
                    }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "encryption", "шифрование"))
                    }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "retention", "хранение"))
                    }
                }
            }
            tbody {
                tr style="border-bottom: 1px dotted var(--rule);" {
                    td style="padding: 6px 8px;" { "1. local" }
                    td style="padding: 6px 8px;" { span.ed-mono { (crate::app::DEFAULT_BACKUP_DIR) } }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "plaintext (daemon-owned 0640)", "plaintext (демон-only 0640)")) }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "24 hourly + 30 daily + 12 monthly", "24 часовых + 30 дневных + 12 месячных")) }
                }
                tr style="border-bottom: 1px dotted var(--rule);" {
                    td style="padding: 6px 8px;" { "2. LAN archive" }
                    td style="padding: 6px 8px;" { span.ed-mono { "user@192.168.0.207:/home/user/backups/vpnctl/" } }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "age (recipient pubkey on 236)", "age (pubkey получателя на 236)")) }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "14 days · daily 03:04 UTC", "14 дней · ежедневно 03:04 UTC")) }
                }
                tr {
                    td style="padding: 6px 8px;" { "3. off-site" }
                    td style="padding: 6px 8px;" { span.ed-mono { "root@93.95.226.167:/root/vpnctl-backups/" } " (Iceland)" }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "age (same recipient)", "age (тот же получатель)")) }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "30 days · daily 03:04 UTC", "30 дней · ежедневно 03:04 UTC")) }
                }
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 10px 0 0;" {
            (tr(
                lang,
                "The age private key (",
                "Приватный age-ключ (",
            ))
            span.ed-mono { "/home/user/vpnctl-backup-key.age" }
            (tr(
                lang,
                ") lives on 207. If 207 also burns, tiers 2+3 become unreadable — keep a copy on a USB stick / paper / password manager.",
                ") живёт на 207. Если 207 тоже сгорит, уровни 2+3 нерасшифровываются — храни копию на USB / бумаге / в password-manager.",
            ))
        }

        // ── What's bundled ──────────────────────────────────────────────
        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; margin-top: 20px;" {
            (tr(lang, "What's in each daily bundle", "Что в ежедневном бандле"))
        }
        ul style="font-family: var(--serif); font-size: 13px; line-height: 1.6; margin: 8px 0 0 24px; padding: 0;" {
            li {
                span.ed-mono { "inv.db" }
                " — "
                (tr(lang, "the entire inventory: users, servers, grants, sub_tokens, WG keys, TUIC passwords, audit log, all sub_access_log / vpn_user_* analytics tables.", "вся inventory: users, servers, grants, sub_tokens, WG-ключи, TUIC-пароли, audit log, все аналитические таблицы sub_access_log / vpn_user_*."))
            }
            li {
                span.ed-mono { "/var/lib/vpnctl/.ssh/id_ed25519{,.pub}" }
                " — "
                b { (tr(lang, "deploy SSH key", "deploy SSH-ключ")) }
                ". " (tr(lang, "Without this a restored vpnctld can't reach ANY VPN node (CLAUDE.md «hard invariant»).", "Без него восстановленный vpnctld не достучится ни до одной VPN-ноды («жёсткий инвариант» в CLAUDE.md)."))
            }
            li {
                span.ed-mono { "/var/lib/vpnctl/.ssh/known_hosts" }
                " — "
                (tr(lang, "TOFU-pinned host keys (so post-restore SSH doesn't prompt unknown-host).", "TOFU-pinned ключи хостов (чтобы SSH после restore не спрашивал unknown-host)."))
            }
            li {
                span.ed-mono { "/etc/vpnctl/vpnctld.env" }
                " · "
                span.ed-mono { "/etc/vpnctl/backup-recipient.txt" }
                " — "
                (tr(lang, "admin password + Telegram token + which age recipient to push NEW backups to.", "admin password + Telegram-токен + кому age-encrypt'ить новые бэкапы."))
            }
            li {
                span.ed-mono { "/var/lib/vpnctl/geoip/*.mmdb" }
                " — "
                (tr(lang, "DB-IP City + ASN (130MB + 9MB). Re-fetchable via the «update now» button above, but bundling avoids the first-boot round-trip.", "DB-IP City + ASN (130MB + 9MB). Можно перекачать кнопкой «обновить сейчас» выше, но в бандле — чтобы не ждать первой загрузки."))
            }
            li {
                span.ed-mono { "/etc/systemd/system/vpnctld.{service,…}" }
                " · "
                span.ed-mono { "/etc/iptables/rules.v4" }
                " — "
                (tr(lang, "service unit + firewall rules so the restored host self-bootstraps.", "unit + iptables правила чтобы хост восстановился сам."))
            }
        }

        // ── Last self-test status ───────────────────────────────────────
        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; margin-top: 20px;" {
            (tr(lang, "Last restore self-test", "Последний self-test восстановления"))
        }
        @match &last {
            Some((ts, overall, duration_ms)) => {
                @let color = match overall.as_str() {
                    "ok"    => "#2e7d32",
                    "warn"  => "#e6a23c",
                    "fail" | "error" => "#c62828",
                    _ => "var(--mute)",
                };
                @let label = match overall.as_str() {
                    "ok"    => tr(lang, "PASS", "ПРОЙДЕНО"),
                    "warn"  => tr(lang, "PASS · with warnings", "ПРОЙДЕНО · с предупреждениями"),
                    "fail"  => tr(lang, "FAIL", "ПРОВАЛ"),
                    "error" => tr(lang, "ERROR", "ОШИБКА"),
                    other => other,
                };
                div style="display: flex; gap: 16px; align-items: center; margin: 8px 0 14px; padding: 10px 14px; border: 1px solid var(--rule); background: var(--paper);" {
                    span style=(format!("font-family: var(--serif); font-weight: 500; color: {color}; font-size: 14px;")) { (label) }
                    span style="color: var(--mute); font-family: var(--mono); font-size: 11px;" {
                        (format_msk_iso(*ts))
                        " · "
                        @match duration_ms {
                            Some(ms) => { (ms) " ms" }
                            None => { (tr(lang, "(duration missing)", "(длительность отсутствует)")) }
                        }
                    }
                }
            }
            None => {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 8px 0 14px; font-size: 12px;" {
                    (tr(lang, "Never run on this daemon. Click below to prove the latest snapshot restores cleanly — takes <1s, doesn't touch the live inv.db.", "Никогда не запускался на этом демоне. Кликни ниже чтобы доказать что последний снэпшот восстанавливается чисто — займёт <1с, живую inv.db не трогает."))
                }
            }
        }
        div style="display: flex; gap: 12px; margin-bottom: 18px;" {
            form method="post" action="/admin/backup/self-test" style="display: inline;" {
                button type="submit"
                       class="ed-abtn ed-abtn--recovery ed-abtn--lg" {
                    (tr(lang, "run self-test now", "запустить self-test сейчас"))
                }
            }
            // `?action=` is the real filter param (audit 2026-06-10:
            // `action_prefix` doesn't exist in AuditQuery — the old
            // link silently showed the unfiltered timeline). Trailing
            // dot per the prefix-filter convention: matches
            // backup.snapshot + backup.self_test.
            a href="/admin/audit?action=backup."
              style="padding: 6px 14px; border: 1px solid var(--rule); color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (tr(lang, "self-test history", "история self-test"))
            }
        }

        // ── Restore procedure ───────────────────────────────────────────
        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; margin-top: 16px;" {
            (tr(lang, "Restore procedure · 3 steps", "Процедура восстановления · 3 шага"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 8px;" {
            (tr(
                lang,
                "Steps 1+2 run on a NEW host (because 236 is presumed dead — there's no daemon to push buttons on). Step 3 returns to the normal Web UI on the recovered daemon.",
                "Шаги 1+2 выполняются на НОВОМ хосте (потому что 236 предположительно мёртв — некому жать кнопки в UI). Шаг 3 возвращается к обычному Web UI на восстановленном демоне.",
            ))
        }
        ol style="font-family: var(--serif); font-size: 13px; line-height: 1.6; margin: 8px 0 0 24px; padding: 0;" {
            li {
                b { (tr(lang, "On the new host: decrypt + extract", "На новом хосте: расшифруй + распакуй")) }
                " — "
                (tr(lang, "anywhere (new VPS, restored from VM snapshot, fresh laptop install). Decrypt the latest archive from tier 3 (Iceland) with ", "где угодно (новый VPS, восстановленный VM-снэпшот, свежий ноут). Расшифруй последний архив с уровня 3 (Iceland) через "))
                span.ed-mono { "age -d -i /path/to/vpnctl-backup-key.age" }
                (tr(lang, ". Extract the tar — you'll get the full ", ". Распакуй tar — получишь полный "))
                span.ed-mono { "vpnctl-snap/" }
                (tr(lang, " tree.", " дерево."))
            }
            li {
                b { (tr(lang, "On the new host: restore inv.db + start the daemon", "На новом хосте: восстанови inv.db + запусти демон")) }
                " — "
                (tr(lang, "install the new vpnctld binary (built from git, glibc-2.36-compatible), then ", "поставь свежий vpnctld binary (собранный из git, glibc-2.36-совместимый), затем "))
                span.ed-mono { "vpnctl restore /path/to/inv.db" }
                (tr(lang, ". This is the one CLI-only exception even on a HEALTHY host (daemon can't replace its own open DB); on a recovery host the daemon doesn't even exist yet. Copy env + assets + deploy key into place; ", ". Это один CLI-only шаг даже на ЗДОРОВОМ хосте (демон не может заменить свою же открытую БД); на recovery-хосте демона ещё нет. Скопируй env + assets + deploy-ключ на места; "))
                span.ed-mono { "systemctl restart vpnctld" }
                "."
            }
            li {
                b { (tr(lang, "Verify + push deploy key", "Проверь + push deploy-ключ")) }
                " — "
                (tr(lang, "click ", "кликни "))
                // POST form, not an anchor (audit 2026-06-10): the
                // self-test route is POST-only — a GET link 405'd.
                form method="post" action="/admin/backup/self-test"
                     style="display: inline;" {
                    button type="submit"
                           style="border: none; background: none; padding: 0; color: var(--ink); font: inherit; text-decoration: underline; cursor: pointer;" {
                        (tr(lang, "run self-test", "run self-test"))
                    }
                }
                (tr(lang, " on the restored daemon, then for each server in ", " на восстановленном демоне, потом для каждого сервера в "))
                a href="/admin/servers" style="color: var(--ink);" { (tr(lang, "/admin/servers", "/admin/servers")) }
                (tr(lang, " click «push deploy key» so the daemon re-authorises itself on every VPN node. ", " кликни «push deploy key» чтобы демон переавторизовался на каждой VPN-ноде. "))
                (tr(lang, "Existing client URIs continue to work byte-stable — verified by ", "Существующие client URI продолжают работать байт-стабильно — проверено через "))
                span.ed-mono { "restore_e2e" }
                (tr(lang, " test on every commit.", " тест на каждый коммит."))
            }
        }
    }
}

/// Phase 3c — the «update now» button hits
/// `/admin/settings/geoip/update-now` (SSE source). The button
/// flips into a live log pane that streams stdout/stderr from the
/// `vpnctl geoip-update` subprocess until the terminal Ok/Error
/// event closes the connection.
fn settings_geoip_section(lang: crate::i18n::Locale) -> Markup {
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

/// `POST /admin/settings/timezone` — operator picks an IANA TZ
/// name from the Settings dropdown (2026-05-23). Validates the
/// name parses as `chrono_tz::Tz`, writes to inventory + updates
/// the global cache so subsequent renders see the new zone
/// without a daemon restart.
pub(crate) async fn settings_timezone_set(State(state): State<AppState>, body: String) -> Response {
    let tz_name = form_field(&body, "tz").unwrap_or_default();
    if tz_name.is_empty() {
        return bad_request("missing `tz` field");
    }
    let tz: chrono_tz::Tz = match tz_name.parse() {
        Ok(t) => t,
        Err(_) => {
            return bad_request(&format!(
                "'{tz_name}' is not a valid IANA timezone name (e.g. 'Europe/Moscow', 'UTC', 'America/New_York')"
            ));
        }
    };
    // Persist to DB FIRST — then update cache. If the write fails
    // we want the cache to still reflect the actually-stored value.
    if let Err(e) = state.inv.set_display_timezone(&tz_name).await {
        return internal_error(anyhow::Error::new(e));
    }
    set_display_tz_cache(tz);
    // Audit row for the timeline.
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "settings.timezone.set",
            Some("display"),
            Some(&serde_json::json!({ "timezone": tz_name })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            error = %e,
            "audit row for settings.timezone.set failed; mutation already committed"
        );
    }
    Redirect::to("/admin/settings/appearance#timezone-section").into_response()
}

/// settings' in-page tabs (ui-audit §5 Phase 3). Same recipe as
/// `ServerTab`/`UserTab`: real sub-routes (`/admin/settings/{slug}`),
/// plain `<a href>` links, each tab renders only its own sections.
/// `Appearance` is the default (bare `/admin/settings`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingsTab {
    Appearance,
    Backups,
    Notifications,
    System,
}

impl SettingsTab {
    fn slug(self) -> &'static str {
        match self {
            SettingsTab::Appearance => "appearance",
            SettingsTab::Backups => "backups",
            SettingsTab::Notifications => "notifications",
            SettingsTab::System => "system",
        }
    }
}

// Thin axum handlers — one per tab route in app.rs. Bare
// `/admin/settings` (+ trailing slash) + `/appearance` both land here.
pub(crate) async fn settings(headers: HeaderMap, State(state): State<AppState>) -> Markup {
    settings_render(headers, state, SettingsTab::Appearance).await
}

pub(crate) async fn settings_backups(headers: HeaderMap, State(state): State<AppState>) -> Markup {
    settings_render(headers, state, SettingsTab::Backups).await
}

pub(crate) async fn settings_notifications(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Markup {
    settings_render(headers, state, SettingsTab::Notifications).await
}

pub(crate) async fn settings_system(headers: HeaderMap, State(state): State<AppState>) -> Markup {
    settings_render(headers, state, SettingsTab::System).await
}

async fn settings_render(headers: HeaderMap, state: AppState, tab: SettingsTab) -> Markup {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    // Auto-generated by vpnctld on startup (see
    // `crate::app::DEFAULT_DEPLOY_KEY_PATH` + `ensure_deploy_key`).
    // Surfaces the public half for diagnostic / out-of-inventory
    // paste. In-inventory servers should use the «push deploy key»
    // button on the server-detail page — the daemon handles SSH
    // itself, no manual editing required.
    let deploy_key_path = std::path::Path::new(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let deploy_pubkey =
        crate::ssh_subprocess::read_public_key(deploy_key_path).map_err(|e| e.to_string());

    // Phase C-4 — inventory snapshots. Reads the canonical backup
    // dir (same path the scheduler writes to). Listing failure is
    // shown inline rather than 500-ing — the rest of Settings
    // (theme, deploy key) should still render.
    let backup_dir = std::path::PathBuf::from(crate::app::DEFAULT_BACKUP_DIR);
    let snapshots = vpnctl_inventory::list_snapshots(&backup_dir).map_err(|e| e.to_string());

    // Phase 5e — Disaster recovery section pulls the LATEST
    // `backup.self_test` audit row to show last drill result inline.
    // Filtered SQL query (audit 2026-06-10): the old in-memory scan of
    // `recent_audit(50)` went blind within ~2 days — the hourly
    // `backup.snapshot` scheduler writes 24 rows/day, evicting the
    // self-test row from the last-50 window and rendering a false
    // «Never run».
    let last_self_test = state
        .inv
        .recent_audit_paginated(1, 0, None, Some("backup.self_test"), None, None)
        .await
        .ok()
        .and_then(|rows| rows.into_iter().next());

    // 2026-05-23 — display timezone (migration 0027). Render the
    // current setting in the dropdown's selected state. Failure to
    // read = use the default; doesn't break the rest of Settings.
    let display_tz_current = state
        .inv
        .get_display_timezone()
        .await
        .unwrap_or_else(|_| "Europe/Moscow".into());

    // Phase G chunk 3 — push notification transport config (Telegram
    // bot). Failure to read = render «(failed: …)» inline; don't
    // poison the rest of Settings.
    let telegram_cfg = state
        .inv
        .get_telegram_config()
        .await
        .map_err(|e| e.to_string());

    // Phase G chunk 3.5 — list inventory servers for the «proxy via»
    // dropdown. If the listing fails the dropdown shows only the
    // «direct» option (empty Vec) + the rest of Settings still renders.
    let servers_for_proxy_dropdown = state.inv.list_servers().await.unwrap_or_default();

    // v2 6a — one-glance «is the Telegram sink live» flag for the
    // System facts table (token AND chat id both set).
    let telegram_configured = matches!(
        telegram_cfg.as_ref(),
        Ok(Some(c)) if c.token.is_some() && c.chat_id.is_some()
    );

    let body = html! {
            div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageSettings)) }
            h1.ed-art-h1 {
                (crate::i18n::tr(lang, "homelab ", "homelab "))
                em { (crate::i18n::tr(lang, "controls", "управление")) }
            }
            p.ed-art-deck {
                (crate::i18n::tr(
                    lang,
                    "Daemon-wide knobs live here. Server / user mutations live on their respective pages.",
                    "Здесь лежат настройки уровня всего демона. Изменения серверов / пользователей — на их собственных страницах.",
                ))
            }

    (detail_tabs("/admin/settings", tab.slug(), &[("appearance", crate::i18n::tr(lang, "Appearance", "Внешний вид")), ("backups", crate::i18n::tr(lang, "Backups", "Бэкапы")), ("notifications", crate::i18n::tr(lang, "Notifications", "Уведомления")), ("system", crate::i18n::tr(lang, "System", "Система"))]))
    @if tab == SettingsTab::Appearance {
            // No ed-rule here — the tab row above already draws its own
            // bottom border; stacking both produced a double line
            // (design review 2026-07-10).
            div.ed-art-eyebrow style="margin-top: 14px;" { (crate::i18n::tr(lang, "Appearance — theme + accent", "Внешний вид — тема + акцент")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (crate::i18n::tr(
                    lang,
                    "Pick a paper theme (background palette) and an accent colour. Choices are stored as cookies; one-time configuration.",
                    "Выбери бумажную тему (фон) и акцентный цвет. Сохраняется в cookies; настраивается один раз.",
                ))
            }
            (tweaks_inline(&theme, &accent, lang))

            div.ed-rule {}
            div id="timezone-section" {
                div.ed-art-eyebrow {
                    (crate::i18n::tr(lang, "Display timezone", "Часовой пояс отображения"))
                }
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                    (crate::i18n::tr(
                        lang,
                        "Every operator-visible timestamp (alerts feed, audit timeline, sub-access log, chart axis labels, …) is rendered in this timezone with its UPPERCASE abbreviation suffix (e.g. ",
                        "Каждая видимая оператору метка времени (лента alerts, audit, sub-access лог, подписи осей графиков, …) рендерится в этом часовом поясе с прописной аббревиатурой (например ",
                    ))
                    span.ed-mono { "MSK" } ", " span.ed-mono { "UTC" } ", " span.ed-mono { "EST" }
                    (crate::i18n::tr(
                        lang,
                        "). Pick an IANA timezone name; full database (incl. DST rules) is bundled.",
                        "). Выбери IANA-имя часового пояса; полная база (включая DST) встроена.",
                    ))
                }
                form method="post"
                     action="/admin/settings/timezone"
                     style="display: flex; gap: 8px; align-items: baseline;" {
                    label style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.10em;" {
                        (crate::i18n::tr(lang, "timezone", "часовой пояс"))
                    }
                    @let common_tzs: &[&str] = &[
                        "UTC",
                        "Europe/Moscow",
                        "Europe/London",
                        "Europe/Berlin",
                        "Europe/Helsinki",
                        "Europe/Istanbul",
                        "Asia/Dubai",
                        "Asia/Tbilisi",
                        "Asia/Bangkok",
                        "Asia/Shanghai",
                        "Asia/Tokyo",
                        "America/New_York",
                        "America/Los_Angeles",
                    ];
                    select name="tz"
                           style="padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink); min-width: 220px;" {
                        @for tz in common_tzs {
                            @if *tz == display_tz_current.as_str() {
                                option value=(tz) selected="selected" { (tz) }
                            } @else {
                                option value=(tz) { (tz) }
                            }
                        }
                        // If current value isn't in the common list,
                        // surface it as a selected option at the end so
                        // the operator can keep it without retyping.
                        @if !common_tzs.contains(&display_tz_current.as_str()) {
                            option value=(display_tz_current) selected="selected" {
                                (display_tz_current) " (custom)"
                            }
                        }
                    }
                    button type="submit"
                           style="padding: 4px 12px; border: 1px solid var(--accent); background: var(--accent); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                        (crate::i18n::tr(lang, "save", "сохранить"))
                    }
                    span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                        (crate::i18n::tr(
                            lang,
                            "→ takes effect on the next page render (no restart needed)",
                            "→ применится при следующем рендере страницы (рестарт не нужен)",
                        ))
                    }
                }
            }

    }
    @if tab == SettingsTab::Backups {
            // No ed-rule — the tab row draws its own bottom border (R2).
            div #backups-section.ed-art-eyebrow style="margin-top: 14px;" {
                (crate::i18n::tr(lang, "Backups — inventory snapshots", "Бэкапы — снэпшоты инвентаря"))
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (crate::i18n::tr(lang, "vpnctld snapshots ", "vpnctld делает снэпшоты "))
                span.ed-mono { (crate::app::DEFAULT_DEPLOY_KEY_PATH.replace("/.ssh/id_ed25519", "/inv.db")) }
                (crate::i18n::tr(lang, " hourly into ", " ежечасно в "))
                span.ed-mono { (crate::app::DEFAULT_BACKUP_DIR) }
                (crate::i18n::tr(
                    lang,
                    " (24 hourly + 30 daily + 12 monthly retained). ",
                    " (хранятся 24 часовых + 30 дневных + 12 месячных). ",
                ))
                b { (crate::i18n::tr(lang, "Off-site is operator-driven", "Off-site копии делает оператор")) }
                (crate::i18n::tr(lang, " — click ", " — кликни "))
                em { (crate::i18n::tr(lang, "download", "скачать")) }
                (crate::i18n::tr(
                    lang,
                    " next to a snapshot and copy it to USB / Forgejo / cloud / wherever you trust. The daemon never pushes anywhere by itself.",
                    " рядом со снэпшотом и скопируй на USB / Forgejo / облако / куда доверяешь. Демон сам никуда не пушит.",
                ))
            }
            div style="display: flex; gap: 12px; align-items: center; margin-bottom: 14px; flex-wrap: wrap;" {
                form method="post" action="/admin/backup/snapshot" style="display: inline;" {
                    button type="submit"
                           title=(crate::i18n::tr(
                               lang,
                               "Take a snapshot now (in addition to the hourly schedule). Safe to click any time.",
                               "Сделать снэпшот сейчас (вдобавок к часовому расписанию). Безопасно нажимать в любой момент.",
                           ))
                           class="ed-abtn ed-abtn--secondary ed-abtn--lg" {
                        (crate::i18n::tr(lang, "snapshot now", "снэпшот сейчас"))
                    }
                }
                // Phase 5c — restore self-test button. Operator clicks →
                // verify_snapshot runs against the latest snapshot in a
                // tempdir → /admin/backup/self-test renders a pass/fail
                // HTML report (no SSE — completes in <1s for our DB size).
                form method="post" action="/admin/backup/self-test" style="display: inline;" {
                    button type="submit"
                           title=(crate::i18n::tr(
                               lang,
                               "Run restore fire-drill against the latest snapshot — does it actually restore into a usable DB? Safe to click any time; does NOT touch live inv.db.",
                               "Запустить проверку восстановления на последнем снэпшоте — реально ли он восстанавливается в рабочую БД? Безопасно нажимать в любой момент; живую inv.db не трогает.",
                           ))
                           class="ed-abtn ed-abtn--recovery ed-abtn--lg" {
                        (crate::i18n::tr(lang, "run restore self-test", "проверить восстановление"))
                    }
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                    (crate::i18n::tr(
                        lang,
                        "Restore-in-place is a CLI command (the daemon's restore subcommand — it can't replace its own open DB). The self-test above proves the snapshot WOULD restore, without touching the live DB.",
                        "Восстановление поверх живой БД — это CLI-команда (подкоманда restore демона — он не может заменить свою же открытую БД). Self-test выше доказывает что снэпшот ВОССТАНОВИТСЯ, не трогая живую БД.",
                    ))
                }
            }
            @match snapshots {
                Ok(list) if list.is_empty() => {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px;" {
                        (crate::i18n::tr(
                            lang,
                            "No snapshots yet. The scheduler fires its first snapshot ~60 seconds after daemon start; click ",
                            "Снэпшотов пока нет. Шедулер делает первый ~60 секунд после старта демона; кликни ",
                        ))
                        b { (crate::i18n::tr(lang, "snapshot now", "снэпшот сейчас")) }
                        (crate::i18n::tr(lang, " above to skip the wait.", " выше чтобы не ждать."))
                    }
                }
                Ok(list) => {
                    // Scrollable container so a 60-row backlog at the
                    // retention policy's cap doesn't push the rest of
                    // Settings (Deploy key, Telegram, etc) several
                    // viewport-heights down. Sticky header keeps the
                    // column labels visible while scrolling.
                    div style="max-height: 360px; overflow-y: auto; border: 1px solid var(--rule);" {
                        table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                            thead style="position: sticky; top: 0; background: var(--paper); z-index: 1;" {
                                tr {
                                    th style="text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--rule); color: var(--mute); font-weight: normal; letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                                        (crate::i18n::tr(lang, "created", "создан"))
                                    }
                                    th style="text-align: right; padding: 6px 8px; border-bottom: 1px solid var(--rule); color: var(--mute); font-weight: normal; letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                                        (crate::i18n::tr(lang, "size", "размер"))
                                    }
                                    th style="text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--rule); color: var(--mute); font-weight: normal; letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                                        (crate::i18n::tr(lang, "action", "действие"))
                                    }
                                }
                            }
                            tbody {
                                @for snap in list.iter().take(60) {
                                    tr {
                                        td style="padding: 4px 8px; border-bottom: 1px dotted var(--rule);" {
                                            // R2 2026-07-10: the display timezone applies here
                                            // like everywhere else; a filename that doesn't
                                            // carry a parseable stamp shows the NAME instead of
                                            // a «(unparseable timestamp)» parser complaint.
                                            @match snap
                                                .created
                                                .as_deref()
                                                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                            {
                                                Some(ts) => (format_msk_iso(ts.with_timezone(&chrono::Utc))),
                                                None => span.ed-grid__mut
                                                    title=(crate::i18n::tr(
                                                        lang,
                                                        "No timestamp in the filename (manual or legacy snapshot) — shown by name.",
                                                        "В имени файла нет метки времени (ручной или легаси-снэпшот) — показан по имени.",
                                                    )) {
                                                    (snap.file_name)
                                                },
                                            }
                                        }
                                        td style="padding: 4px 8px; border-bottom: 1px dotted var(--rule); text-align: right; color: var(--soft);" {
                                            (format_size_bytes(snap.size_bytes))
                                        }
                                        td style="padding: 4px 8px; border-bottom: 1px dotted var(--rule);" {
                                            a href=(format!("/admin/backup/download/{}", path_segment_encode(&snap.file_name)))
                                              download=(&snap.file_name)
                                              title=(crate::i18n::tr(
                                                  lang,
                                                  "Save this snapshot to your local disk for off-site storage",
                                                  "Скачать этот снэпшот на локальный диск для off-site хранения",
                                              ))
                                              style="color: var(--ink); text-decoration: underline;" {
                                                (crate::i18n::tr(lang, "download", "скачать"))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    @if list.len() > 60 {
                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 11px; margin-top: 8px;" {
                            "(" (list.len() - 60)
                            @if list.len() - 60 != 1 {
                                (crate::i18n::tr(lang, " older snapshots hidden", " более старых снэпшотов скрыто"))
                            } @else {
                                (crate::i18n::tr(lang, " older snapshot hidden", " более старый снэпшот скрыт"))
                            }
                            (crate::i18n::tr(
                                lang,
                                " — the retention policy caps total count, so the table won't grow unbounded.)",
                                " — политика хранения ограничивает количество, таблица не растёт бесконечно.)",
                            ))
                        }
                    }
                }
                Err(e) => {
                    p style="font-family: var(--serif); font-style: italic; color: var(--red); font-size: 12px;" {
                        (crate::i18n::tr(lang, "Can't list snapshots in ", "Не удалось перечислить снэпшоты в "))
                        span.ed-mono { (crate::app::DEFAULT_BACKUP_DIR) }
                        ": " (e)
                        (crate::i18n::tr(
                            lang,
                            ". Most likely the daemon user doesn't have access — check the permissions on the daemon's data directory.",
                            ". Скорее всего у пользователя демона нет доступа — проверь права на каталог данных демона.",
                        ))
                    }
                }
            }

            (settings_disaster_recovery_section(lang, last_self_test.as_ref()))

    }
    @if tab == SettingsTab::Notifications {
            // No ed-rule — the tab row draws its own bottom border (R2).
            // `id` so the POST-redirect-GET after Save can use a
            // fragment anchor (`#telegram-notifications`) and the
            // browser scrolls back to this section instead of jumping
            // to the top of /admin/settings.
            div #telegram-notifications.ed-art-eyebrow style="margin-top: 14px;" {
                (crate::i18n::tr(
                    lang,
                    "Notifications — Telegram bot",
                    "Уведомления — Telegram-бот",
                ))
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (crate::i18n::tr(
                    lang,
                    "When an alert fires (probe-detector or service flip), vpnctld POSTs a one-line message to a Telegram chat via ",
                    "Когда срабатывает алерт (probe-detector или поднятие/падение сервиса), vpnctld POST-ит однострочное сообщение в Telegram-чат через ",
                ))
                span.ed-mono { "api.telegram.org/bot<token>/sendMessage" }
                (crate::i18n::tr(
                    lang,
                    ". One operator, one chat — paste the bot token and your numeric chat-id below. Create the bot via ",
                    ". Один оператор, один чат — вставь bot-токен и свой числовой chat-id ниже. Создай бота через ",
                ))
                span.ed-mono { "@BotFather" }
                (crate::i18n::tr(lang, " on Telegram; get your chat-id by messaging ", " в Telegram; узнай свой chat-id написав "))
                span.ed-mono { "@userinfobot" }
                ". "
                b { (crate::i18n::tr(lang, "The token is a secret", "Токен — секрет")) }
                (crate::i18n::tr(lang, " — stored in ", " — хранится в "))
                span.ed-mono { "/var/lib/vpnctl/inv.db" }
                (crate::i18n::tr(
                    lang,
                    " (daemon-owned 0640), masked in this page after save. Clear both fields and re-save to disable.",
                    " (демон-only 0640), маскируется на этой странице после сохранения. Очисти оба поля и сохрани снова чтобы отключить.",
                ))
            }

            // Status line — tells the operator at a glance whether the
            // transport is wired. Three branches: config read failed,
            // both fields set ("enabled"), or partial/none ("disabled").
            @match &telegram_cfg {
                Err(e) => {
                    p style="font-family: var(--serif); font-style: italic; color: var(--red); font-size: 12px;" {
                        (crate::i18n::tr(lang, "Can't read notification settings: ", "Не удалось прочитать настройки уведомлений: ")) (e)
                    }
                }
                Ok(None) => {
                    p style="font-family: var(--serif); font-style: italic; color: var(--red); font-size: 12px;" {
                        (crate::i18n::tr(
                            lang,
                            "Settings row missing — migration 0014 didn't seed it. Daemon restart should re-run migrations.",
                            "Строка settings отсутствует — миграция 0014 не записала её. Перезапуск демона прогонит миграции заново.",
                        ))
                    }
                }
                Ok(Some(cfg)) if cfg.is_enabled() => {
                    p style="font-family: var(--mono); font-size: 12px; color: var(--ink); margin: 0 0 10px;" {
                        (crate::i18n::tr(lang, "Status: ", "Статус: ")) b { (crate::i18n::tr(lang, "enabled", "включено")) }
                        (crate::i18n::tr(lang, " · token ", " · токен "))
                        span style="color: var(--mute);" { "••••" (cfg.token_last4()) }
                        (crate::i18n::tr(lang, " · chat ", " · чат "))
                        span style="color: var(--mute);" { (cfg.chat_id.as_deref().unwrap_or("")) }
                    }
                }
                Ok(Some(cfg)) if cfg.token.is_some() || cfg.chat_id.is_some() => {
                    @let which_missing = if cfg.token.is_none() {
                        crate::i18n::tr(lang, "bot token", "bot-токен")
                    } else {
                        crate::i18n::tr(lang, "chat-id", "chat-id")
                    };
                    p style="font-family: var(--mono); font-size: 12px; color: var(--red); margin: 0 0 10px;" {
                        (crate::i18n::tr(lang, "Status: ", "Статус: ")) b { (crate::i18n::tr(lang, "partial config", "конфиг неполный")) }
                        " — " (which_missing)
                        (crate::i18n::tr(
                            lang,
                            " missing, transport effectively disabled. Fill in the missing field below + save, OR clear both fields to fully reset.",
                            " отсутствует, транспорт фактически выключен. Заполни недостающее поле ниже + сохрани, ЛИБО очисти оба чтобы сбросить.",
                        ))
                    }
                }
                Ok(Some(_)) => {
                    p style="font-family: var(--mono); font-size: 12px; color: var(--mute); margin: 0 0 10px;" {
                        (crate::i18n::tr(lang, "Status: ", "Статус: "))
                        b style="color: var(--ink);" { (crate::i18n::tr(lang, "disabled", "выключено")) }
                        (crate::i18n::tr(lang, " — fill in both fields below + save.", " — заполни оба поля ниже + сохрани."))
                    }
                }
            }

            form method="post" action="/admin/settings/telegram" style="margin: 0 0 14px;" {
                div style="display: grid; grid-template-columns: 140px 1fr; gap: 10px 14px; align-items: center; max-width: 720px;" {
                    label for="telegram_bot_token" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                        (crate::i18n::tr(lang, "bot token", "bot-токен"))
                    }
                    input type="password"
                          id="telegram_bot_token"
                          name="telegram_bot_token"
                          // R2: the old placeholder was a three-clause
                          // manual that truncated at narrower widths —
                          // the full rules live in the tooltip.
                          placeholder=(crate::i18n::tr(
                              lang,
                              "blank = keep existing",
                              "пусто = оставить как есть",
                          ))
                          autocomplete="off"
                          title=(crate::i18n::tr(
                              lang,
                              "Token from @BotFather, shape `123456:ABC-XYZ...`. Stored in inv.db, masked after save. Leave blank to keep the existing token; paste a new value to replace it; clear BOTH fields and save to disable the Telegram sink entirely.",
                              "Токен от @BotFather, форма `123456:ABC-XYZ...`. Хранится в inv.db, маскируется после сохранения. Пусто = оставить текущий; новое значение = заменить; очистить ОБА поля и сохранить = полностью выключить Telegram.",
                          ))
                          style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";
                    label for="telegram_chat_id" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                        (crate::i18n::tr(lang, "chat-id", "chat-id"))
                    }
                    input type="text"
                          id="telegram_chat_id"
                          name="telegram_chat_id"
                          value=(match &telegram_cfg {
                              Ok(Some(cfg)) => cfg.chat_id.as_deref().unwrap_or(""),
                              _ => "",
                          })
                          placeholder=(crate::i18n::tr(
                              lang,
                              "numeric, e.g. 123456789 (or @your_channel)",
                              "число, напр. 123456789 (или @your_channel)",
                          ))
                          title=(crate::i18n::tr(
                              lang,
                              "Numeric user/group id from @userinfobot OR a public @channel handle. Test-send button below checks this end-to-end.",
                              "Числовой user/group id от @userinfobot ИЛИ публичный @channel-хэндл. Кнопка тестового сообщения ниже проверяет всю цепочку.",
                          ))
                          style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";

                    label for="proxy_via_server_id" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                        (crate::i18n::tr(lang, "egress", "выход"))
                    }
                    @let current_proxy_id: &str = match &telegram_cfg {
                        Ok(Some(cfg)) => cfg.proxy_via_server_id.as_deref().unwrap_or(""),
                        _ => "",
                    };
                    select name="proxy_via_server_id"
                           id="proxy_via_server_id"
                           title=(crate::i18n::tr(
                               lang,
                               "If the daemon host can't reach api.telegram.org directly (РФ blocks, NAT, etc), route the call through an inventory server's network instead. Uses the existing deploy SSH key — the public half must be on root@<proxy-server>:~/.ssh/authorized_keys (see «Deploy SSH key» section below to copy).",
                               "Если хост демона не может достучаться до api.telegram.org напрямую (блоки РФ, NAT и т.п.), направь вызов через сеть одного из серверов инвентаря. Использует существующий deploy SSH-ключ — его публичная половина должна быть на root@<proxy-server>:~/.ssh/authorized_keys (см. секцию «Deploy SSH key» ниже).",
                           ))
                           style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);" {
                        option value="" selected[current_proxy_id.is_empty()] {
                            (crate::i18n::tr(lang, "direct (local network)", "напрямую (локальная сеть)"))
                        }
                        @for s in &servers_for_proxy_dropdown {
                            option value=(s.id.0) selected[current_proxy_id == s.id.0] {
                                (crate::i18n::tr(lang, "via server: ", "через сервер: ")) (s.id.0) " (" (s.address) ")"
                            }
                        }
                    }
                }

                @if servers_for_proxy_dropdown.is_empty() {
                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0; max-width: 720px;" {
                        (crate::i18n::tr(lang, "No servers in inventory yet — only ", "Серверов в инвентаре пока нет — доступен только "))
                        b { (crate::i18n::tr(lang, "direct", "напрямую")) }
                        (crate::i18n::tr(lang, " egress is available. Add a server on ", " выход. Добавь сервер на "))
                        span.ed-mono { "/admin/servers" }
                        (crate::i18n::tr(lang, " first if your daemon host can't reach ", " если хост демона не достучивается до "))
                        span.ed-mono { "api.telegram.org" } "."
                    }
                } @else {
                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0; max-width: 720px;" {
                        (crate::i18n::tr(lang, "Picking a ", "Выбор опции "))
                        b { (crate::i18n::tr(lang, "via server: …", "через сервер: …")) }
                        (crate::i18n::tr(
                            lang,
                            " option requires the daemon's deploy SSH pubkey to be on that server's ",
                            " требует чтобы deploy SSH публичный ключ демона был в ",
                        ))
                        span.ed-mono { "~/.ssh/authorized_keys" }
                        (crate::i18n::tr(lang, ". The pubkey lives in the ", " этого сервера. Pubkey лежит в секции "))
                        a href="#deploy-ssh-key" style="color: var(--ink);" {
                            b { (crate::i18n::tr(lang, "Deploy SSH key", "Deploy SSH-ключ")) }
                        }
                        (crate::i18n::tr(
                            lang,
                            " section below — copy it once, then ",
                            " ниже — скопируй один раз, затем ",
                        ))
                        em { (crate::i18n::tr(lang, "send test message", "отправить тестовое сообщение")) }
                        (crate::i18n::tr(lang, " confirms the path works.", " подтвердит что путь работает."))
                    }
                }

                div style="margin-top: 12px;" {
                    button type="submit"
                           title=(crate::i18n::tr(
                               lang,
                               "Save all three fields. Empty token = keep existing (unless chat-id is ALSO empty, then clear). Empty chat-id = clear. Egress dropdown is always overwritten with the selected value.",
                               "Сохранить все три поля. Пустой токен = оставить как есть (если chat-id ТОЖЕ пуст, тогда очистить). Пустой chat-id = очистить. Egress dropdown всегда переписывается выбранным значением.",
                           ))
                           style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                        (crate::i18n::t(lang, crate::i18n::K::BtnSave))
                    }
                }
            }

            // Test-send button — separate form POSTing to /admin/settings/
            // telegram/test so the operator can verify their credentials
            // without waiting for an actual alert to fire. Disabled (greyed
            // out via inline disabled attr) when the transport isn't
            // currently enabled — same predicate the dispatch loop uses.
            @match &telegram_cfg {
                Ok(Some(cfg)) if cfg.is_enabled() => {
                    form method="post" action="/admin/settings/telegram/test" style="margin-top: 10px;" {
                        button type="submit"
                               title=(crate::i18n::tr(
                                   lang,
                                   "Send a test message to the configured chat. Surfaces curl / Telegram-API errors inline.",
                                   "Отправить тестовое сообщение в настроенный чат. Ошибки curl / Telegram-API показываются прямо здесь.",
                               ))
                               style="padding: 5px 12px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                            (crate::i18n::tr(lang, "send test message", "отправить тестовое сообщение"))
                        }
                        span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 14px;" {
                            (crate::i18n::tr(
                                lang,
                                "Posts a «🟢 Telegram connected» sample in the real alert format + your chosen language.",
                                "Пошлёт пример «🟢 Telegram подключён» в реальном формате алертов и на выбранном языке.",
                            ))
                        }
                    }
                    // On-demand fleet digest (the daily scheduler sends it
                    // automatically; this is the «send it now» button).
                    form method="post" action="/admin/settings/digest-now" style="margin-top: 8px;" {
                        button type="submit"
                               title=(crate::i18n::tr(
                                   lang,
                                   "Send the fleet digest now: all-clear, or the list of open problems. Also sent daily.",
                                   "Отправить дайджест по флоту сейчас: всё спокойно или список открытых проблем. Также шлётся раз в сутки.",
                               ))
                               style="padding: 5px 12px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                            (crate::i18n::tr(lang, "send digest now", "отправить дайджест"))
                        }
                        span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 14px;" {
                            (crate::i18n::tr(
                                lang,
                                "A daily summary is sent automatically; this sends one immediately.",
                                "Ежедневная сводка отправляется автоматически; эта кнопка шлёт её сразу.",
                            ))
                        }
                    }
                }
                _ => {
                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 10px 0 0;" {
                        (crate::i18n::tr(
                            lang,
                            "Test-send button appears after both fields are saved + status is ",
                            "Кнопка тестового сообщения появится после сохранения обоих полей и когда статус ",
                        ))
                        b style="color: var(--ink);" { (crate::i18n::tr(lang, "enabled", "включено")) } "."
                    }
                }
            }

            // Notification language — operator-selectable locale for the
            // Telegram alert pushes. Independent of the per-browser admin-UI
            // [EN|RU] shell toggle: this one is persisted in
            // notification_settings.language + drives render_alert at push
            // time, so alerts speak the chosen language regardless of which
            // browser the operator reads /admin from.
            @let notif_lang = match &telegram_cfg {
                Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
                _ => crate::i18n::Locale::En,
            };
            div style="margin-top: 18px;" {
                div.ed-art-eyebrow style="margin-bottom: 8px;" {
                    (crate::i18n::tr(lang, "Alert language", "Язык уведомлений"))
                }
                @for (code, label, is_active) in [
                    ("ru", "Русский", notif_lang == crate::i18n::Locale::Ru),
                    ("en", "English", notif_lang == crate::i18n::Locale::En),
                ] {
                    form method="post" action="/admin/settings/notification-language"
                         style="display: inline; margin: 0 8px 0 0;" {
                        input type="hidden" name="language" value=(code);
                        button type="submit" disabled[is_active]
                               style=(if is_active {
                                   "padding: 5px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px;"
                               } else {
                                   "padding: 5px 12px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;"
                               }) {
                            (label)
                        }
                    }
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 6px;" {
                    (crate::i18n::tr(
                        lang,
                        "Telegram alerts are sent in this language.",
                        "Алерты в Telegram приходят на этом языке.",
                    ))
                }
            }

    }
    @if tab == SettingsTab::System {
            // v2 6a — system facts table: the daemon's moving parts and
            // their cadence, one glance. Values come from the same env
            // knobs the pollers read; alert sink state from inventory.
            @let probe_min = std::env::var("VPNCTLD_NODE_PROBE_INTERVAL_SECS").ok()
                .and_then(|v| v.parse::<u64>().ok()).unwrap_or(600) / 60;
            @let clash_min = std::env::var("VPNCTLD_POLL_INTERVAL_SECS").ok()
                .and_then(|v| v.parse::<u64>().ok()).unwrap_or(300) / 60;
            div.ed-art-eyebrow { (crate::i18n::tr(lang, "System", "Система")) }
            table.ed-feed style="margin: 8px 0 16px;" {
                tbody {
                    tr {
                        td.ed-grid__mut style="width: 160px;" { (crate::i18n::tr(lang, "probe tick", "тик проб")) }
                        td { b { (probe_min) " " (crate::i18n::tr(lang, "min", "мин")) } }
                        td.num.ed-grid__mut.ed-grid__sm { "node_probe_poller · VPNCTLD_NODE_PROBE_INTERVAL_SECS" }
                    }
                    tr {
                        td.ed-grid__mut { (crate::i18n::tr(lang, "clash poll", "опрос clash")) }
                        td { b { (clash_min) " " (crate::i18n::tr(lang, "min", "мин")) } " · " (crate::i18n::tr(lang, "per-node traffic attribution", "атрибуция трафика по нодам")) }
                        td.num.ed-grid__mut.ed-grid__sm { "clash_poller · VPNCTLD_POLL_INTERVAL_SECS" }
                    }
                    tr {
                        td.ed-grid__mut { (crate::i18n::tr(lang, "alert sink", "канал алертов")) }
                        td {
                            "telegram "
                            @if telegram_configured {
                                b style="color: var(--green);" { "on" }
                            } @else {
                                b.ed-grid__mut { "off" }
                            }
                        }
                        td.num.ed-grid__mut.ed-grid__sm {
                            a href="/admin/settings/notifications" style="color: var(--acc);" {
                                (crate::i18n::tr(lang, "configure →", "настроить →"))
                            }
                        }
                    }
                    tr {
                        td.ed-grid__mut { (crate::i18n::tr(lang, "rate limit", "rate limit")) }
                        td.ed-grid__sm { "/sub + /api/v1/app/config · " (crate::i18n::tr(lang, "per-device + non-egress per-IP buckets", "пер-девайс + пер-IP (не-egress) бакеты")) }
                        td.num.ed-grid__mut.ed-grid__sm { "rate_limit.rs" }
                    }
                }
            }

            div.ed-rule {}
            (settings_geoip_section(lang))

            div.ed-rule {}
            div #deploy-ssh-key.ed-art-eyebrow {
                (crate::i18n::tr(lang, "Deploy SSH key", "Deploy SSH-ключ"))
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (crate::i18n::tr(
                    lang,
                    "vpnctld auto-generated this Curve25519 keypair on first start. The private half stays in ",
                    "vpnctld сгенерировал эту Curve25519-пару при первом старте. Приватная половина остаётся в ",
                ))
                span.ed-mono { (crate::app::DEFAULT_DEPLOY_KEY_PATH) }
                (crate::i18n::tr(
                    lang,
                    " — never shown. The public half (below) goes into each VPN node's ",
                    " — никогда не показывается. Публичная половина (ниже) идёт в ",
                ))
                span.ed-mono { "~/.ssh/authorized_keys" }
                (crate::i18n::tr(lang, ". Once authorised, every ", " каждой VPN-ноды. Когда авторизован, каждый клик "))
                b { (crate::i18n::tr(lang, "deploy →", "деплой →")) }
                (crate::i18n::tr(
                    lang,
                    " button click pushes configs through vpnctld → ssh subprocess → node, no operator-typed CLI needed.",
                    " пушит конфиги по пути vpnctld → ssh-подпроцесс → нода, без ручных CLI-команд оператора.",
                ))
            }
            @match deploy_pubkey {
                Ok(pk) => {
                    pre style="font-family: var(--mono); font-size: 11px; padding: 12px 14px; background: var(--paper); border: 1px solid var(--rule); white-space: pre-wrap; word-break: break-all;" {
                        (pk)
                    }
                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0;" {
                        (crate::i18n::tr(lang, "Authorise this key on a server via the ", "Авторизуй этот ключ на сервере через "))
                        a href="/admin/servers" style="color: var(--ink);" {
                            b { "/admin/servers" }
                        }
                        (crate::i18n::tr(lang, " list → pick a server → ", " → выбрать сервер → "))
                        span.ed-mono { (crate::i18n::tr(lang, "«Deploy SSH key — push to this server»", "«Deploy SSH key — push to this server»")) }
                        (crate::i18n::tr(lang, " section → ", " секция → "))
                        span.ed-mono { (crate::i18n::tr(lang, "«push deploy key»", "«push deploy key»")) }
                        (crate::i18n::tr(
                            lang,
                            " button. The daemon handles the SSH dance for you — no manual SSH login or ",
                            " кнопка. Демон делает SSH-танец сам — без ручного SSH-логина или редактирования ",
                        ))
                        span.ed-mono { "authorized_keys" }
                        (crate::i18n::tr(
                            lang,
                            " editing. The pubkey above is shown for diagnostic / out-of-band-paste use only (e.g. you want to authorise the key on something that ISN'T in vpnctl's inventory).",
                            " вручную. Pubkey выше показан только для диагностики / out-of-band вставки (например если ты хочешь авторизовать ключ на чём-то ВНЕ инвентаря vpnctl).",
                        ))
                    }
                }
                Err(e) => {
                    p style="font-family: var(--serif); font-style: italic; color: var(--red);" {
                        (crate::i18n::tr(lang, "Public key file unreadable: ", "Публичный ключ не читается: ")) (e)
                        (crate::i18n::tr(lang, ". Most common cause: ", ". Чаще всего: "))
                        span.ed-mono { "/var/lib/vpnctl/.ssh" }
                        (crate::i18n::tr(
                            lang,
                            " not writable by the daemon. Check its directory permissions; vpnctld writes there as the systemd-unit user (typically ",
                            " недоступен на запись демону. Проверь права на каталог; vpnctld пишет туда из-под пользователя systemd-юнита (обычно ",
                        ))
                        span.ed-mono { "user" } ")."
                    }
                }
            }
    }
        };
    render_page(&state, "settings", &theme, &accent, lang, body).await
}

/// `POST /admin/settings/digest-now` — send the fleet digest to Telegram
/// on demand (the daily scheduler sends it automatically; this is the
/// «send it now» button). Audited; 303 back to /admin/settings.
pub(crate) async fn settings_digest_now(State(state): State<AppState>) -> Response {
    crate::node_probe_poller::send_digest(&state.inv).await;
    if let Err(e) = state
        .inv
        .audit("admin", "settings.digest.send", None, None)
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_digest_now",
            error = %e,
            "audit row for digest-now failed; digest was sent"
        );
    }
    Redirect::to("/admin/settings/notifications#telegram-notifications").into_response()
}

/// `POST /admin/settings/notification-language` — set the operator's
/// notification language (`ru` / `en`). Persisted in
/// `notification_settings.language`; drives `alert_text::render_alert`
/// at push time so Telegram alerts (and the localized test-send) speak
/// the chosen language. Audited; 303-redirects back to /admin/settings.
pub(crate) async fn settings_notification_language(
    State(state): State<AppState>,
    body: String,
) -> Response {
    let lang_in = form_field(&body, "language").unwrap_or_default();
    let lang = lang_in.trim();
    if lang != "ru" && lang != "en" {
        return bad_request("notification language must be 'ru' or 'en'");
    }
    if let Err(e) = state.inv.set_notification_language(Some(lang)).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "settings.notification.language",
            None,
            Some(&serde_json::json!({ "language": lang })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_notification_language",
            error = %e,
            "audit row for notification-language change failed; setting was applied"
        );
    }
    Redirect::to("/admin/settings/notifications").into_response()
}

/// `POST /admin/settings/telegram` — save the Telegram bot
/// transport config (Phase G chunk 3 part 1). Atomic update of both
/// fields. Either empty input → that field set to NULL in DB →
/// `is_enabled()` becomes false → transport disabled.
///
/// **Secret handling:** the token is NEVER logged or echoed back to
/// the operator after save. The audit_log payload records ONLY a
/// boolean («token set or cleared») + the chat_id; the token itself
/// stays in `notification_settings` only.
///
/// **Validation:**
///   * `token` shape: contains `:` and a non-trivial post-colon body
///     (Telegram bot tokens are `<bot_id>:<auth_hex>`); we don't pin
///     the exact length because BotFather has changed the format
///     across years.
///   * `chat_id`: either all-digits (with optional leading `-`) for
///     private chats / groups, OR `@<channel_name>` for public
///     channels.
///
/// Both checks reject obvious garbage with a 400 before the row is
/// written, so a typo doesn't silently kill alerts the operator
/// expects to receive.
pub(crate) async fn settings_telegram(State(state): State<AppState>, body: String) -> Response {
    let token_in = form_field(&body, "telegram_bot_token").unwrap_or_default();
    let chat_id_in = form_field(&body, "telegram_chat_id").unwrap_or_default();
    let token = token_in.trim();
    let chat_id = chat_id_in.trim();

    // Empty token semantics: «keep existing» NOT «clear». The «clear»
    // path requires the operator to clear BOTH fields (their browser
    // sends both inputs even when blank, so detecting clear-intent
    // means «chat_id is also empty»).
    let token_arg: Option<String> = if token.is_empty() {
        if chat_id.is_empty() {
            // Both empty → operator wants to disable. Clear both.
            None
        } else {
            // Operator changed chat_id but didn't paste a new token →
            // preserve the existing token. Fetch current.
            match state.inv.get_telegram_config().await {
                Ok(Some(cfg)) => cfg.token,
                // Singleton row missing — same condition the GET
                // handler surfaces in red on the page. Loud here too
                // so the operator doesn't silently disable the
                // transport while believing they updated chat_id.
                Ok(None) => {
                    return error_resp(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "notification_settings singleton row missing (migration 0014 not applied?) — restart vpnctld to re-run migrations, then re-save with token + chat-id both filled in",
                    );
                }
                Err(e) => return internal_error(anyhow::Error::new(e)),
            }
        }
    } else {
        // Shape gate: Telegram bot tokens always have a colon in the
        // middle. Reject obvious paste-error.
        if !token.contains(':') || token.len() < 20 {
            return bad_request(
                "bot token looks malformed (expected '<bot_id>:<auth_hex>' from @BotFather)",
            );
        }
        Some(token.to_string())
    };

    let chat_id_arg: Option<String> = if chat_id.is_empty() {
        None
    } else {
        // Shape gate: numeric (optionally leading `-`) or `@channel`.
        let looks_numeric = chat_id
            .strip_prefix('-')
            .unwrap_or(chat_id)
            .chars()
            .all(|c| c.is_ascii_digit())
            && !chat_id.is_empty()
            && chat_id != "-";
        let looks_channel = chat_id.starts_with('@')
            && chat_id.len() >= 2
            && chat_id[1..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !looks_numeric && !looks_channel {
            return bad_request(
                "chat-id must be numeric (e.g. 123456789, or -100123... for supergroups) or '@channel_name'",
            );
        }
        Some(chat_id.to_string())
    };

    // ─── Phase G chunk 3.5 — proxy_via_server_id ─────────────────
    // Empty = direct (NULL in DB). Non-empty = inventory server id.
    // We DON'T validate the id against the inventory here because:
    //   (1) the dropdown can only emit existing ids OR empty;
    //   (2) if an operator hand-crafts a POST with a fake id, the
    //       build_alert_sink path will log + fall back to direct
    //       mode (loud-but-non-fatal), AND the test-send button will
    //       surface the SSH error the very next time they click it.
    let proxy_via_raw = form_field(&body, "proxy_via_server_id").unwrap_or_default();
    let proxy_arg: Option<String> = if proxy_via_raw.trim().is_empty() {
        None
    } else {
        Some(proxy_via_raw.trim().to_string())
    };

    if let Err(e) = state
        .inv
        .set_telegram_config(
            token_arg.as_deref(),
            chat_id_arg.as_deref(),
            proxy_arg.as_deref(),
        )
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }

    // Audit row. Payload carries the chat_id + proxy_via_server_id
    // (both operator-visible anyway) + a boolean for «token state
    // changed». NEVER the token.
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "settings.telegram.set",
            None,
            Some(&serde_json::json!({
                "token_set": token_arg.is_some(),
                "chat_id_set": chat_id_arg.is_some(),
                "chat_id": chat_id_arg.as_deref().unwrap_or(""),
                "proxy_via_server_id": proxy_arg.as_deref().unwrap_or(""),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_telegram",
            error = %e,
            "audit row for settings.telegram.set failed; config saved"
        );
    }

    // Fragment anchor → browser scrolls back to the Telegram
    // section instead of jumping to the top of /admin/settings
    // after Save / test-send.
    Redirect::to("/admin/settings/notifications#telegram-notifications").into_response()
}

/// `POST /admin/settings/telegram/test` — synchronously send a test
/// message via the currently-configured Telegram bot. Surfaces
/// success (redirect to /admin/settings) or failure (502 Bad Gateway
/// with the truncated curl-stderr line, so the operator can
/// distinguish «bot blocked», «wrong chat-id», «proxy down», «РФ
/// blocked api.telegram.org» without journalctl access).
///
/// Audit row written either way — operator action, regardless of
/// outcome. Payload includes `success: bool` + error string when
/// failed (NO token).
///
/// **NOT fire-and-forget** — unlike the probe-loop's push, this
/// handler awaits the curl call so the response carries the verdict.
/// Default timeout is 20s (curl `--max-time`), so the operator's
/// HTTP request can take that long in the worst case.
pub(crate) async fn settings_telegram_test(State(state): State<AppState>) -> Response {
    // Use the SAME sink-construction logic as the production push
    // loop (`node_probe_poller::build_alert_sink`) so the test-send
    // path doesn't drift on details like `proxy_via_server_id` —
    // operator's test verifies the exact same pipeline that real
    // alerts use.
    let sink = match crate::node_probe_poller::build_alert_sink(&state.inv).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return bad_request(
                "Telegram transport not configured — fill in both fields on /admin/settings first",
            );
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // Render the test message in the operator's chosen language, in the
    // SAME pretty HTML format real alerts use — so the test verifies not
    // just connectivity but that the operator likes the look + locale.
    let loc = match state.inv.get_telegram_config().await {
        Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
        _ => crate::i18n::Locale::En,
    };
    let time_local = format_local_with_pattern(chrono::Utc::now(), "%d.%m %H:%M");
    let sample = crate::alert_text::RenderedAlert {
        icon: "🟢",
        title: crate::i18n::tr(loc, "Telegram connected — vpnctl", "Telegram подключён — vpnctl")
            .to_string(),
        body: crate::i18n::tr(
            loc,
            "This is a test message. Real alerts arrive in this format: a severity icon, what happened, and what to do.",
            "Это тестовое сообщение. Реальные алерты приходят в этом формате: иконка важности, что случилось и что делать.",
        )
        .to_string(),
        action: None,
    };
    let text = crate::alert_text::to_telegram_html(&sample, loc, &time_local, false);
    let send_result = sink.send_text("test", "info", &text, true).await;

    // Audit either way.
    let audit_payload = match &send_result {
        Ok(_) => serde_json::json!({"success": true}),
        Err(e) => serde_json::json!({"success": false, "error": e.to_string()}),
    };
    if let Err(audit_err) = state
        .inv
        .audit(
            "admin",
            "settings.telegram.test_send",
            None,
            Some(&audit_payload),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_telegram_test",
            error = %audit_err,
            "audit row for test_send failed; result was {:?}",
            send_result.is_ok()
        );
    }

    match send_result {
        Ok(_) => {
            Redirect::to("/admin/settings/notifications#telegram-notifications").into_response()
        }
        Err(e) => {
            let raw = e.to_string();
            // Don't double up on remediation hints: `classify_ssh_failure`
            // (in alert_sink) already produces a specific message for
            // the SSH path (Permission denied / refused / timed out /
            // host-key). Appending the generic «common causes» list on
            // top of that classified message creates redundancy that
            // dilutes the actionable bit — caught by Pavel during live
            // testing 2026-05-18. Only append the generic list when
            // the failure was NOT SSH-level (curl-direct path or
            // Telegram-API-level «ok:false»).
            let msg = if raw.contains("ssh-then-curl") {
                format!("test-send failed: {e}")
            } else {
                format!(
                    "test-send failed: {e} — common causes: \
                     chat-id wrong (Telegram returns 'chat not found'), \
                     token revoked, \
                     bot never started conversation with you \
                     (open the bot in Telegram + tap Start), \
                     api.telegram.org blocked (use the «egress» dropdown \
                     on /admin/settings to route via an inventory server, \
                     or set VPNCTLD_HTTPS_PROXY env)"
                )
            };
            error_resp(StatusCode::BAD_GATEWAY, &msg)
        }
    }
}

// `set_tweak_cookie`, `sanitize_referer`, `set_tweak`, `logout` moved to helpers.rs & tweaks.rs

