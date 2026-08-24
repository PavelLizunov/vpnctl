use maud::{Markup, html};

use crate::handlers::admin::helpers::format_msk_iso;

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
pub(crate) fn settings_disaster_recovery_section(
    lang: crate::i18n::Locale,
    last_self_test: Option<&vpnctl_inventory::AuditEntry>,
) -> Markup {
    use crate::i18n::tr;
    let deploy_key = crate::app::deploy_key_path();
    let deploy_key_pub = crate::ssh_subprocess::public_key_path(&deploy_key);
    let deploy_key_bundle_label =
        format!("{} · {}", deploy_key.display(), deploy_key_pub.display());
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
                span.ed-mono { (deploy_key_bundle_label) }
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
