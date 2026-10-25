use crate::handlers::admin::icons::icon;
use maud::{Markup, html};

use crate::handlers::admin::helpers::format_msk_iso;

pub(crate) fn settings_disaster_recovery_section(
    lang: crate::i18n::Locale,
    last_self_test: Option<&vpnctl_inventory::AuditEntry>,
) -> Markup {
    use crate::i18n::tr;
    let backup_dir = vpnctl_inventory::backup_dir_from_env();
    let deploy_key = crate::app::deploy_key_path();
    let deploy_key_pub = crate::ssh_subprocess::public_key_path(&deploy_key);
    let deploy_key_bundle_label =
        format!("{} · {}", deploy_key.display(), deploy_key_pub.display());
    let env_value = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let backup_target = |host: &str, dir: &str| match (env_value(host), env_value(dir)) {
        (Some(h), Some(d)) => format!("{h}:{d}/"),
        (Some(h), None) => format!("{h}:"),
        _ => format!("{host} not set for vpnctld (backup job default applies)"),
    };
    let lan_target = backup_target("TARGET_HOST", "TARGET_DIR");
    let offsite_target = backup_target("OFFSITE_HOST", "OFFSITE_DIR");
    let lan_days = env_value("RETENTION_DAYS").unwrap_or_else(|| "14".into());
    let offsite_days = env_value("OFFSITE_RETENTION_DAYS").unwrap_or_else(|| "30".into());
    let last = last_self_test.map(|e| {
        let payload = e.payload.as_ref();
        let overall = payload
            .and_then(|p| p.get("overall").and_then(|v| v.as_str()))
            .unwrap_or("?")
            .to_string();
        let duration_ms: Option<i64> =
            payload.and_then(|p| p.get("duration_ms").and_then(|v| v.as_i64()));
        (e.ts, overall, duration_ms)
    });

    html! {
        div.ed-rule {}
        div #disaster-recovery.ed-art-eyebrow {
            (tr(lang, "Disaster recovery — if this host is lost", "Аварийное восстановление — если этот хост потерян"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "What happens when this host disappears and you need to bring vpnctld back from scratch — sources of truth, what's in each bundle, the self-test status, and the 3-step recovery path. Click the button below ANY time to prove the latest snapshot is restorable BEFORE you need to do it for real.",
                "Что произойдёт когда этот хост пропадёт и нужно поднять vpnctld с нуля — источники истины, что в каждом архиве, статус self-test'а и трёхшаговый план восстановления. Нажми кнопку ниже ЛЮБОЕ время чтобы доказать что последний снэпшот восстанавливается ДО того как это станет нужно по-настоящему.",
            ))
        }

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
                    td style="padding: 6px 8px;" { span.ed-mono { (backup_dir.display()) } }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "plaintext (daemon-owned 0640)", "plaintext (демон-only 0640)")) }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "24 hourly + 30 daily + 12 monthly", "24 часовых + 30 дневных + 12 месячных")) }
                }
                tr style="border-bottom: 1px dotted var(--rule);" {
                    td style="padding: 6px 8px;" { "2. LAN archive" }
                    td style="padding: 6px 8px;" { span.ed-mono { (lan_target) } }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "age (recipient public key on this host)", "age (pubkey получателя на этом хосте)")) }
                    td style="padding: 6px 8px; color: var(--mute);" { (lan_days) (tr(lang, " days · daily 03:04 UTC", " дн. · ежедневно 03:04 UTC")) }
                }
                tr {
                    td style="padding: 6px 8px;" { "3. off-site" }
                    td style="padding: 6px 8px;" { span.ed-mono { (offsite_target) } }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "age (same recipient)", "age (тот же получатель)")) }
                    td style="padding: 6px 8px; color: var(--mute);" { (offsite_days) (tr(lang, " days · daily 03:04 UTC", " дн. · ежедневно 03:04 UTC")) }
                }
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 10px 0 0;" {
            (tr(
                lang,
                "The age private key is not stored on this host. If it is lost, tiers 2+3 become unreadable — keep a copy on a USB stick / paper / password manager.",
                "Приватный age-ключ не хранится на этом хосте. Если он потерян, уровни 2+3 не расшифровать — храни копию на USB / бумаге / в password-manager.",
            ))
        }

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
                ". " (tr(lang, "Without this a restored vpnctld can't reach ANY VPN node.", "Без него восстановленный vpnctld не достучится ни до одной VPN-ноды."))
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
                    (icon("shield-check")) (tr(lang, "run self-test now", "запустить self-test сейчас"))
                }
            }
            a href="/admin/audit?action=backup."
              style="padding: 6px 14px; border: 1px solid var(--rule); color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (icon("history")) (tr(lang, "self-test history", "история self-test"))
            }
        }

        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; margin-top: 16px;" {
            (tr(lang, "Restore procedure · 3 steps", "Процедура восстановления · 3 шага"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 8px;" {
            (tr(
                lang,
                "Steps 1+2 run on a NEW host (because the old one is presumed dead — there's no daemon to push buttons on). Step 3 returns to the normal Web UI on the recovered daemon.",
                "Шаги 1+2 выполняются на НОВОМ хосте (потому что старый предположительно мёртв — некому жать кнопки в UI). Шаг 3 возвращается к обычному Web UI на восстановленном демоне.",
            ))
        }
        ol style="font-family: var(--serif); font-size: 13px; line-height: 1.6; margin: 8px 0 0 24px; padding: 0;" {
            li {
                b { (tr(lang, "On the new host: decrypt + extract", "На новом хосте: расшифруй + распакуй")) }
                " — "
                (tr(lang, "run the recovery script on the latest archive from tier 3 (off-site): ", "запусти скрипт восстановления для последнего архива с уровня 3 (off-site): "))
                span.ed-mono { "scripts/vpnctl-restore.sh /path/to/archive.tar.zst.age /path/to/vpnctl-backup-key.age" }
                (tr(lang, ". It decrypts, unpacks and verifies the bundle in a scratch directory; it does not install files. The extracted ", ". Он расшифрует, распакует и проверит бандл во временном каталоге; файлы на рабочие места он не устанавливает. Распакованное дерево "))
                span.ed-mono { "vpnctl-snap/" }
                (tr(lang, " tree includes inv.db and the other recovery files.", " содержит inv.db и остальные файлы восстановления."))
            }
            li {
                b { (tr(lang, "On the new host: restore inv.db + start the daemon", "На новом хосте: восстанови inv.db + запусти демон")) }
                " — "
                (tr(lang, "install vpnctld and vpnctl, keep the daemon stopped, then restore the decrypted SQLite snapshot: ", "установи vpnctld и vpnctl, оставь демон остановленным и восстанови расшифрованный SQLite-снэпшот: "))
                span.ed-mono { "vpnctl restore /path/to/inv.db" }
                (tr(lang, ". Use the extracted inv.db, never the encrypted archive. Restore env, assets, deploy key, known_hosts, GeoIP, systemd units and firewall rules to their configured paths, preserving ownership and permissions; ", ". Передай распакованный inv.db, а не зашифрованный архив. Восстанови env, assets, deploy-ключ, known_hosts, GeoIP, systemd units и правила firewall на настроенные пути, сохраняя владельцев и права; "))
                span.ed-mono { "systemctl restart vpnctld" }
                "."
            }
            li {
                b { (tr(lang, "Verify + push deploy key", "Проверь + push deploy-ключ")) }
                " — "
                (tr(lang, "click ", "кликни "))
                form method="post" action="/admin/backup/self-test"
                     style="display: inline;" {
                    button type="submit"
                           style="border: none; background: none; padding: 0; color: var(--ink); font: inherit; text-decoration: underline; cursor: pointer;" {
                        (icon("shield-check")) (tr(lang, "run self-test", "run self-test"))
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
