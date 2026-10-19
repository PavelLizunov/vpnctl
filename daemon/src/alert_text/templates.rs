use crate::i18n::Locale;
use serde_json::Value;

use super::formatting::{RenderedAlert, code, esc, icon_for, pick};

fn u(p: &Value, k: &str) -> Option<u64> {
    p.get(k).and_then(Value::as_u64)
}
fn pf(p: &Value, k: &str) -> Option<f64> {
    p.get(k).and_then(Value::as_f64)
}
fn ps<'a>(p: &'a Value, k: &str) -> Option<&'a str> {
    p.get(k).and_then(Value::as_str)
}

pub fn render_alert(
    kind: &str,
    severity: &str,
    subject: &str,
    payload: &Value,
    loc: Locale,
) -> RenderedAlert {
    let subj = esc(subject);
    let icon = icon_for(kind, severity);
    let base = kind.split(':').next().unwrap_or(kind);

    let (title, body, action): (String, String, Option<String>) = match base {
        "server.singbox.down" => {
            let ip = ps(payload, "ip").map(code).unwrap_or_default();
            (
                pick(loc, format!("sing-box down — {subj}"), format!("sing-box упал — {subj}")),
                pick(loc,
                    format!("sing-box on {subj} {ip} is not active — this server's VPN protocols (REALITY, hysteria2, …) are not being served."),
                    format!("На ноде {subj} {ip} демон sing-box не активен — VPN-протоколы (REALITY, hysteria2…) на этом сервере не обслуживаются.")),
                Some(pick(loc,
                    "Open the server page and click Deploy (restarts + reapplies the config). If it crash-loops, check the node logs.".into(),
                    "Открой страницу сервера и нажми «Деплой» (перезапустит и применит конфиг). Если crash-loop — смотри логи ноды.".into())),
            )
        }
        "server.singbox.up" => {
            let dur = ps(payload, "downtime_human");
            let auto = payload
                .get("auto_remediated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            (
                if auto {
                    pick(
                        loc,
                        format!("Fixed automatically — {subj}"),
                        format!("Исправлено автоматически — {subj}"),
                    )
                } else {
                    pick(
                        loc,
                        format!("sing-box recovered — {subj}"),
                        format!("sing-box поднялся — {subj}"),
                    )
                },
                if auto {
                    pick(
                        loc,
                        format!(
                            "vpnctl restarted sing-box on {subj} and verified that it is active."
                        ),
                        format!(
                            "vpnctl перезапустил sing-box на {subj} и проверил, что он активен."
                        ),
                    )
                } else {
                    match dur {
                        Some(d) => pick(
                            loc,
                            format!("sing-box is active again on {subj}. Was down for {d}."),
                            format!("sing-box снова активен на {subj}. Был недоступен {d}."),
                        ),
                        None => pick(
                            loc,
                            format!("sing-box is active again on {subj}."),
                            format!("sing-box снова активен на {subj}."),
                        ),
                    }
                },
                None,
            )
        }
        "server.fail2ban.banned_self" => {
            let ip = ps(payload, "our_ip").map(code).unwrap_or_default();
            (
                pick(loc, format!("fail2ban banned our own IP — {subj}"), format!("fail2ban забанил наш IP — {subj}")),
                pick(loc,
                    format!("fail2ban on {subj} banned the daemon's own outbound IP {ip} in sshd — the control daemon can no longer manage this node over SSH."),
                    format!("fail2ban на ноде {subj} внёс исходящий IP управляющего демона {ip} в бан sshd — демон больше не управляет этой нодой по SSH.")),
                Some(pick(loc,
                    "The daemon can't self-unban — use the hoster's serial console / KVM to clear the ban (or wait out the ban window).".into(),
                    "Сам разбанить не может — зайди через консоль/KVM хостера и сними бан (или подожди срок).".into())),
            )
        }

        "server.unreachable" if severity == "info" => (
            pick(
                loc,
                format!("Node reachable again — {subj}"),
                format!("Нода снова доступна — {subj}"),
            ),
            pick(
                loc,
                format!("{subj} is responding again — SSH probes succeed."),
                format!("{subj} снова отвечает — SSH-проверки проходят."),
            ),
            None,
        ),
        "server.unreachable" => {
            let n = u(payload, "consecutive_failures").unwrap_or(3);
            let ip = ps(payload, "ip");
            let ipc = ip
                .map(code)
                .unwrap_or_else(|| pick(loc, "the server".into(), "сервер".into()));
            (
                pick(loc, format!("Node unreachable — {subj}"), format!("Нода недоступна — {subj}")),
                pick(loc,
                    format!("{ipc} is not responding: {n} probes failed in a row. Likely causes: the VPS is down · the hoster null-routed it · the SSH port changed."),
                    format!("{ipc} не отвечает: {n} проверок подряд не прошли. Вероятно: упал VPS · null-route у хостера · сменился SSH-порт.")),
                Some(pick(loc,
                    "Check the hoster panel (running? null-routed? suspended?) and reboot the node.".into(),
                    "Проверь панель хостера (запущен? null-route? suspended?) и ребутни ноду.".into())),
            )
        }
        "server.fail2ban.down" => (
            pick(
                loc,
                format!("fail2ban down — {subj}"),
                format!("fail2ban не работает — {subj}"),
            ),
            pick(
                loc,
                format!(
                    "The fail2ban service on {subj} is not active — SSH brute-force protection is temporarily off."
                ),
                format!(
                    "Служба fail2ban на ноде {subj} не активна — защита от перебора SSH временно отключена."
                ),
            ),
            Some(pick(
                loc,
                "Redeploy the node or check the fail2ban service.".into(),
                "Передеплой ноду или проверь службу fail2ban.".into(),
            )),
        ),
        "server.fail2ban.up" => {
            let auto = payload
                .get("auto_remediated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            (
                if auto {
                    pick(
                        loc,
                        format!("Fixed automatically — {subj}"),
                        format!("Исправлено автоматически — {subj}"),
                    )
                } else {
                    pick(
                        loc,
                        format!("fail2ban recovered — {subj}"),
                        format!("fail2ban снова работает — {subj}"),
                    )
                },
                if auto {
                    pick(
                        loc,
                        format!(
                            "vpnctl started fail2ban on {subj} and verified that it is active."
                        ),
                        format!("vpnctl запустил fail2ban на {subj} и проверил, что он активен."),
                    )
                } else {
                    pick(
                        loc,
                        format!("fail2ban is active again on {subj}."),
                        format!("fail2ban снова активен на {subj}."),
                    )
                },
                None,
            )
        }
        "server.disk.pressure" => {
            let pct = u(payload, "current_pct")
                .map(|p| code(&format!("{p}%")))
                .unwrap_or_default();
            (
                pick(
                    loc,
                    format!("Low disk space — {subj}"),
                    format!("Мало места на диске — {subj}"),
                ),
                pick(
                    loc,
                    format!(
                        "Disk on {subj} is {pct} full (threshold 90%). Risk: overflow → services crash, log writes fail. Usual culprit: a bloated sing-box log."
                    ),
                    format!(
                        "Диск ноды {subj} заполнен на {pct} (порог 90%). Риск: переполнение → падение сервисов, отказ записи логов. Чаще всего виноват разросшийся лог sing-box."
                    ),
                ),
                Some(pick(
                    loc,
                    "Clear logs/cache on the node or grow the disk.".into(),
                    "Почисти логи/кэш на ноде или расширь диск.".into(),
                )),
            )
        }
        "server.disk.recovered" => {
            let pct = u(payload, "current_pct")
                .map(|p| code(&format!("{p}%")))
                .unwrap_or_default();
            let auto = payload
                .get("auto_remediated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            (
                if auto {
                    pick(
                        loc,
                        format!("Fixed automatically — {subj}"),
                        format!("Исправлено автоматически — {subj}"),
                    )
                } else {
                    pick(
                        loc,
                        format!("Disk recovered — {subj}"),
                        format!("Диск разгрузился — {subj}"),
                    )
                },
                if auto {
                    pick(
                        loc,
                        format!(
                            "vpnctl rotated the sing-box log, kept 14 days of system journal, cleaned the package cache, and verified disk usage at {pct}."
                        ),
                        format!(
                            "vpnctl ротировал лог sing-box, оставил 14 дней system journal, очистил кэш пакетов и проверил заполнение диска: {pct}."
                        ),
                    )
                } else {
                    pick(
                        loc,
                        format!("Disk on {subj} is back down to {pct}."),
                        format!("Диск ноды {subj} разгрузился, сейчас {pct}."),
                    )
                },
                None,
            )
        }
        "server.mem.pressure" => {
            let pct = u(payload, "current_pct")
                .map(|p| code(&format!("{p}%")))
                .unwrap_or_default();
            (
                pick(
                    loc,
                    format!("Low memory — {subj}"),
                    format!("Мало памяти — {subj}"),
                ),
                pick(
                    loc,
                    format!(
                        "Memory on {subj} is {pct} used (threshold 95%). Risk: the OOM-killer may take services down."
                    ),
                    format!(
                        "Память ноды {subj} занята на {pct} (порог 95%). Риск OOM-killer → сервисы могут упасть."
                    ),
                ),
                Some(pick(
                    loc,
                    "See what's eating memory; on repeats, grow the RAM.".into(),
                    "Глянь, что ест память; при повторах — расширь RAM.".into(),
                )),
            )
        }
        "server.mem.recovered" => {
            let pct = u(payload, "current_pct")
                .map(|p| code(&format!("{p}%")))
                .unwrap_or_default();
            (
                pick(
                    loc,
                    format!("Memory recovered — {subj}"),
                    format!("Память разгрузилась — {subj}"),
                ),
                pick(
                    loc,
                    format!("Memory on {subj} is back down to {pct}."),
                    format!("Память ноды {subj} разгрузилась, сейчас {pct}."),
                ),
                None,
            )
        }
        "server.singbox.log.too_big" => {
            let mib = u(payload, "current_bytes")
                .map(|b| b / 1_048_576)
                .unwrap_or(500);
            (
                pick(
                    loc,
                    format!("sing-box log bloated — {subj}"),
                    format!("Лог sing-box разросся — {subj}"),
                ),
                pick(
                    loc,
                    format!(
                        "The sing-box log on {subj} crossed {} (≈{mib} MiB) — it will fill the disk soon.",
                        code(&format!("{mib} MiB"))
                    ),
                    format!(
                        "Лог sing-box на ноде {subj} превысил {} — скоро забьёт диск.",
                        code(&format!("{mib} МиБ"))
                    ),
                ),
                Some(pick(
                    loc,
                    "Redeploy the node (rotates the log).".into(),
                    "Передеплой ноду (ротация лога).".into(),
                )),
            )
        }
        "server.singbox.log.recovered" => {
            let mib = u(payload, "current_bytes")
                .map(|b| b / 1_048_576)
                .unwrap_or(0);
            let auto = payload
                .get("auto_remediated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            (
                if auto {
                    pick(
                        loc,
                        format!("Fixed automatically — {subj}"),
                        format!("Исправлено автоматически — {subj}"),
                    )
                } else {
                    pick(
                        loc,
                        format!("sing-box log recovered — {subj}"),
                        format!("Лог sing-box снова в норме — {subj}"),
                    )
                },
                if auto {
                    pick(
                        loc,
                        format!(
                            "vpnctl rotated the sing-box log on {subj} and verified it at ≈{mib} MiB."
                        ),
                        format!(
                            "vpnctl ротировал лог sing-box на {subj} и проверил его размер: ≈{mib} МиБ."
                        ),
                    )
                } else {
                    pick(
                        loc,
                        format!("The sing-box log on {subj} is back under 500 MiB (≈{mib} MiB)."),
                        format!("Лог sing-box на ноде {subj} снова меньше 500 МиБ (≈{mib} МиБ)."),
                    )
                },
                None,
            )
        }
        "server.singbox.restarted" => {
            let delta = u(payload, "delta").unwrap_or(1);
            let counter = u(payload, "current")
                .map(|c| code(&format!("NRestarts={c}")))
                .unwrap_or_default();
            let running = payload.get("active").and_then(|v| v.as_bool()) == Some(true);
            let (running_en, running_ru) = if running {
                (
                    " It is running again; clients on this node lost their connection for a few seconds.",
                    " Сервис снова работает; клиенты этой ноды на несколько секунд потеряли соединение.",
                )
            } else {
                ("", "")
            };
            (
                pick(
                    loc,
                    format!("sing-box restarted — {subj}"),
                    format!("sing-box перезапустился — {subj}"),
                ),
                pick(
                    loc,
                    format!(
                        "sing-box on {subj} crashed {delta} time(s) between health probes {counter} and systemd restarted it automatically.{running_en}"
                    ),
                    format!(
                        "sing-box на ноде {subj} аварийно завершился {delta} раз(а) между проверками {counter}, и systemd сам его перезапустил.{running_ru}"
                    ),
                ),
                Some(pick(
                    loc,
                    "Nothing to do for a single crash. If it repeats, open the server page: frequent restarts with high memory point to RAM; with normal memory they point to a sing-box bug.".into(),
                    "Разовый сбой — делать ничего не нужно. Если повторяется — открой страницу сервера: частые перезапуски при высокой памяти указывают на нехватку RAM, при нормальной — на баг sing-box.".into())),
            )
        }
        "server.fingerprint.drift" => {
            let ip = ps(payload, "ip").map(code).unwrap_or_default();
            (
                pick(loc, format!("SSH host-key changed — {subj}"), format!("Сменился SSH-отпечаток — {subj}")),
                pick(loc,
                    format!("The SSH host-key of {subj} {ip} no longer matches the pinned one. Either the node was reinstalled, or it's a MITM."),
                    format!("SSH host-key ноды {subj} {ip} не совпадает с закреплённым. Либо ноду переустановили, либо это MITM.")),
                Some(pick(loc,
                    "If you reinstalled the node, re-pin the fingerprint on the server page. If not — that's a red flag, investigate.".into(),
                    "Если переустанавливал ноду — обнови отпечаток на странице сервера. Если нет — тревожный знак, проверь.".into())),
            )
        }
        kind if kind.starts_with("protocol.assurance.failed.") && severity == "info" => {
            let protocol = ps(payload, "protocol").map(code).unwrap_or_default();
            let client = ps(payload, "client_kind").map(code).unwrap_or_default();
            let stage = ps(payload, "stage").map(code).unwrap_or_default();
            (
                pick(
                    loc,
                    format!("Protocol recovered — {subj}"),
                    format!("Протокол восстановлен — {subj}"),
                ),
                pick(
                    loc,
                    format!("{protocol} passed assurance at stage {stage} using {client}."),
                    format!("{protocol} снова прошёл проверку на этапе {stage}, клиент {client}."),
                ),
                None,
            )
        }
        kind if kind.starts_with("protocol.assurance.failed.") => {
            let protocol = ps(payload, "protocol").map(code).unwrap_or_default();
            let client = ps(payload, "client_kind").map(code).unwrap_or_default();
            let stage = ps(payload, "stage").map(code).unwrap_or_default();
            let failure = ps(payload, "failure_code").map(code).unwrap_or_default();
            (
                pick(loc, format!("Protocol assurance failed — {subj}"), format!("Проверка протокола не пройдена — {subj}")),
                pick(loc,
                    format!("{protocol} failed at stage {stage} using {client}. Failure: {failure}."),
                    format!("{protocol} не прошёл этап {stage}, клиент {client}. Причина: {failure}.")),
                Some(pick(loc,
                    "Open the server page and check the protocol assurance matrix; config generation alone does not prove external reachability.".into(),
                    "Открой страницу сервера и проверь матрицу протоколов: генерация конфига сама по себе не доказывает внешнюю доступность.".into())),
            )
        }
        "server.quality.degraded" if severity == "info" => {
            let score = u(payload, "score")
                .map(|s| code(&format!("{s}/100")))
                .unwrap_or_else(|| code("—"));
            let loss = pf(payload, "packet_loss_pct")
                .map(|l| code(&format!("{l:.1}%")))
                .unwrap_or_default();
            let p95 = u(payload, "p95_rtt_ms")
                .map(|ms| code(&pick(loc, format!("{ms} ms"), format!("{ms} мс"))))
                .unwrap_or_default();
            (
                pick(
                    loc,
                    format!("Service quality recovered — {subj}"),
                    format!("Качество связи восстановилось — {subj}"),
                ),
                pick(
                    loc,
                    format!(
                        "Service-path quality to {subj} is back to {score} (above recovery threshold). Loss {loss}, p95 latency {p95}."
                    ),
                    format!(
                        "Качество service-path до ноды {subj} восстановилось до {score} (выше порога восстановления). Потери {loss}, p95-задержка {p95}."
                    ),
                ),
                None,
            )
        }
        "server.quality.degraded" => {
            let score = u(payload, "score")
                .map(|s| code(&format!("{s}/100")))
                .unwrap_or_else(|| code("—"));
            let thresh = u(payload, "low_threshold").unwrap_or(60);
            let thresh_str = code(&format!("{thresh}/100"));
            let avail = pf(payload, "availability_pct")
                .map(|a| code(&format!("{a:.1}%")))
                .unwrap_or_else(|| code("—"));
            let loss = pf(payload, "packet_loss_pct")
                .map(|l| code(&format!("{l:.1}%")))
                .unwrap_or_else(|| code("—"));
            let p95 = u(payload, "p95_rtt_ms")
                .map(|ms| code(&pick(loc, format!("{ms} ms"), format!("{ms} мс"))))
                .unwrap_or_else(|| code("—"));
            let vantage = ps(payload, "vantage");
            let vantage_en = vantage
                .map(|v| format!(" from {}", code(v)))
                .unwrap_or_default();
            let vantage_ru = vantage
                .map(|v| format!(" (источник: {})", code(v)))
                .unwrap_or_default();
            (
                pick(
                    loc,
                    format!("Service quality degraded — {subj}"),
                    format!("Качество связи деградировало — {subj}"),
                ),
                pick(
                    loc,
                    format!(
                        "Service-path quality to {subj} dropped to {score}{vantage_en} (threshold {thresh_str}). Metrics: availability {avail}, loss {loss}, p95 latency {p95}."
                    ),
                    format!(
                        "Качество service-path до ноды {subj} упало до {score}{vantage_ru} (порог {thresh_str}). Метрики: доступность {avail}, потери {loss}, p95-задержка {p95}."
                    ),
                ),
                Some(pick(
                    loc,
                    "Check network connectivity or hoster route quality.".into(),
                    "Проверь сетевую связность ноды или маршруты хостера.".into(),
                )),
            )
        }
        "user.traffic_limit" => {
            let pct = u(payload, "used_pct").or_else(|| u(payload, "pct"));
            let pcts = pct
                .map(|p| code(&format!("{p}%")))
                .unwrap_or_else(|| pick(loc, "its".into(), "своего".into()));
            (
                pick(
                    loc,
                    format!("User near traffic limit — {subj}"),
                    format!("Юзер у лимита трафика — {subj}"),
                ),
                pick(
                    loc,
                    format!("User <b>{subj}</b> has used {pcts} of the monthly traffic limit."),
                    format!("Юзер <b>{subj}</b> использовал {pcts} месячного лимита трафика."),
                ),
                Some(pick(
                    loc,
                    "Check the user detail — could be a shared subscription URL or a heavy client."
                        .into(),
                    "Глянь деталь юзера — возможен шаринг подписки или тяжёлый клиент.".into(),
                )),
            )
        }

        "server.attribution.stalled" => (
            pick(
                loc,
                format!("Per-user attribution stalled — {subj}"),
                format!("Не считается per-user трафик — {subj}"),
            ),
            pick(
                loc,
                format!(
                    "{subj} has active connections but clash-api hasn't returned per-user attribution for a while — this node's per-user stats are temporarily blind."
                ),
                format!(
                    "На ноде {subj} есть активные соединения, но clash-api какое-то время не отдаёт привязку к юзерам — подушевая статистика по ноде временно слепа."
                ),
            ),
            Some(pick(
                loc,
                "Usually self-heals. If it persists, check clash-api / sing-box on the node."
                    .into(),
                "Обычно само чинится. Держится — проверь clash-api/sing-box на ноде.".into(),
            )),
        ),
        "user.sub_no_traffic" => {
            let mins = u(payload, "minutes_since_fetch").or_else(|| u(payload, "minutes"));
            let mw = mins
                .map(|m| pick(loc, format!("{m} min ago"), format!("{m} мин назад")))
                .unwrap_or_else(|| pick(loc, "recently".into(), "недавно".into()));
            (
                pick(
                    loc,
                    format!("Sub fetched, no traffic — {subj}"),
                    format!("Подписка обновлена, трафика нет — {subj}"),
                ),
                pick(
                    loc,
                    format!(
                        "User <b>{subj}</b> fetched the subscription {mw} but has had zero traffic since. They may be unable to connect (like the RU-block case)."
                    ),
                    format!(
                        "Юзер <b>{subj}</b> обновил подписку {mw}, но с тех пор ноль трафика. Возможно, не коннектится (как при РФ-блоке)."
                    ),
                ),
                Some(pick(
                    loc,
                    "Ask the user whether they connect — it can signal a node / protocol problem."
                        .into(),
                    "Спроси юзера — подключается ли. Может быть сигналом проблемы ноды/протокола."
                        .into(),
                )),
            )
        }
        "sub_access.suspicious_local_ip" => {
            let ip = ps(payload, "ip").map(code).unwrap_or_default();
            (
                pick(loc, format!("Suspicious sub-fetch IP — {subj}"), format!("Подозрительный IP фетча подписки — {subj}")),
                pick(loc,
                    format!("User <b>{subj}</b>'s subscription was fetched from local or loopback IP {ip}. This address is not configured as a trusted reverse proxy."),
                    format!("Подписка <b>{subj}</b> запрошена с локального или loopback-IP {ip}. Этот адрес не настроен как доверенный reverse proxy.")),
                Some(pick(loc, "Check whether this fetch was expected. Only if it should have passed through a reverse proxy, verify that proxy is in VPNCTLD_TRUSTED_PROXIES and forwards the client IP.".into(), "Проверь, ожидаем ли этот фетч. Только если он должен был идти через reverse proxy, проверь IP прокси в VPNCTLD_TRUSTED_PROXIES и передачу IP клиента.".into())),
            )
        }

        "boosty.sync.failed" => {
            let auth = payload
                .get("auth")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if auth {
                (
                    pick(
                        loc,
                        "Boosty bridge — credentials dead".into(),
                        "Boosty-мост — креды недействительны".into(),
                    ),
                    pick(
                        loc,
                        "Boosty auth failed and the bridge cannot self-heal: the stored refresh token was consumed or revoked. New subscribers are NOT being enabled.".into(),
                        "Авторизация Boosty упала, и мост не восстановится сам: сохранённый refresh-токен использован или отозван. Новые подписчики НЕ включаются.".into(),
                    ),
                    Some(pick(
                        loc,
                        "Paste a fresh refresh token + device id on /admin/boosty.".into(),
                        "Вставь свежий refresh token + device id на /admin/boosty.".into(),
                    )),
                )
            } else {
                (
                    pick(
                        loc,
                        "Boosty sync failed".into(),
                        "Boosty-синк упал".into(),
                    ),
                    pick(
                        loc,
                        "The subscriber-roster sync failed (network / Boosty API). Usually transient — the next tick retries automatically.".into(),
                        "Синхронизация ростера подписчиков упала (сеть / API Boosty). Обычно временно — следующий тик повторит сам.".into(),
                    ),
                    None,
                )
            }
        }

        other => {
            let okind = esc(other);
            (
                pick(loc, format!("Alert — {subj}"), format!("Событие — {subj}")),
                pick(
                    loc,
                    format!("{okind} ({subj})"),
                    format!("{okind} ({subj})"),
                ),
                None,
            )
        }
    };

    RenderedAlert {
        icon,
        title,
        body,
        action,
    }
}
