//! Localized, pretty alert-message rendering (ru / en) for vpnctld.
//!
//! Replaces the bare English plain-text Telegram formatter. Each
//! alert `kind` is rendered from its structured `payload` (already
//! captured in `health_monitor::AlertEvent.payload` / the
//! node-probe-poller payloads) into a localized `{icon, title, body,
//! action}`, then laid out for Telegram (HTML) or the admin UI.
//!
//! ## Why structured-payload → render-at-display
//!
//! The alert-creation sites historically baked an English `summary`
//! string. That can't be re-localized. Instead the fields live in
//! `payload` (pct, prior/current, ip, …) and the human text is produced
//! HERE, in the viewer's locale — so the SAME event pushes Russian to
//! the operator's Telegram (locale from `notification_settings.language`)
//! while the admin UI shows the request-locale.
//!
//! ## Adding a kind
//!
//! Add a `match` arm in [`render_alert`]. A `:user`/`:server` suffix
//! (e.g. `user.traffic_limit:alice`) is stripped before matching. An
//! unknown kind falls through to a neutral render rather than panicking
//! — but every SHIPPED kind has an arm, pinned by the tests below.
//!
//! ## Operator-action policy
//!
//! The `action` («что делать») line must NEVER instruct the operator to
//! `ssh root@…` / `journalctl` / `systemctl` (CLAUDE.md operator-action
//! policy) — only "open the server page → Deploy" / "check the hoster
//! panel". `action_has_no_shell_instructions` pins this.

use crate::i18n::Locale;
use serde_json::Value;

/// A rendered alert split into its presentational parts. `title` already
/// includes the subject (e.g. "Нода недоступна — Нидерланды"); `body`
/// may contain `<code>…</code>` spans (HTML-escaped values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedAlert {
    pub icon: &'static str,
    pub title: String,
    pub body: String,
    pub action: Option<String>,
}

/// HTML-escape a value going into a `parse_mode=HTML` Telegram message.
/// Telegram HTML only treats `<`, `>`, `&` as special. Applied to EVERY
/// interpolated value (subject, ip, user name) so a `<` in data can't
/// break the markup or inject a tag.
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Whether the Telegram push for this severity should be SILENT
/// (`disable_notification=true`): info / recovery alerts don't buzz;
/// warning / critical do.
pub fn is_silent(severity: &str) -> bool {
    severity == "info"
}

/// Convert a rendered (Telegram-HTML) `title`/`body`/`action` string to
/// plain text for the admin UI — strips the fixed markup vocabulary
/// (`<b>`,`<code>`) then unescapes the 3 entities. Order matters: strip
/// real tags FIRST, then unescape, so a literal `<b>` in data (which the
/// render escaped to `&lt;b&gt;`) survives as text rather than being
/// stripped. maud re-escapes on render, so the result is injection-safe.
pub fn to_plain(s: &str) -> String {
    s.replace("<code>", "")
        .replace("</code>", "")
        .replace("<b>", "")
        .replace("</b>", "")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Severity / kind → leading icon. Recovery (`*.up` / `*.recovered`, or
/// severity `info`) is always 🟢; otherwise by severity.
fn icon_for(kind: &str, severity: &str) -> &'static str {
    if severity == "info" || kind.ends_with(".up") || kind.ends_with(".recovered") {
        return "🟢";
    }
    match severity {
        "critical" => "🔴",
        "warning" => "🟠",
        _ => "🟡",
    }
}

/// Pick the locale variant of a dynamic (interpolated) string. The
/// `i18n::tr` helper only takes `&'static str`; alert bodies interpolate
/// values, so they need this owned-String picker.
fn pick(loc: Locale, en: String, ru: String) -> String {
    match loc {
        Locale::En => en,
        Locale::Ru => ru,
    }
}

fn u(p: &Value, k: &str) -> Option<u64> {
    p.get(k).and_then(Value::as_u64)
}
fn ps<'a>(p: &'a Value, k: &str) -> Option<&'a str> {
    p.get(k).and_then(Value::as_str)
}

/// `<code>`-wrap an HTML-escaped value (for ips / ports / percentages).
fn code(s: &str) -> String {
    format!("<code>{}</code>", esc(s))
}

/// Render a localized alert. `subject` is the already-resolved
/// display-name — the country label for server alerts (`server_display_label`)
/// or the user id for user alerts. We HTML-escape it here, so callers pass
/// it RAW.
pub fn render_alert(
    kind: &str,
    severity: &str,
    subject: &str,
    payload: &Value,
    loc: Locale,
) -> RenderedAlert {
    let subj = esc(subject);
    let icon = icon_for(kind, severity);
    // Strip a `:identifier` suffix (e.g. user.traffic_limit:alice).
    let base = kind.split(':').next().unwrap_or(kind);

    let (title, body, action): (String, String, Option<String>) = match base {
        // ───────────────────────── critical ─────────────────────────
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
            (
                pick(
                    loc,
                    format!("sing-box recovered — {subj}"),
                    format!("sing-box поднялся — {subj}"),
                ),
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

        // ───────────────────────── warnings ─────────────────────────
        "server.unreachable" if severity == "info" => {
            // Recovery variant (edit-on-recover flips the original 🔴 to
            // this 🟢). Unreachable has no separate `.up` kind, so the
            // recovery is signalled by severity=info on the same kind.
            (
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
            )
        }
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
        "server.fail2ban.up" => (
            pick(
                loc,
                format!("fail2ban recovered — {subj}"),
                format!("fail2ban снова работает — {subj}"),
            ),
            pick(
                loc,
                format!("fail2ban is active again on {subj}."),
                format!("fail2ban снова активен на {subj}."),
            ),
            None,
        ),
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
            (
                pick(
                    loc,
                    format!("Disk recovered — {subj}"),
                    format!("Диск разгрузился — {subj}"),
                ),
                pick(
                    loc,
                    format!("Disk on {subj} is back down to {pct}."),
                    format!("Диск ноды {subj} разгрузился, сейчас {pct}."),
                ),
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
            (
                pick(
                    loc,
                    format!("sing-box log recovered — {subj}"),
                    format!("Лог sing-box снова в норме — {subj}"),
                ),
                pick(
                    loc,
                    format!("The sing-box log on {subj} is back under 500 MiB (≈{mib} MiB)."),
                    format!("Лог sing-box на ноде {subj} снова меньше 500 МиБ (≈{mib} МиБ)."),
                ),
                None,
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

        // ──────────────────────── soft-warnings ─────────────────────
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

        // ───────────────────── boosty.sync.failed ───────────────────
        "boosty.sync.failed" => {
            // payload.auth=true → dead credentials (cannot self-heal);
            // false → transient network/API failure, next tick retries.
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

        // ───────────────────────── fallback ─────────────────────────
        other => {
            // Unknown kind: neutral, still localized scaffolding so a new
            // kind shipped without an arm is at least readable (and the
            // test `every_known_kind_has_a_dedicated_arm` catches the gap).
            // Escape the raw kind too — keeps the module invariant that
            // EVERY interpolated value into parse_mode=HTML is esc()'d.
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

/// Lay a [`RenderedAlert`] out as a Telegram `parse_mode=HTML` message
/// body. `time_local` is the operator-TZ timestamp string; `repeat`
/// appends the «повтор» marker for a re-fired alert.
pub fn to_telegram_html(r: &RenderedAlert, loc: Locale, time_local: &str, repeat: bool) -> String {
    let mut m = String::with_capacity(256);
    m.push_str(r.icon);
    m.push_str(" <b>");
    m.push_str(&r.title);
    m.push_str("</b>\n\n");
    m.push_str(&r.body);
    m.push_str("\n\n🕐 ");
    m.push_str(&esc(time_local));
    if repeat {
        m.push_str(match loc {
            Locale::En => " · 🔁 repeat",
            Locale::Ru => " · 🔁 повтор",
        });
    }
    if let Some(a) = &r.action {
        m.push_str("\n⚙️ ");
        m.push_str(a);
    }
    m
}

/// Render a fleet digest as a Telegram HTML message. `open_titles` are
/// the already-rendered, HTML-safe `{icon} {title}` lines of every open
/// alert (caller produces them via `render_alert`). Empty → an «all
/// clear» 🟢 summary; non-empty → a 🔴 list. `servers` is the fleet size
/// for the headline context.
pub fn render_digest_html(
    loc: Locale,
    servers: usize,
    open_titles: &[String],
    time_local: &str,
) -> String {
    let mut m = String::with_capacity(256);
    let servers_noun = crate::i18n::noun_for(
        loc,
        servers as u64,
        "server",
        "servers",
        "сервер",
        "сервера",
        "серверов",
    );
    if open_titles.is_empty() {
        m.push_str(match loc {
            Locale::En => "🟢 <b>vpnctl digest — all clear</b>",
            Locale::Ru => "🟢 <b>Дайджест vpnctl — всё спокойно</b>",
        });
        m.push_str("\n\n");
        m.push_str(&pick(
            loc,
            format!("{servers} {servers_noun} monitored · no open alerts."),
            format!("{servers} {servers_noun} под наблюдением · открытых алертов нет."),
        ));
    } else {
        let n = open_titles.len();
        let problems = crate::i18n::noun_for(
            loc,
            n as u64,
            "open",
            "open",
            "открытая проблема",
            "открытые проблемы",
            "открытых проблем",
        );
        m.push_str(&pick(
            loc,
            format!("🔴 <b>vpnctl digest — {n} {problems}</b>"),
            format!("🔴 <b>Дайджест vpnctl — {n} {problems}</b>"),
        ));
        m.push_str("\n\n");
        for line in open_titles {
            m.push_str("• ");
            m.push_str(line); // already icon + HTML-escaped title
            m.push('\n');
        }
        m.push_str(&pick(
            loc,
            format!("\n{servers} {servers_noun} monitored."),
            format!("\n{servers} {servers_noun} под наблюдением."),
        ));
    }
    m.push_str("\n\n🕐 ");
    m.push_str(&esc(time_local));
    m
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Every kind the daemon actually fires. Keep in lockstep with the
    /// `kind=` literals in health_monitor.rs + node_probe_poller.rs.
    const SHIPPED_KINDS: &[(&str, &str)] = &[
        ("server.singbox.down", "critical"),
        ("server.singbox.up", "info"),
        ("server.fail2ban.banned_self", "critical"),
        ("server.unreachable", "warning"),
        ("server.fail2ban.down", "warning"),
        ("server.fail2ban.up", "info"),
        ("server.disk.pressure", "warning"),
        ("server.disk.recovered", "info"),
        ("server.mem.pressure", "warning"),
        ("server.mem.recovered", "info"),
        ("server.singbox.log.too_big", "warning"),
        ("server.singbox.log.recovered", "info"),
        ("server.fingerprint.drift", "warning"),
        ("user.traffic_limit", "warning"),
        ("server.attribution.stalled", "warning"),
        ("user.sub_no_traffic", "warning"),
        ("sub_access.suspicious_local_ip", "warning"),
        ("boosty.sync.failed", "warning"),
    ];

    #[test]
    fn every_known_kind_has_a_dedicated_arm() {
        // The fallback arm produces a title starting with "Событие"/"Alert".
        // A shipped kind must NOT hit it → its title differs.
        for (kind, sev) in SHIPPED_KINDS {
            for loc in [Locale::En, Locale::Ru] {
                let r = render_alert(kind, sev, "де", &json!({}), loc);
                assert!(
                    !r.title.starts_with("Alert ") && !r.title.starts_with("Событие "),
                    "kind {kind} fell through to the fallback arm ({loc:?})"
                );
                assert!(
                    !r.title.is_empty() && !r.body.is_empty(),
                    "empty render for {kind}"
                );
            }
        }
    }

    #[test]
    fn both_locales_differ_for_every_kind() {
        for (kind, sev) in SHIPPED_KINDS {
            let en = render_alert(
                kind,
                sev,
                "Germany",
                &json!({"current_pct":91,"consecutive_failures":3}),
                Locale::En,
            );
            let ru = render_alert(
                kind,
                sev,
                "Германия",
                &json!({"current_pct":91,"consecutive_failures":3}),
                Locale::Ru,
            );
            assert_ne!(en.title, ru.title, "title not localized for {kind}");
            assert_ne!(en.body, ru.body, "body not localized for {kind}");
        }
    }

    #[test]
    fn unreachable_ru_is_pretty_and_actionable() {
        let r = render_alert(
            "server.unreachable",
            "warning",
            "Нидерланды",
            &json!({"consecutive_failures": 3, "ip": "194.87.222.111"}),
            Locale::Ru,
        );
        assert_eq!(r.icon, "🟠");
        assert!(r.title.contains("Нода недоступна") && r.title.contains("Нидерланды"));
        assert!(r.body.contains("194.87.222.111") && r.body.contains("3 проверок"));
        assert!(r.action.as_ref().unwrap().contains("хостер"));
        // No shell instructions in the action (operator-action policy).
        assert!(!r.action.as_ref().unwrap().to_lowercase().contains("ssh "));
    }

    #[test]
    fn recovery_kinds_get_green_icon_and_no_action() {
        for kind in [
            "server.singbox.up",
            "server.fail2ban.up",
            "server.disk.recovered",
            "server.mem.recovered",
            "server.singbox.log.recovered",
        ] {
            let r = render_alert(kind, "info", "де", &json!({"current_pct": 40}), Locale::Ru);
            assert_eq!(r.icon, "🟢", "{kind} should be green");
            assert!(r.action.is_none(), "{kind} should have no action line");
            assert!(is_silent("info"), "recovery should be silent");
        }
    }

    #[test]
    fn severity_icons() {
        assert_eq!(
            render_alert(
                "server.singbox.down",
                "critical",
                "x",
                &json!({}),
                Locale::En
            )
            .icon,
            "🔴"
        );
        assert_eq!(
            render_alert(
                "server.disk.pressure",
                "warning",
                "x",
                &json!({}),
                Locale::En
            )
            .icon,
            "🟠"
        );
        assert_eq!(
            render_alert(
                "server.attribution.stalled",
                "warning",
                "x",
                &json!({}),
                Locale::En
            )
            .icon,
            "🟠"
        );
    }

    #[test]
    fn suspicious_local_ip_text_does_not_assume_proxy_misconfiguration() {
        let payload = json!({"ip": "192.168.1.23"});
        let en = render_alert(
            "sub_access.suspicious_local_ip:alice",
            "warning",
            "alice",
            &payload,
            Locale::En,
        );
        assert!(en.body.contains("local or loopback IP"), "got: {}", en.body);
        assert!(
            !en.body.contains("trusted-proxy list is empty")
                && !en.body.contains("logged client IP will be wrong"),
            "the detector does not establish either claim: {}",
            en.body
        );
        assert!(
            en.action
                .as_deref()
                .is_some_and(|action| action
                    .contains("Only if it should have passed through a reverse proxy")),
            "proxy remediation must remain conditional: {en:?}"
        );

        let ru = render_alert(
            "sub_access.suspicious_local_ip:alice",
            "warning",
            "alice",
            &payload,
            Locale::Ru,
        );
        assert!(
            !ru.body.contains("пустом списке доверенных прокси")
                && !ru.body.contains("IP в логах будет неверным"),
            "the detector does not establish either claim: {}",
            ru.body
        );
    }

    #[test]
    fn kind_with_user_suffix_is_stripped() {
        // `user.traffic_limit:alice` must match the base arm.
        let r = render_alert(
            "user.traffic_limit:alice",
            "warning",
            "alice",
            &json!({"used_pct": 82}),
            Locale::Ru,
        );
        assert!(
            r.title.contains("лимит"),
            "suffix kind didn't match base arm: {}",
            r.title
        );
        assert!(r.body.contains("82%"));
    }

    #[test]
    fn html_escape_prevents_injection_in_subject() {
        // A subject carrying `<b>` must be escaped, not rendered as markup.
        let r = render_alert(
            "server.unreachable",
            "warning",
            "<b>evil</b>",
            &json!({}),
            Locale::Ru,
        );
        assert!(
            r.title.contains("&lt;b&gt;evil&lt;/b&gt;"),
            "subject not escaped: {}",
            r.title
        );
        assert!(!r.title.contains("<b>evil"));
    }

    #[test]
    fn action_has_no_shell_instructions() {
        // operator-action policy: no `ssh root@`, `journalctl`, `systemctl`
        // in any localized action line.
        for (kind, sev) in SHIPPED_KINDS {
            for loc in [Locale::En, Locale::Ru] {
                let r = render_alert(kind, sev, "x", &json!({}), loc);
                if let Some(a) = &r.action {
                    let low = a.to_lowercase();
                    for bad in ["ssh root@", "journalctl", "systemctl", "ssh -i"] {
                        assert!(
                            !low.contains(bad),
                            "{kind} action leaks shell instruction {bad:?}: {a}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn telegram_html_layout() {
        let r = render_alert(
            "server.disk.pressure",
            "warning",
            "Германия",
            &json!({"current_pct": 91}),
            Locale::Ru,
        );
        let html = to_telegram_html(&r, Locale::Ru, "26 июня, 17:40 MSK", true);
        assert!(html.starts_with("🟠 <b>Мало места на диске — Германия</b>"));
        assert!(html.contains("<code>91%</code>"));
        assert!(html.contains("🕐 26 июня, 17:40 MSK · 🔁 повтор"));
        assert!(html.contains("⚙️ "));
        // No raw `<` outside the tags we emit (sanity: balanced <b>/<code>).
        assert_eq!(html.matches("<b>").count(), 1);
        assert_eq!(html.matches("</b>").count(), 1);
    }

    #[test]
    fn unreachable_info_severity_renders_recovery_not_down() {
        // Edit-on-recover uses severity=info on the same kind to signal
        // the 🟢 recovery variant (unreachable has no `.up` kind).
        let up = render_alert(
            "server.unreachable",
            "info",
            "Нидерланды",
            &json!({}),
            Locale::Ru,
        );
        assert_eq!(up.icon, "🟢");
        assert!(up.title.contains("снова доступна"), "got: {}", up.title);
        assert!(up.action.is_none(), "recovery has no what-to-do line");
        assert!(is_silent("info"), "recovery push is silent");
        // The warning variant is still the 🟠 down message — same kind.
        let down = render_alert(
            "server.unreachable",
            "warning",
            "Нидерланды",
            &json!({"consecutive_failures": 3}),
            Locale::Ru,
        );
        assert_eq!(down.icon, "🟠");
        assert!(down.title.contains("недоступна"), "got: {}", down.title);
        // EN side too.
        let up_en = render_alert("server.unreachable", "info", "NL", &json!({}), Locale::En);
        assert!(
            up_en.title.contains("reachable again"),
            "got: {}",
            up_en.title
        );
    }

    #[test]
    fn user_body_keeps_inline_bold_and_escapes_subject() {
        // user.* bodies wrap the (escaped) subject in literal <b>…</b>.
        // A `<` in the user id must be escaped INSIDE the bold, and the
        // title's own <b> must stay balanced — guards against a
        // double-escape or a stray-tag regression in the user arms.
        let r = render_alert(
            "user.traffic_limit:weird",
            "warning",
            "a<b>c",
            &json!({"used_pct": 82}),
            Locale::Ru,
        );
        let html = to_telegram_html(&r, Locale::Ru, "26.06 17:40 MSK", false);
        // The dangerous `<b>` from the subject is escaped everywhere.
        assert!(html.contains("a&lt;b&gt;c"));
        assert!(!html.contains("a<b>c"));
        // Title bold + the body's inline bold around the subject → two pairs.
        assert_eq!(html.matches("<b>").count(), 2);
        assert_eq!(html.matches("</b>").count(), 2);
        assert!(html.contains("82%"));
    }

    #[test]
    fn unknown_kind_escapes_the_raw_kind() {
        // Fallback arm must escape the kind too (parse_mode=HTML safety).
        let r = render_alert("weird.<kind>", "warning", "x", &json!({}), Locale::En);
        assert!(r.body.contains("weird.&lt;kind&gt;"));
        assert!(!r.body.contains("weird.<kind>"));
    }

    #[test]
    fn digest_all_clear_vs_problems() {
        // All-clear: 🟢 + the fleet size, no bullet list.
        let clear = render_digest_html(Locale::Ru, 4, &[], "27.06 10:00 MSK");
        assert!(clear.starts_with("🟢 <b>Дайджест vpnctl — всё спокойно</b>"));
        assert!(clear.contains("4 сервера под наблюдением"));
        assert!(!clear.contains("• "));
        assert!(clear.contains("🕐 27.06 10:00 MSK"));
        // Problems: 🔴 + count + one bullet per title.
        let probs = render_digest_html(
            Locale::Ru,
            4,
            &[
                "🔴 <b>sing-box упал — de</b>".into(),
                "🟠 <b>Мало места на диске — fi</b>".into(),
            ],
            "27.06 10:00 MSK",
        );
        assert!(probs.contains("2 открытые проблемы"));
        assert!(probs.contains("• 🔴 <b>sing-box упал — de</b>"));
        assert_eq!(probs.matches("• ").count(), 2);
        // EN side.
        let en = render_digest_html(Locale::En, 3, &[], "27.06 10:00 MSK");
        assert!(en.contains("all clear") && en.contains("3 servers"));
    }

    #[test]
    fn digest_ru_declines_problem_and_server_counts() {
        let title = "🟠 <b>test</b>".to_string();
        for (n, expected) in [
            (1, "1 открытая проблема"),
            (2, "2 открытые проблемы"),
            (5, "5 открытых проблем"),
            (11, "11 открытых проблем"),
            (14, "14 открытых проблем"),
            (21, "21 открытая проблема"),
        ] {
            let html = render_digest_html(Locale::Ru, 4, &vec![title.clone(); n], "now");
            assert!(html.contains(expected), "n={n}: {html}");
        }

        for (servers, expected) in [
            (1, "1 сервер под наблюдением"),
            (2, "2 сервера под наблюдением"),
            (4, "4 сервера под наблюдением"),
            (5, "5 серверов под наблюдением"),
            (11, "11 серверов под наблюдением"),
            (21, "21 сервер под наблюдением"),
        ] {
            let html = render_digest_html(Locale::Ru, servers, &[], "now");
            assert!(html.contains(expected), "servers={servers}: {html}");
        }
    }
}
