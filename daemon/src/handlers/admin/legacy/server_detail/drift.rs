use std::collections::{BTreeSet, HashMap};

use crate::handlers::admin::icons::{icon, status};
use maud::{Markup, html};

use crate::http_util::path_segment_encode;

pub(crate) fn expected_ports_for_protocol(
    registry: &vpnctl_core::Registry,
    pid: &vpnctl_core::ProtocolId,
    secrets: &HashMap<String, String>,
) -> Vec<(String, u16)> {
    match registry.protocol(pid) {
        Some(p) => p
            .effective_listen_ports(secrets)
            .into_iter()
            .map(|(s, n)| (s.to_string(), n))
            .collect(),
        None => Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrphanUuid {
    pub(crate) uuid: String,
    pub(crate) name: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) enum DriftLiveResult {
    Ok { orphans: Vec<OrphanUuid> },
    Unavailable,
}

pub(crate) fn compute_orphan_uuids(
    node_uuids: &BTreeSet<String>,
    granted_users: &[vpnctl_core::User],
    all_users: &[vpnctl_core::User],
) -> Vec<OrphanUuid> {
    let inventory_uuids: BTreeSet<&str> = granted_users.iter().map(|u| u.uuid.as_str()).collect();
    let uuid_to_user: HashMap<&str, &str> = all_users
        .iter()
        .map(|u| (u.uuid.as_str(), u.id.0.as_str()))
        .collect();

    node_uuids
        .iter()
        .filter(|u| !inventory_uuids.contains(u.as_str()))
        .map(|u| OrphanUuid {
            uuid: u.clone(),
            name: uuid_to_user.get(u.as_str()).map(|s| s.to_string()),
        })
        .collect()
}

pub(super) async fn load_drift_live(
    server: &vpnctl_core::Server,
    granted_users: &[vpnctl_core::User],
    all_users: &[vpnctl_core::User],
    jump: Option<vpnctl_core::PinnedJumpRoute>,
) -> DriftLiveResult {
    use crate::ssh_subprocess::SubprocessSshTransport;
    use vpnctl_core::SshTransport;

    let key_path = crate::app::deploy_key_path();
    let transport =
        SubprocessSshTransport::new(server.address.clone(), server.ssh_user.clone(), key_path)
            .port(server.ssh_port)
            .trusted_fingerprint(server.trusted_host_fingerprint.clone())
            .with_jump(jump)
            .timeout(std::time::Duration::from_secs(6));

    let read = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        transport.read_file("/etc/sing-box/config.json"),
    )
    .await;

    let bytes = match read {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            tracing::info!(
                target = "vpnctld::admin",
                server = %server.id,
                error = %e,
                "drift=live: live config read failed (best-effort)"
            );
            return DriftLiveResult::Unavailable;
        }
        Err(_elapsed) => {
            tracing::info!(
                target = "vpnctld::admin",
                server = %server.id,
                "drift=live: live config read timed out (best-effort)"
            );
            return DriftLiveResult::Unavailable;
        }
    };

    let node_uuids = vpnctl_kernels::live_config_user_uuids(&bytes);
    let orphans = compute_orphan_uuids(&node_uuids, granted_users, all_users);
    DriftLiveResult::Ok { orphans }
}

pub(super) fn server_detail_drift_detail_section(
    server: &vpnctl_core::Server,
    drift_live: Option<&DriftLiveResult>,
    armed: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        section id="drift-detail" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (t(lang, K::EyebrowDriftDetail)) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "The port-level drift above compares declared protocols to listening sockets. This card goes deeper — it reads the node's live sing-box config and lists UUIDs the node still serves that no granted user accounts for (a revoked user whose UUID lingers, or a service account). It's a live SSH read, so it runs only on demand.",
                    "Дрейф по портам выше сравнивает заявленные протоколы со слушающими сокетами. Эта карточка копает глубже — читает живой конфиг sing-box на ноде и показывает UUID, которые нода всё ещё обслуживает, но за которыми не стоит ни один выданный доступ (отозванный юзер, чей UUID завис, или сервисный аккаунт). Это живое SSH-чтение, поэтому запускается только по запросу.",
                ))
            }
            @if !armed {
                p style="font-family: var(--mono); font-size: 12px; margin: 8px 0;" {
                    a href=(format!("/admin/servers/{sid_enc}/protocols?drift=live#drift-detail"))
                      style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                        (icon("scan")) (tr(lang, "check live drift", "проверить живой дрейф"))
                    }
                }
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 4px 0 0;" {
                    (tr(
                        lang,
                        "Skipped by default so the page loads fast — no node is contacted until you click.",
                        "По умолчанию пропускается ради быстрой загрузки — пока не нажмёшь, нода не опрашивается.",
                    ))
                }
            } @else {
                @match drift_live {
                    Some(DriftLiveResult::Ok { orphans }) if !orphans.is_empty() => {
                        div style="margin-top: 6px; padding: 10px 12px; border: 1px solid var(--acc); background: var(--paper);" {
                            div style="font-family: var(--mono); font-size: 10px; color: var(--acc); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 6px;" {
                                (tr(lang, "orphan uuids on node", "осиротевшие uuid на ноде"))
                            }
                            ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                                @for o in orphans {
                                    li style="padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                                        span.ed-mono { (o.uuid) }
                                        " — "
                                        @match &o.name {
                                            Some(name) => {
                                                span style="color: var(--ink); font-style: italic; font-family: var(--serif);" {
                                                    (tr(lang, "maps to user ", "соответствует юзеру "))
                                                }
                                                a href=(format!("/admin/users/{}", path_segment_encode(name)))
                                                  style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                                                    (name)
                                                }
                                            }
                                            None => {
                                                span style="color: var(--mute); font-style: italic; font-family: var(--serif);" {
                                                    (tr(lang, "(unresolved — likely service account)", "(не определён — вероятно сервисный аккаунт)"))
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 8px 0 0;" {
                                (tr(
                                    lang,
                                    "A redeploy re-renders the config from inventory and removes any UUID inventory doesn't expect.",
                                    "Redeploy перерендерит конфиг из инвентаря и уберёт любой UUID, которого инвентарь не ждёт.",
                                ))
                            }
                        }
                    }
                    Some(DriftLiveResult::Ok { .. }) => {
                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--soft); margin-top: 6px;" {
                            (tr(
                                lang,
                                "Live config read OK — every UUID the node serves maps to a granted user. No orphans.",
                                "Живой конфиг прочитан — каждый UUID на ноде соответствует выданному доступу. Сирот нет.",
                            ))
                        }
                    }
                    _ => {
                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 6px;" {
                            (tr(
                                lang,
                                "Couldn't read the live config (node unreachable or deploy key not authorised on it). Nothing was changed; try again after the node is back, or run a deploy which re-pushes the config anyway.",
                                "Не удалось прочитать живой конфиг (нода недоступна или deploy-ключ на ней не авторизован). Ничего не менялось; попробуй снова когда нода вернётся, либо запусти deploy — он всё равно перезальёт конфиг.",
                            ))
                        }
                    }
                }
            }
        }
    }
}

pub(super) fn server_detail_drift_summary(
    missing: &[(String, u16)],
    extra: &[(String, u16)],
    have_probe: bool,
    base: &str,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    html! {
        div.ed-rule {}
        div id="drift-summary" style="margin: 14px 0; font-family: var(--serif); font-size: 13px;" {
            @if !have_probe {
                span style="color: var(--mute); font-style: italic;" {
                    (tr(
                        lang,
                        "Drift — no probe yet (poller runs every 10 min; sing-box nodes only).",
                        "Дрейф — probe ещё нет (поллер ходит раз в 10 минут; только sing-box ноды).",
                    ))
                }
            } @else if missing.is_empty() && extra.is_empty() {
                span style="color: var(--soft);" {
                    (icon("check"))
                    (tr(
                        lang,
                        "Declared and observed match. No drift.",
                        "Заявленное и наблюдаемое совпадают. Дрейфа нет.",
                    ))
                }
            } @else {
                span style="color: var(--acc);" {
                    (icon("triangle-alert")) (tr(lang, "drift — ", "дрейф — "))
                    (missing.len()) " " (tr(lang, "declared-but-silent", "заявлено-но-молчит"))
                    " · "
                    (extra.len()) " " (tr(lang, "listening-but-undeclared", "слушает-но-не-заявлено"))
                }
                " "
                a href=(format!("{base}/protocols#drift-detail"))
                  style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                    (icon("arrow-right")) (tr(lang, "full grid on protocols tab", "полная таблица на вкладке протоколы"))
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn server_detail_drift_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    secrets: &HashMap<String, String>,
    observed: &BTreeSet<(String, u16)>,
    missing: &[(String, u16)],
    extra: &[(String, u16)],
    have_probe: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let has_wg = server
        .enabled_protocols
        .iter()
        .any(|p| p.0.contains("wireguard") || p.0.contains("amnezia"));
    let mut wg_peers = 0usize;
    let mut caddy_internals: Vec<String> = Vec::new();
    let mut unclassified: Vec<String> = Vec::new();
    for (proto, port) in extra {
        if proto == "tcp" && (*port == 2019 || *port == 80) {
            caddy_internals.push(format!("{proto}/{port}"));
        } else if has_wg && proto == "udp" && *port >= 30000 {
            wg_peers += 1;
        } else {
            unclassified.push(format!("{proto}/{port}"));
        }
    }
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Declared vs observed", "Заявлено vs наблюдается")) " "
            span.ed-tip title=(tr(
                lang,
                "Declared = protocol in the inventory for this node. Listening = the latest probe found the port open (ss -tlnup). A declared-but-silent port is the dangerous drift; undeclared listeners are usually per-user wg peers.",
                "Заявлено = протокол в инвентаре этой ноды. Слушает = последняя проба нашла порт открытым (ss -tlnup). Заявлено-но-молчит — опасный дрейф; незаявленные слушатели обычно пер-пировые wg-порты.",
            )) { (status("info", lang, "Information", "Информация")) }
        }
        @if !have_probe {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin-top: 8px;" {
                (tr(lang, "(no probe yet — poller runs every 10 min; sing-box nodes only)", "(probe ещё нет — поллер ходит раз в 10 минут; только sing-box ноды)"))
            }
        } @else {
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th { (tr(lang, "protocol", "протокол")) }
                        th { (tr(lang, "port(s)", "порт(ы)")) }
                        th { (tr(lang, "declared", "заявлен")) }
                        th { (tr(lang, "listening", "слушает")) }
                    }
                }
                tbody {
                    @for pid in &server.enabled_protocols {
                        @let ports = expected_ports_for_protocol(registry, pid, secrets);
                        @let silent = ports.iter().any(|pp| !observed.contains(pp));
                        tr class=(if silent && !ports.is_empty() { "on-warn" } else { "" }) {
                            td { b { (pid.0) } }
                            td.num.ed-grid__sm {
                                @if ports.is_empty() {
                                    span.ed-grid__mut { "—" }
                                } @else {
                                    @for (i, (proto, port)) in ports.iter().enumerate() {
                                        @if i > 0 { " · " }
                                        (port) "/" (proto)
                                    }
                                }
                            }
                            td { span style="color: var(--green);" { (status("check", lang, "Declared", "Заявлен")) } }
                            td.ed-grid__sm {
                                @if ports.is_empty() {
                                    span.ed-grid__mut { (tr(lang, "n/a (no fixed port)", "н/д (нет фикс. порта)")) }
                                } @else {
                                    @for (i, pp) in ports.iter().enumerate() {
                                        @if i > 0 { " · " }
                                        @if observed.contains(pp) {
                                            span style="color: var(--green);" { (status("check", lang, "Listening", "Слушает")) }
                                        } @else {
                                            span.ed-grid__flag { (icon("x")) (tr(lang, "silent", "молчит")) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if !missing.is_empty() {
                p style="font-family: var(--mono); font-size: 11px; color: var(--warm); margin-top: 8px;" {
                    (icon("triangle-alert")) (tr(lang, "declared but NOT listening: ", "заявлено, но НЕ слушает: "))
                    @for (i, (proto, port)) in missing.iter().enumerate() {
                        @if i > 0 { ", " }
                        (proto) "/" (port)
                    }
                    " — " (tr(lang, "re-deploy or check the service on the node", "передеплой или проверь сервис на ноде"))
                }
            }
            @if !extra.is_empty() {
                div.ed-art-eyebrow style="margin-top: 14px;" {
                    (tr(lang, "Listening but undeclared", "Слушает, но не заявлено"))
                    " · " (extra.len()) " "
                    span.ed-tip title=(tr(
                        lang,
                        "Per-user AmneziaWG peers each bind their own UDP port — expected, but the inventory doesn't model them yet (NM-14). This grouping keeps the wall readable; there's nothing to click.",
                        "Каждый пер-пировый порт AmneziaWG — свой UDP-сокет: ожидаемо, но инвентарь их пока не моделирует (NM-14). Группировка держит стену читабельной; кликать тут нечего.",
                    )) { (status("info", lang, "Information", "Информация")) }
                }
                table.ed-grid style="margin-top: 8px;" {
                    thead {
                        tr {
                            th { (tr(lang, "group", "группа")) }
                            th.num { (tr(lang, "ports", "портов")) }
                            th { (tr(lang, "classification", "классификация")) }
                        }
                    }
                    tbody {
                        @if wg_peers > 0 {
                            tr {
                                td { b { (tr(lang, "wg per-user peers", "wg пер-пировые порты")) } }
                                td.num { (wg_peers) }
                                td.ed-grid__sm { span.ed-grid__flag { (icon("triangle-alert")) (tr(lang, "expected · unmodelled (NM-14)", "ожидаемо · не смоделировано (NM-14)")) } }
                            }
                        }
                        @if !caddy_internals.is_empty() {
                            tr {
                                td { b { "caddy internals" } }
                                td.num { (caddy_internals.len()) }
                                td.ed-grid__mut.ed-grid__sm { (caddy_internals.join(" · ")) " · " (tr(lang, "known-benign", "заведомо безобидно")) }
                            }
                        }
                        @if !unclassified.is_empty() {
                            tr {
                                td { b { (tr(lang, "unclassified", "не классифицировано")) } }
                                td.num { (unclassified.len()) }
                                td.ed-grid__sm { (unclassified.join(" · ")) }
                            }
                        }
                    }
                }
            } @else if missing.is_empty() {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--soft); margin-top: 10px;" {
                    (tr(lang, "Declared and observed match. No drift.", "Заявленное и наблюдаемое совпадают. Дрейфа нет."))
                }
            }
        }
    }
}
